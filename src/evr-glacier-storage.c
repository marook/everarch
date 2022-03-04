/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2022  Markus Peröbner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <threads.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>
#include <poll.h>

#include "basics.h"
#include "configuration.h"
#include "errors.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "glacier.h"
#include "files.h"
#include "concurrent-glacier.h"
#include "server.h"

sig_atomic_t running = 1;

struct evr_connection{
    int socket;
};

struct evr_modified_blob {
    evr_blob_key_t key;
    unsigned long long last_modified;
    int flags;
};

/**
 * evr_list_blobs_blobs_len's value tries to fill one IP packet well.
 */
#define evr_list_blobs_blobs_len (1000 / (evr_blob_key_size + sizeof(uint64_t)))

struct evr_list_blobs_ctx {
    struct evr_connection *connection;
    size_t blobs_used;
    struct evr_modified_blob blobs[evr_list_blobs_blobs_len];
};

void handle_sigterm(int signum);
int evr_glacier_tcp_server(const struct evr_glacier_storage_configuration *config);
int evr_connection_worker(void *context);
int evr_work_put_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd);
int evr_work_stat_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx);
int evr_work_watch_blobs(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx);
int evr_handle_blob_list(void *ctx, const evr_blob_key_t key, int flags, unsigned long long last_modified, int last_blob);
int evr_flush_list_blobs_ctx(struct evr_list_blobs_ctx *ctx);
void evr_handle_blob_modified(void *ctx, int wd, evr_blob_key_t key, int flags, unsigned long long last_modified);
int evr_ensure_worker_rctx_exists(struct evr_glacier_read_ctx **rctx, const struct evr_connection *ctx);
int send_get_response(void *arg, int exists, int flags, size_t blob_size);
int pipe_data(void *arg, const char *data, size_t data_size);

/**
 * config exists until the program is terminated.
 */
struct evr_glacier_storage_configuration *config;

int main(){
    int ret = evr_error;
    config = create_evr_glacier_storage_configuration();
    if(!config){
        goto out;
    }
    {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_sigterm;
        sigaction(SIGINT, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    const char *config_paths[] = {
        "~/.config/everarch/glacier-storage.json",
        "glacier-storage.json",
    };
    if(load_evr_glacier_storage_configurations(config, config_paths, sizeof(config_paths) / sizeof(char*)) != evr_ok){
        log_error("Failed to load configuration");
        goto out;
    }
    if(evr_quick_check_glacier(config) != evr_ok){
        log_error("Glacier quick check failed");
        goto out_with_free_configuration;
    }
    if(evr_persister_start(config) != evr_ok){
        log_error("Failed to start glacier persister thread");
        goto out_with_free_configuration;
    }
    int tcpret = evr_glacier_tcp_server(config);
    if(tcpret != evr_ok && tcpret != evr_end){
        log_error("TCP server failed");
        goto out_with_stop_persister;
    }
    ret = evr_ok;
 out_with_stop_persister:
    if(evr_persister_stop() != evr_ok){
        log_error("Failed to stop glacier persister thread");
        ret = evr_error;
    }
 out_with_free_configuration:
    // TODO we should wait for the worker threads to be finished before freeing config or maybe free config by OS when program ends?
    free_evr_glacier_storage_configuration(config);
 out:
    return ret;
}

void handle_sigterm(int signum){
    if(running){
        log_info("Shutting down");
        running = 0;
    }
}

int evr_glacier_tcp_server(const struct evr_glacier_storage_configuration *config){
    int s = evr_make_tcp_socket(evr_glacier_storage_port);
    if(s < 0){
        log_error("Failed to create socket");
        return evr_error;
    }
    if(listen(s, 7) < 0){
        log_error("Failed to listen on localhost:%d", evr_glacier_storage_port);
        // TODO don't we have to close s here?
        return evr_error;
    }
    log_info("Listening on localhost:%d", evr_glacier_storage_port);
    fd_set active_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(s, &active_fd_set);
    struct sockaddr_in client_addr;
    while(running){
        int sret = select(FD_SETSIZE, &active_fd_set, NULL, NULL, NULL);
        if(sret == -1){
            // select returns -1 on sigint.
            // TODO don't we have to close s here?
            return evr_end;
        } else if(sret < 0){
            // TODO don't we have to close s here?
            return evr_error;
        }
        for(int i = 0; i < FD_SETSIZE; ++i){
            if(FD_ISSET(i, &active_fd_set)){
                if(i == s){
                    // incomming connection request
                    socklen_t size = sizeof(client_addr);
                    int c = accept(s, (struct sockaddr*)&client_addr, &size);
                    if(c < 0){
                        // TODO don't we have to close s here?
                        return evr_error;
                    }
                    log_debug("Connection from %s:%d accepted (will be worker %d)", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), c);
                    struct evr_connection *context = malloc(sizeof(struct evr_connection));
                    if(!context){
                        goto context_alloc_fail;
                    }
                    context->socket = c;
                    thrd_t t;
                    if(thrd_create(&t, evr_connection_worker, context) != thrd_success){
                        goto thread_create_fail;
                    }
                    if(thrd_detach(t) != thrd_success){
                        goto thread_create_fail;
                    }
                    goto end;
                thread_create_fail:
                    free(context);
                context_alloc_fail:
                    close(c);
                    log_error("Failed to startup connection from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                end:
                    continue;
                }
            }
        }
    }
    // TODO don't we have to close s here?
    return evr_ok;
}

int evr_connection_worker(void *context){
    int result = evr_error;
    struct evr_connection ctx = *(struct evr_connection*)context;
    free(context);
    log_debug("Started worker %d", ctx.socket);
    struct evr_glacier_read_ctx *rctx = NULL;
    // TODO i guess buffer is never used for storing responses. why do
    // we make sure it fits evr_resp_header_n_size
    const size_t buffer_size = max(evr_cmd_header_n_size, evr_resp_header_n_size);
    char buffer[buffer_size];
    struct evr_cmd_header cmd;
    while(running){
        const int header_result = read_n(ctx.socket, buffer, evr_cmd_header_n_size);
        if(header_result == evr_end){
            log_debug("Worker %d ends because of remote termination", ctx.socket);
            result = evr_ok;
            goto end;
        } else if (header_result != evr_ok){
            goto end;
        }
        if(evr_parse_cmd_header(&cmd, buffer) != evr_ok){
            goto end;
        }
        log_debug("Worker %d retrieved cmd 0x%02x with body size %d", ctx.socket, cmd.type, cmd.body_size);
        switch(cmd.type){
        default:
            // unknown command
            log_error("Worker %d retieved unknown cmd 0x%02x", ctx.socket, cmd.type);
            // TODO respond evr_status_code_unknown_cmd
            result = evr_ok;
            goto end;
        case evr_cmd_type_get_blob: {
            size_t body_size = evr_blob_key_size;
            if(cmd.body_size != body_size){
                goto end;
            }
            evr_blob_key_t key;
            const int body_result = read_n(ctx.socket, (char*)&key, body_size);
            if(body_result != evr_ok){
                goto end;
            }
#ifdef EVR_LOG_DEBUG
            {
                evr_fmt_blob_key_t fmt_key;
                evr_fmt_blob_key(fmt_key, key);
                log_debug("Worker %d retrieved cmd get %s", ctx.socket, fmt_key);
            }
#endif
            if(evr_ensure_worker_rctx_exists(&rctx, &ctx) != evr_ok){
                goto end;
            }
            int read_res = evr_glacier_read_blob(rctx, key, send_get_response, pipe_data, &ctx.socket);
#ifdef EVR_LOG_DEBUG
            if(read_res == evr_not_found) {
                evr_fmt_blob_key_t fmt_key;
                evr_fmt_blob_key(fmt_key, key);
                log_debug("Worker %d did not find key %s", ctx.socket, fmt_key);
            }
#endif
            if(read_res != evr_ok && read_res != evr_not_found){
                // TODO should we send a server error here?
                goto end;
            }
            break;
        }
        case evr_cmd_type_put_blob:
            if(evr_work_put_blob(&ctx, &cmd) != evr_ok){
                goto end;
            }
            break;
        case evr_cmd_type_stat_blob:
            if(evr_work_stat_blob(&ctx, &cmd, &rctx) != evr_ok){
                goto end;
            }
            break;
        case evr_cmd_type_watch_blobs:
            if(evr_work_watch_blobs(&ctx, &cmd, &rctx) != evr_ok){
                goto end;
            }
            break;
        }
    }
    result = evr_ok;
 end:
    close(ctx.socket);
    if(rctx){
        if(evr_free_glacier_read_ctx(rctx) != evr_ok){
            result = evr_error;
        }
    }
    log_debug("Ended worker %d with result %d", ctx.socket, result);
    return result;
}

int evr_work_put_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd){
    int ret = evr_error;
    if(cmd->body_size < evr_blob_key_size){
        goto out;
    }
    size_t blob_size = cmd->body_size - evr_blob_key_size - sizeof(uint8_t);
    if(blob_size > evr_max_blob_data_size){
        // TODO should we send a client error here?
        goto out;
    }
    struct evr_writing_blob wblob;
    if(read_n(ctx->socket, (char*)&wblob.key, evr_blob_key_size) != evr_ok){
        goto out;
    }
    uint8_t flags;
    if(read_n(ctx->socket, (char*)&flags, sizeof(flags)) != evr_ok){
        goto out;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_fmt_blob_key_t fmt_key;
        evr_fmt_blob_key(fmt_key, wblob.key);
        log_debug("Worker %d retrieved cmd put %s with flags 0x%02x and %d bytes blob", ctx->socket, fmt_key, flags, blob_size);
    }
#endif
    struct chunk_set *blob = read_into_chunks(ctx->socket, blob_size);
    if(!blob){
        goto out;
    }
    evr_blob_key_t calced_key;
    if(evr_calc_blob_key(calced_key, blob_size, blob->chunks) != evr_ok){
        goto out_free_blob;
    }
    if(memcmp(wblob.key, calced_key, 0)){
        // TODO indicate to the client that the key does not
        // match the blob's hash
        log_debug("Client and server blob keys did not match");
        goto out_free_blob;
    }
    struct evr_persister_task task;
    wblob.flags = flags;
    wblob.size = blob_size;
    wblob.chunks = blob->chunks;
    if(evr_persister_init_task(&task, &wblob) != evr_ok){
        goto out_free_blob;
    }
    if(evr_persister_queue_task(&task) != evr_ok){
        goto out_destroy_task;
    }
    if(evr_persister_wait_for_task(&task) != evr_ok){
        goto out_destroy_task;
    }
    if(task.result != evr_ok){
        goto out_destroy_task;
    }
    struct evr_resp_header resp;
    resp.status_code = evr_status_code_ok;
    resp.body_size = 0;
    char buffer[evr_resp_header_n_size];
    if(evr_format_resp_header(buffer, &resp) != evr_ok){
        goto out_destroy_task;
    }
    if(write_n(ctx->socket, buffer, evr_resp_header_n_size) != evr_ok){
        goto out_destroy_task;
    }
    ret = evr_ok;
 out_destroy_task:
    if(evr_persister_destroy_task(&task) != evr_ok){
        ret = evr_error;
    }
 out_free_blob:
    evr_free_chunk_set(blob);
 out:
    return ret;
}

int evr_work_stat_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx){
    int ret = evr_error;
    if(cmd->body_size != evr_blob_key_size){
        goto out;
    }
    evr_blob_key_t key;
    if(read_n(ctx->socket, (char*)&key, evr_blob_key_size) != evr_ok){
        goto out;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_fmt_blob_key_t fmt_key;
        evr_fmt_blob_key(fmt_key, key);
        log_debug("Worker %d retrieved cmd stat %s", ctx->socket, fmt_key);
    }
#endif
    if(evr_ensure_worker_rctx_exists(rctx, ctx) != evr_ok){
        goto out;
    }
    struct evr_glacier_blob_stat stat;
    int stat_ret = evr_glacier_stat_blob(*rctx, key, &stat);
    struct evr_resp_header resp;
    if(stat_ret == evr_not_found){
        resp.status_code = evr_status_code_blob_not_found;
        resp.body_size = 0;
        char buf[evr_resp_header_n_size];
        if(evr_format_resp_header(buf, &resp) != evr_ok){
            goto out;
        }
        if(write_n(ctx->socket, buf, evr_resp_header_n_size) != evr_ok){
            goto out;
        }
    } else if(stat_ret == evr_ok){
        const size_t buf_size = evr_resp_header_n_size + evr_stat_blob_resp_n_size;
        char buf[buf_size];
        char *p = buf;
        resp.status_code = evr_status_code_ok;
        resp.body_size = evr_stat_blob_resp_n_size;
        if(evr_format_resp_header(p, &resp) != evr_ok){
            goto out;
        }
        p += evr_resp_header_n_size;
        struct evr_stat_blob_resp stat_resp;
        stat_resp.flags = stat.flags;
        stat_resp.blob_size = stat.blob_size;
        if(evr_format_stat_blob_resp(p, &stat_resp) != evr_ok){
            goto out;
        }
        if(write_n(ctx->socket, buf, buf_size) != evr_ok){
            goto out;
        }
    } else {
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

#define evr_modified_blobs_len (2 << 8)

struct evr_work_watch_ctx {
    struct evr_blob_filter *filter;

    mtx_t queue_lock;
    cnd_t queue_cnd;
    /**
     * status indicates if the watch callbacks produced an error.
     */
    int status;
    size_t writing_blobs_i;
    size_t reading_blobs_i;
    struct evr_modified_blob blobs[evr_modified_blobs_len];
};

int evr_work_watch_blobs(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx){
    int ret = evr_error;
    if(cmd->body_size != evr_blob_filter_n_size){
        goto out;
    }
    char buf[max(max(evr_blob_filter_n_size, evr_resp_header_n_size), evr_blob_key_size + sizeof(uint64_t) + sizeof(uint8_t))];
    if(read_n(ctx->socket, buf, evr_blob_filter_n_size) != evr_ok){
        goto out;
    }
    struct evr_blob_filter f;
    if(evr_parse_blob_filter(&f, buf) != evr_ok){
        goto out;
    }
    log_debug("Worker %d retrieved cmd watch with flags_filter 0x%02x and last_modified_after %llu", ctx->socket, f.flags_filter, f.last_modified_after);
    struct evr_resp_header resp;
    resp.status_code = evr_status_code_ok;
    resp.body_size = 0;
    if(evr_format_resp_header(buf, &resp) != evr_ok){
        goto out;
    }
    if(write_n(ctx->socket, buf, evr_resp_header_n_size) != evr_ok){
        goto out;
    }
    struct evr_work_watch_ctx wctx;
    wctx.filter = &f;
    if(mtx_init(&wctx.queue_lock, mtx_timed) != thrd_success){
        goto out;
    }
    if(cnd_init(&wctx.queue_cnd) != thrd_success){
        goto out_with_free_queue_lock;
    }
    wctx.status = evr_ok;
    wctx.writing_blobs_i = 0;
    wctx.reading_blobs_i = 0;
    atomic_thread_fence(memory_order_seq_cst);
    int wd = evr_persister_add_watcher(evr_handle_blob_modified, &wctx);
    if(wd < 0){
        log_error("Worker %d can't add watcher because list full", ctx->socket);
        goto out_with_free_queue_cnd;
    }
    if(evr_ensure_worker_rctx_exists(rctx, ctx) != evr_ok){
        goto out_with_rm_watcher;
    }
    struct evr_list_blobs_ctx lctx;
    lctx.connection = ctx;
    lctx.blobs_used = 0;
    if(evr_glacier_list_blobs(*rctx, evr_handle_blob_list, f.flags_filter, f.last_modified_after, &lctx) != evr_ok){
        goto out_with_rm_watcher;
    }
    if(evr_flush_list_blobs_ctx(&lctx) != evr_ok){
        goto out_with_rm_watcher;
    }
    if(mtx_lock(&wctx.queue_lock) != thrd_success){
        goto out_with_rm_watcher;
    }
    struct evr_modified_blob blob;
    while(running){
        while(running){
            if(wctx.status != evr_ok){
                goto out_with_unlock_queue;
            }
            if(wctx.writing_blobs_i == wctx.reading_blobs_i){
                break;
            }
            blob = wctx.blobs[wctx.reading_blobs_i];
            wctx.reading_blobs_i = (wctx.reading_blobs_i + 1) & (evr_modified_blobs_len - 1);
            if(mtx_unlock(&wctx.queue_lock) != thrd_success){
                evr_panic("Failed to unlock wctx.queue_lock");
                return evr_error;
            }
#ifdef EVR_LOG_DEBUG
            {
                evr_fmt_blob_key_t fmt_key;
                evr_fmt_blob_key(fmt_key, blob.key);
                log_debug("Worker %d watch indicates blob with key %s modified", ctx->socket, fmt_key);
            }
#endif
            struct evr_buf_pos bp;
            evr_init_buf_pos(&bp, buf);
            memcpy(bp.pos, blob.key, evr_blob_key_size);
            bp.pos += evr_blob_key_size;
            evr_push_map(&bp, &blob.last_modified, uint64_t, htobe64);
            int flags = evr_watch_flag_eob;
            evr_push_as(&bp, &flags, uint8_t);
            if(write_n(ctx->socket, buf, evr_blob_key_size + sizeof(uint64_t) + sizeof(uint8_t)) != evr_ok){
                goto out_with_rm_watcher;
            }
            if(mtx_lock(&wctx.queue_lock) != thrd_success){
                goto out_with_rm_watcher;
            }
        }
        if(!running){
            break;
        }
        struct pollfd fds;
        fds.fd = ctx->socket;
        fds.events = POLLRDHUP | POLLHUP;
        if(poll(&fds, 1, 0) < 0){
            goto out_with_unlock_queue;
        }
        if(fds.revents & (POLLRDHUP | POLLHUP)){
            // peer closed connection
            ret = evr_end;
            goto out_with_unlock_queue;
        }
        time_t t;
        time(&t);
        struct timespec timeout;
        timeout.tv_sec = t + 10;
        timeout.tv_nsec = 0;
        // cnd_timedwait returns an error either if a timeout is met
        // or another error occured. so we don't check the error
        // response.
        cnd_timedwait(&wctx.queue_cnd, &wctx.queue_lock, &timeout);
    }
    ret = evr_ok;
 out_with_unlock_queue:
    // before unlocking queue_lock we might have a locked OR unlocked
    // queue_lock
    if(mtx_unlock(&wctx.queue_lock) != thrd_success){
        ret = evr_error;
    }
 out_with_rm_watcher:
    if(evr_persister_rm_watcher(wd) == evr_ok){
        // wait until watcher ends
        if(mtx_lock(&wctx.queue_lock) != thrd_success){
            ret = evr_error;
        }
        if(mtx_unlock(&wctx.queue_lock) != thrd_success){
            ret = evr_error;
        }
        log_debug("Worker %d watch context reported status %d", ctx->socket, wctx.status);
        if(wctx.status != evr_ok){
            ret = evr_error;
        }
    } else {
        ret = evr_error;
    }
 out_with_free_queue_cnd:
    cnd_destroy(&wctx.queue_cnd);
 out_with_free_queue_lock:
    mtx_destroy(&wctx.queue_lock);
 out:
    log_debug("Worker %d watch ends with status %d", ctx->socket, ret);
    return ret;
}

int evr_handle_blob_list(void *ctx0, const evr_blob_key_t key, int flags, unsigned long long last_modified, int last_blob){
    int ret = evr_error;
    struct evr_list_blobs_ctx *ctx = ctx0;
    if(ctx->blobs_used == evr_list_blobs_blobs_len){
        if(evr_flush_list_blobs_ctx(ctx) != evr_ok){
            goto out;
        }
    }
    struct evr_modified_blob *b = &ctx->blobs[ctx->blobs_used];
    memcpy(b->key, key, evr_blob_key_size);
    b->last_modified = last_modified;
    b->flags = last_blob && evr_watch_flag_eob;
    ctx->blobs_used += 1;
    ret = evr_ok;
 out:
    return ret;
}

int evr_flush_list_blobs_ctx(struct evr_list_blobs_ctx *ctx){
    int ret = evr_error;
    if(ctx->blobs_used > 0){
        char buf[ctx->blobs_used * (evr_blob_key_size + sizeof(uint64_t) + sizeof(uint8_t))];
        struct evr_buf_pos bp;
        evr_init_buf_pos(&bp, buf);
        for(size_t i = 0; i < ctx->blobs_used; ++i){
            struct evr_modified_blob *b = &ctx->blobs[i];
            memcpy(bp.pos, b->key, evr_blob_key_size);
            bp.pos += evr_blob_key_size;
            evr_push_map(&bp, &b->last_modified, uint64_t, htobe64);
            evr_push_as(&bp, &b->flags, uint8_t);
        }
        if(write_n(ctx->connection->socket, buf, sizeof(buf)) != evr_ok){
            goto out;
        }
        ctx->blobs_used = 0;
    }
    ret = evr_ok;
 out:
    return ret;
}

void evr_handle_blob_modified(void *ctx, int wd, evr_blob_key_t key, int flags, unsigned long long last_modified){
    struct evr_work_watch_ctx *wctx = ctx;
    if((wctx->filter->flags_filter & flags) != wctx->filter->flags_filter){
        return;
    }
    if(mtx_lock(&wctx->queue_lock) != thrd_success){
        evr_panic("Failed to lock evr_work_watch_ctx.queue_lock");
        return;
    }
    size_t next_writing_blobs_i = (wctx->writing_blobs_i + 1) & (evr_modified_blobs_len - 1);
    if(next_writing_blobs_i == wctx->reading_blobs_i){
        // queue full
        wctx->status = evr_temporary_occupied;
    } else {
        struct evr_modified_blob *b = &wctx->blobs[wctx->writing_blobs_i];
        memcpy(b->key, key, evr_blob_key_size);
        b->last_modified = last_modified;
        wctx->writing_blobs_i = next_writing_blobs_i;
    }
    if(cnd_signal(&wctx->queue_cnd) != thrd_success){
        evr_panic("Failed to signal evr_work_watch_ctx.queue_cnd");
        return;
    }
    if(mtx_unlock(&wctx->queue_lock) != thrd_success){
        evr_panic("Failed to unlock evr_work_watch_ctx.queue_lock");
        return;
    }
}

int evr_ensure_worker_rctx_exists(struct evr_glacier_read_ctx **rctx, const struct evr_connection *ctx){
    if(*rctx){
        return evr_ok;
    }
    log_debug("Worker %d creates a glacier read ctx", ctx->socket);
    *rctx = evr_create_glacier_read_ctx(config);
    if(!*rctx){
        return evr_error;
    }
    return evr_ok;
}

int send_get_response(void *arg, int exists, int flags, size_t blob_size){
    int ret = evr_error;
    int *f = (int*)arg;
    struct evr_resp_header resp;
    if(exists){
        resp.status_code = evr_status_code_ok;
        resp.body_size = sizeof(uint8_t) + blob_size;
    } else {
        resp.status_code = evr_status_code_blob_not_found;
        resp.body_size = 0;
    }
    char buffer[evr_resp_header_n_size + (exists ? sizeof(uint8_t) : 0)];
    if(evr_format_resp_header(buffer, &resp) != evr_ok){
        goto end;
    }
    if(exists){
        *(uint8_t*)&buffer[evr_resp_header_n_size] = flags;
    }
    if(write_n(*f, buffer, sizeof(buffer)) != evr_ok){
        goto end;
    }
    ret = evr_ok;
 end:
    return ret;
}

int pipe_data(void *arg, const char *data, size_t data_size){
    int *f = (int*)arg;
    return write_n(*f, data, data_size);
}
