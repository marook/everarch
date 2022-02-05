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

#include "basics.h"
#include "configuration.h"
#include "errors.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "glacier.h"
#include "files.h"
#include "concurrent-glacier.h"

int running = 1;

struct evr_connection{
    int socket;
};

void handle_sigterm(int signum);
int evr_glacier_tcp_server(const evr_glacier_storage_configuration *config);
int evr_glacier_make_tcp_socket();
int evr_connection_worker(void *context);
int evr_work_put_blob(struct evr_connection *ctx, evr_cmd_header_t *cmd);
int send_get_response(void *arg, int exists, size_t blob_size);
int pipe_data(void *arg, const char *data, size_t data_size);

/**
 * config exists until the program is terminated.
 */
evr_glacier_storage_configuration *config;

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

int evr_glacier_tcp_server(const evr_glacier_storage_configuration *config){
    int s = evr_glacier_make_tcp_socket(evr_glacier_storage_port);
    if(s < 0){
        log_error("Failed to create socket");
        return evr_error;
    }
    if(listen(s, 7) < 0){
        log_error("Failed to listen on localhost:%d", evr_glacier_storage_port);
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
            return evr_end;
        } else if(sret < 0){
            return evr_error;
        }
        for(int i = 0; i < FD_SETSIZE; ++i){
            if(FD_ISSET(i, &active_fd_set)){
                if(i == s){
                    // incomming connection request
                    socklen_t size = sizeof(client_addr);
                    int c = accept(s, (struct sockaddr*)&client_addr, &size);
                    if(c < 0){
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
    return evr_ok;
}

int evr_glacier_make_tcp_socket(){
    int s = socket(PF_INET, SOCK_STREAM, 0);
    if(s < 0){
        return -1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(evr_glacier_storage_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        log_error("Failed to bind to localhost:%d", evr_glacier_storage_port);
        return -1;
    }
    return s;
}

int evr_connection_worker(void *context){
    int result = evr_error;
    struct evr_connection ctx = *(struct evr_connection*)context;
    free(context);
    log_debug("Started worker %d", ctx.socket);
    struct evr_glacier_read_ctx *rctx = NULL;
    // TODO i guess buffer is never used for storing responses. why do
    // we make sure it fits evr_resp_header_t_n_size
    const size_t buffer_size = max(evr_cmd_header_t_n_size, evr_resp_header_t_n_size);
    char buffer[buffer_size];
    evr_cmd_header_t cmd;
    while(running){
        const int header_result = read_n(ctx.socket, buffer, evr_cmd_header_t_n_size);
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
            log_error("Worker %d retieved unknown cmd 0x%x", ctx.socket, cmd.type);
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
            if(!rctx){
                log_debug("Worker %d creates a glacier read ctx", ctx.socket);
                rctx = evr_create_glacier_read_ctx(config);
                if(!rctx){
                    goto end;
                }
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

int evr_work_put_blob(struct evr_connection *ctx, evr_cmd_header_t *cmd){
    int ret = evr_error;
    if(cmd->body_size < evr_blob_key_size){
        goto out;
    }
    size_t blob_size = cmd->body_size - evr_blob_key_size;
    if(blob_size > evr_max_blob_data_size){
        // TODO should we send a client error here?
        goto out;
    }
    struct evr_writing_blob wblob;
    const int key_result = read_n(ctx->socket, (char*)&wblob.key, evr_blob_key_size);
    if(key_result != evr_ok){
        goto out;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_fmt_blob_key_t fmt_key;
        evr_fmt_blob_key(fmt_key, wblob.key);
        log_debug("Worker %d retrieved cmd put %s with %d bytes blob", ctx->socket, fmt_key, blob_size);
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
        goto out_free_blob;
    }
    evr_persister_task task;
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
    evr_resp_header_t resp;
    resp.status_code = evr_status_code_ok;
    resp.body_size = 0;
    char buffer[evr_resp_header_t_n_size];
    if(evr_format_resp_header(buffer, &resp) != evr_ok){
        goto out_destroy_task;
    }
    if(write_n(ctx->socket, buffer, evr_resp_header_t_n_size) != evr_ok){
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

int send_get_response(void *arg, int exists, size_t blob_size){
    int ret = evr_error;
    int *f = (int*)arg;
    evr_resp_header_t resp;
    if(exists){
        resp.status_code = evr_status_code_ok;
        resp.body_size = blob_size;
    } else {
        resp.status_code = evr_status_code_blob_not_found;
        resp.body_size = 0;
    }
    char buffer[evr_resp_header_t_n_size];
    if(evr_format_resp_header(buffer, &resp) != evr_ok){
        goto end;
    }
    if(write_n(*f, buffer, evr_resp_header_t_n_size) != evr_ok){
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
