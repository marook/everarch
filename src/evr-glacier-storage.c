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
#include <gcrypt.h>

#include "basics.h"
#include "glacier-storage-configuration.h"
#include "errors.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "glacier.h"
#include "files.h"
#include "concurrent-glacier.h"
#include "server.h"
#include "configurations.h"
#include "configp.h"
#include "evr-tls.h"
#include "queue.h"
#include "daemon.h"

#define program_name "evr-glacier-storage"

const char *argp_program_version = program_name " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " is a content addressable storage server.";

static char args_doc[] = "";

#define default_bucket_dir_path EVR_PREFIX "/var/everarch/" program_name
#define default_host evr_glacier_storage_host
#define default_ssl_cert_path default_storage_ssl_cert_path
#define default_ssl_key_path EVR_PREFIX "/etc/everarch/" program_name "-key.pem"

#define arg_host 256
#define arg_ssl_cert_path 257
#define arg_ssl_key_path 258
#define arg_auth_token 259
#define arg_index_db 260
#define arg_log_path 261
#define arg_pid_path 262

static struct argp_option options[] = {
    {"host", arg_host, "HOST", 0, "The network interface at which the attr index server will listen on. The default is " default_host "."},
    {"port", 'p', "PORT", 0, "The tcp port at which the glacier storage server will listen. The default port is " to_string(evr_glacier_storage_port) "."},
    {"cert", arg_ssl_cert_path, "FILE", 0, "The path to the pem file which contains the public SSL certificate. Default path is " default_ssl_cert_path "."},
    {"key", arg_ssl_key_path, "FILE", 0, "The path to the pem file which contains the private SSL key. Default path is " default_ssl_key_path "."},
    {"auth-token", arg_auth_token, "TOKEN", 0, "An authorization token which must be presented by clients so their requests are accepted. Must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret. You can call 'openssl rand -hex 32' to generate a good token."},
    // TODO max-bucket-size
    {"bucket-dir", 'd', "DIR", 0, "Bucket directory path. This is the place where the data is persisted. Default path is " default_bucket_dir_path "."},
    {"index-db", arg_index_db, "DB", 0, "Path to where the sqlite bucket index DB should be put. The default is to put the index db within the bucket-dir."},
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"log", arg_log_path, "FILE", 0, "A file to which log output messages will be appended. By default logs are written to stdout."},
    {"pid", arg_pid_path, "FILE", 0, "A file to which the daemon's pid is written."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_glacier_storage_cfg *cfg = (struct evr_glacier_storage_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'd':
        evr_replace_str(cfg->bucket_dir_path, arg);
        break;
    case arg_index_db:
        evr_replace_str(cfg->index_db_path, arg);
        break;
    case arg_host:
        evr_replace_str(cfg->host, arg);
        break;
    case 'p':
        evr_replace_str(cfg->port, arg);
        break;
    case 'f':
        cfg->foreground = 1;
        break;
    case arg_log_path:
        evr_replace_str(cfg->log_path, arg);
        break;
    case arg_pid_path:
        evr_replace_str(cfg->pid_path, arg);
        break;
    case arg_ssl_cert_path:
        evr_replace_str(cfg->ssl_cert_path, arg);
        break;
    case arg_ssl_key_path:
        evr_replace_str(cfg->ssl_key_path, arg);
        break;
    case arg_auth_token:
        if(evr_parse_auth_token(cfg->auth_token, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->auth_token_set = 1;
        break;
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

sig_atomic_t running = 1;

struct evr_connection{
    struct evr_file socket;
    int sync_strategy;
};

/**
 * evr_list_blobs_blobs_len's value tries to fill one IP packet well.
 */
#define evr_list_blobs_blobs_len (1000 / (evr_blob_ref_size + sizeof(uint64_t)))

struct evr_list_blobs_ctx {
    struct evr_connection *connection;
    size_t blobs_used;
    struct evr_modified_blob blobs[evr_list_blobs_blobs_len];
};

int evr_load_glacier_storage_cfg(int argc, char **argv);

void handle_sigterm(int signum);
int evr_glacier_tcp_server(const struct evr_glacier_storage_cfg *cfg);
int evr_connection_worker(void *context);
int evr_work_unknown_cmd(struct evr_connection *ctx, struct evr_cmd_header *cmd);
int evr_work_put_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd);
int evr_work_stat_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx);
int evr_work_watch_blobs(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx);
int evr_work_configure_connection(struct evr_connection *ctx, struct evr_cmd_header *cmd);
int evr_handle_blob_list(void *ctx, const evr_blob_ref key, int flags, evr_time last_modified, int last_blob);
int evr_flush_list_blobs_ctx(struct evr_list_blobs_ctx *ctx);
int evr_ensure_worker_rctx_exists(struct evr_glacier_read_ctx **rctx, struct evr_connection *ctx);
int send_get_response(void *arg, int exists, int flags, size_t blob_size);
int pipe_data(void *arg, const char *data, size_t data_size);

/**
 * cfg exists until the program is terminated.
 */
struct evr_glacier_storage_cfg *cfg;

SSL_CTX *ssl_ctx;

int main(int argc, char **argv){
    int ret = evr_error;
    evr_log_app = "g";
    evr_init_basics();
    evr_tls_init();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    if(evr_load_glacier_storage_cfg(argc, argv) != evr_ok){
        goto out_with_tls_free;
    }
    ssl_ctx = evr_create_ssl_server_ctx(cfg->ssl_cert_path, cfg->ssl_key_path);
    if(!ssl_ctx){
        log_error("Unable to configure SSL context");
        goto out_with_free_configuration;
    }
    {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_sigterm;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    if(sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK){
        // read https://sqlite.org/threadsafe.html if you run into
        // this error
        log_error("Failed to configure multi-threaded mode for sqlite3");
        goto out_with_free_ssl_ctx;
    }
    if(evr_quick_check_glacier(cfg) != evr_ok){
        log_error("Glacier quick check failed");
        goto out_with_free_ssl_ctx;
    }
    if(!cfg->foreground){
        if(evr_daemonize(cfg->pid_path) != evr_ok){
            goto out_with_free_ssl_ctx;
        }
    }
    if(evr_persister_start(cfg) != evr_ok){
        log_error("Failed to start glacier persister thread");
        goto out_with_free_ssl_ctx;
    }
    int tcpret = evr_glacier_tcp_server(cfg);
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
 out_with_free_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
 out_with_free_configuration:
    // TODO we should wait for the worker threads to be finished before freeing config or maybe free config by OS when program ends?
    evr_free_glacier_storage_cfg(cfg);
 out_with_tls_free:
    evr_tls_free();
    return ret;
}

int evr_load_glacier_storage_cfg(int argc, char **argv){
    cfg = malloc(sizeof(struct evr_glacier_storage_cfg));
    if(!cfg){
        evr_panic("Unable to allocate memory for configuration");
        return evr_error;
    }
    cfg->host = strdup(default_host);
    cfg->port = strdup(to_string(evr_glacier_storage_port));
    cfg->ssl_cert_path = strdup(default_ssl_cert_path);
    cfg->ssl_key_path = strdup(default_ssl_key_path);
    cfg->auth_token_set = 0;
    memset(cfg->auth_token, 0, sizeof(cfg->auth_token));
    cfg->max_bucket_size = 1024 << 20;
    cfg->bucket_dir_path = strdup(default_bucket_dir_path);
    cfg->index_db_path = NULL;
    cfg->foreground = 0;
    cfg->log_path = NULL;
    cfg->pid_path = NULL;
    if(!cfg->host || !cfg->port || !cfg->bucket_dir_path){
        evr_panic("Unable to allocate memory for configuration");
        return evr_error;
    }
    struct configp configp = {
        options, parse_opt, args_doc, doc
    };
    char *config_paths[] = evr_program_config_paths();
    if(configp_parse(&configp, config_paths, cfg) != 0){
        evr_panic("Unable to parse config files");
        return evr_error;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, cfg);
    if(evr_setup_log(cfg->log_path) != evr_ok){
        return evr_error;
    }
    evr_single_expand_property(cfg->bucket_dir_path, panic);
    if(cfg->auth_token_set == 0){
        log_error("Setting an auth-token is mandatory. Call " program_name " --help for details how to set the auth-token.");
        return evr_error;
    }
    return evr_ok;
 panic:
    evr_panic("Unable to expand configuration values");
    return evr_error;
}

void handle_sigterm(int signum){
    if(running){
        log_info("Shutting down");
        running = 0;
    }
}

int evr_glacier_tcp_server(const struct evr_glacier_storage_cfg *cfg){
    int ret = evr_error;
    int s = evr_make_tcp_socket(cfg->host, cfg->port);
    if(s < 0){
        log_error("Failed to create socket");
        goto out;
    }
    if(listen(s, 7) != 0){
        log_error("Failed to listen on %s:%s", cfg->host, cfg->port);
        goto out_with_close_s;
    }
    log_info("Listening on %s:%s", cfg->host, cfg->port);
    fd_set active_fd_set;
    while(running){
        FD_ZERO(&active_fd_set);
        FD_SET(s, &active_fd_set);
        const int fd_limit = s + 1;
        int sret = select(fd_limit, &active_fd_set, NULL, NULL, NULL);
        if(sret == -1){
            // select returns -1 on sigint.
            ret = evr_end;
            goto out_with_close_s;
        } else if(sret < 0){
            goto out_with_close_s;
        }
        for(int i = 0; i < fd_limit; ++i){
            if(FD_ISSET(i, &active_fd_set)){
                if(i == s){
                    struct evr_connection *ctx = malloc(sizeof(struct evr_connection));
                    if(!ctx){
                        continue;
                    }
                    ctx->sync_strategy = evr_sync_strategy_default;
                    if(evr_tls_accept(&ctx->socket, s, ssl_ctx) != evr_ok){
                        goto out_with_free_ctx;
                    }
                    thrd_t t;
                    if(thrd_create(&t, evr_connection_worker, ctx) != thrd_success){
                        goto out_with_close_socket;
                    }
                    if(thrd_detach(t) != thrd_success){
                        evr_panic("Failed to detach connection worker thread");
                        goto out_with_close_socket;
                    }
                    continue;
                out_with_close_socket:
                    if(ctx->socket.close(&ctx->socket) != 0){
                        evr_panic("Unable to close connection socket");
                        free(ctx);
                        goto out_with_close_s;
                    }
                out_with_free_ctx:
                    free(ctx);
                }
            }
        }
    }
    ret = evr_ok;
 out_with_close_s:
    if(close(s) != 0){
        evr_panic("Unable to close listen socket.");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_authenticate_client(struct evr_file *c);

int evr_connection_worker(void *context){
    int result = evr_error;
    struct evr_connection ctx = *(struct evr_connection*)context;
    free(context);
    const int worker = ctx.socket.get_fd(&ctx.socket);
    log_debug("Started worker %d", worker);
    int auth_res = evr_authenticate_client(&ctx.socket);
    if(auth_res == evr_user_data_invalid){
        result = evr_ok;
        goto out_with_close_socket;
    } else if(auth_res != evr_ok) {
        goto out_with_close_socket;
    }
    struct evr_glacier_read_ctx *rctx = NULL;
    char buffer[evr_cmd_header_n_size];
    struct evr_cmd_header cmd;
    while(running){
        const int header_result = read_n(&ctx.socket, buffer, evr_cmd_header_n_size, NULL, NULL);
        if(header_result == evr_end){
            log_debug("Worker %d ends because of remote termination", ctx.socket.get_fd(&ctx.socket));
            result = evr_ok;
            goto out_with_free_rctx;
        } else if (header_result != evr_ok){
            goto out_with_free_rctx;
        }
        if(evr_parse_cmd_header(&cmd, buffer) != evr_ok){
            goto out_with_free_rctx;
        }
        log_debug("Worker %d retrieved cmd 0x%02x with body size %d", ctx.socket.get_fd(&ctx.socket), cmd.type, cmd.body_size);
        switch(cmd.type){
        default:
            if(evr_work_unknown_cmd(&ctx, &cmd) != evr_ok){
                goto out_with_free_rctx;
            }
            break;
        case evr_cmd_type_get_blob: {
            size_t body_size = evr_blob_ref_size;
            if(cmd.body_size != body_size){
                goto out_with_free_rctx;
            }
            evr_blob_ref key;
            const int body_result = read_n(&ctx.socket, (char*)&key, body_size, NULL, NULL);
            if(body_result != evr_ok){
                goto out_with_free_rctx;
            }
#ifdef EVR_LOG_DEBUG
            {
                evr_blob_ref_str fmt_key;
                evr_fmt_blob_ref(fmt_key, key);
                log_debug("Worker %d retrieved cmd get %s", ctx.socket.get_fd(&ctx.socket), fmt_key);
            }
#endif
            if(evr_ensure_worker_rctx_exists(&rctx, &ctx) != evr_ok){
                goto out_with_free_rctx;
            }
            int read_res = evr_glacier_read_blob(rctx, key, send_get_response, pipe_data, &ctx.socket);
#ifdef EVR_LOG_DEBUG
            if(read_res == evr_not_found) {
                evr_blob_ref_str fmt_key;
                evr_fmt_blob_ref(fmt_key, key);
                log_debug("Worker %d did not find key %s", ctx.socket.get_fd(&ctx.socket), fmt_key);
            }
#endif
            if(read_res != evr_ok && read_res != evr_not_found){
                // TODO should we send a server error here?
                goto out_with_free_rctx;
            }
            break;
        }
        case evr_cmd_type_put_blob:
            if(evr_work_put_blob(&ctx, &cmd) != evr_ok){
                goto out_with_free_rctx;
            }
            break;
        case evr_cmd_type_stat_blob:
            if(evr_work_stat_blob(&ctx, &cmd, &rctx) != evr_ok){
                goto out_with_free_rctx;
            }
            break;
        case evr_cmd_type_watch_blobs:
            if(evr_work_watch_blobs(&ctx, &cmd, &rctx) != evr_ok){
                goto out_with_free_rctx;
            } else {
                // evr_work_watch_blobs must close connection on end
                // to indicate no more blobs to client.
                result = evr_ok;
                goto out_with_free_rctx;
            }
            break;
        case evr_cmd_type_configure_connection:
            if(evr_work_configure_connection(&ctx, &cmd) != evr_ok){
                goto out_with_free_rctx;
            }
            break;
        }
    }
    result = evr_ok;
 out_with_free_rctx:
    if(rctx){
        if(evr_free_glacier_read_ctx(rctx) != evr_ok){
            result = evr_error;
        }
    }
 out_with_close_socket:
    if(ctx.socket.close(&ctx.socket) != 0){
        evr_panic("Unable to close socket of worker %d", worker);
        result = evr_error;
    }
    log_debug("Ended worker %d with result %d", worker, result);
    return result;
}

int evr_authenticate_client(struct evr_file *c){
    char buf[sizeof(uint8_t) + sizeof(evr_auth_token)];
    if(read_n(c, buf, sizeof(buf), NULL, NULL) != evr_ok){
        return evr_error;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    int auth_type;
    evr_pull_as(&bp, &auth_type, uint8_t);
    if(auth_type != evr_auth_type_token){
        log_debug("Worker %d client tried to authenticate using unknown authentication type %d", c->get_fd(c), auth_type);
        return evr_user_data_invalid;
    }
    evr_auth_token token;
    evr_pull_n(&bp, token, sizeof(evr_auth_token));
    if(memcmp(cfg->auth_token, token, sizeof(evr_auth_token)) != 0){
        log_debug("Worker %d client presented wrong auth token", c->get_fd(c));
        return evr_user_data_invalid;
    }
    log_debug("Client successfully authenticated");
    return evr_ok;
}

int evr_work_unknown_cmd(struct evr_connection *ctx, struct evr_cmd_header *cmd){
    struct evr_resp_header resp;
    char buf[evr_resp_header_n_size];
    log_error("Worker %d retieved unknown cmd 0x%02x", ctx->socket.get_fd(&ctx->socket), cmd->type);
    if(dump_n(&ctx->socket, cmd->body_size, NULL, NULL) != evr_ok){
        return evr_error;
    }
    resp.status_code = evr_unknown_request;
    resp.body_size = 0;
    if(evr_format_resp_header(buf, &resp) != evr_ok){
        return evr_error;
    }
    if(write_n(&ctx->socket, buf, evr_resp_header_n_size) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_work_put_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd){
    int ret = evr_error;
    if(cmd->body_size < evr_blob_ref_size){
        goto out;
    }
    size_t blob_size = cmd->body_size - evr_blob_ref_size - sizeof(uint8_t);
    if(blob_size > evr_max_blob_data_size){
        // TODO should we send a client error here?
        goto out;
    }
    struct evr_writing_blob wblob;
    if(read_n(&ctx->socket, (char*)&wblob.key, evr_blob_ref_size, NULL, NULL) != evr_ok){
        goto out;
    }
    uint8_t flags;
    if(read_n(&ctx->socket, (char*)&flags, sizeof(flags), NULL, NULL) != evr_ok){
        goto out;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, wblob.key);
        log_debug("Worker %d retrieved cmd put %s with flags 0x%02x and %d bytes blob", ctx->socket.get_fd(&ctx->socket), fmt_key, flags, blob_size);
    }
#endif
    evr_blob_ref_hd hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto out;
    }
    struct chunk_set *blob = read_into_chunks(&ctx->socket, blob_size, evr_blob_ref_write_se, hd);
    if(!blob){
        goto out_with_close_hd;
    }
    if(evr_blob_ref_hd_match(hd, wblob.key) != evr_ok){
        goto out_free_blob;
    }
    // TODO final check here if blob is already in store to reduce
    // duplicate blobs
    struct evr_persister_task task;
    wblob.flags = flags;
    wblob.size = blob_size;
    wblob.chunks = blob->chunks;
    wblob.sync_strategy = ctx->sync_strategy == evr_sync_strategy_default ? evr_sync_strategy_per_blob : ctx->sync_strategy;
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
    if(write_n(&ctx->socket, buffer, evr_resp_header_n_size) != evr_ok){
        goto out_destroy_task;
    }
    ret = evr_ok;
 out_destroy_task:
    if(evr_persister_destroy_task(&task) != evr_ok){
        ret = evr_error;
    }
 out_free_blob:
    evr_free_chunk_set(blob);
 out_with_close_hd:
    evr_blob_ref_close(hd);
 out:
    return ret;
}

int evr_work_stat_blob(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx){
    int ret = evr_error;
    if(cmd->body_size != evr_blob_ref_size){
        goto out;
    }
    evr_blob_ref key;
    if(read_n(&ctx->socket, (char*)&key, evr_blob_ref_size, NULL, NULL) != evr_ok){
        goto out;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_debug("Worker %d retrieved cmd stat %s", ctx->socket.get_fd(&ctx->socket), fmt_key);
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
        if(write_n(&ctx->socket, buf, evr_resp_header_n_size) != evr_ok){
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
        if(write_n(&ctx->socket, buf, buf_size) != evr_ok){
            goto out;
        }
    } else {
        log_error("evr_glacier_stat_blob failed with error code %d", stat_ret);
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_work_watch_blobs(struct evr_connection *ctx, struct evr_cmd_header *cmd, struct evr_glacier_read_ctx **rctx){
    int ret = evr_error;
    if(cmd->body_size != evr_blob_filter_n_size){
        goto out;
    }
    char buf[max(max(evr_blob_filter_n_size, evr_resp_header_n_size), evr_blob_ref_size + sizeof(uint64_t) + sizeof(uint8_t))];
    if(read_n(&ctx->socket, buf, evr_blob_filter_n_size, NULL, NULL) != evr_ok){
        goto out;
    }
    struct evr_blob_filter f;
    if(evr_parse_blob_filter(&f, buf) != evr_ok){
        goto out;
    }
    log_debug("Worker %d retrieved cmd watch with sort_order 0x%02x, flags_filter 0x%02x and last_modified_after %llu", ctx->socket.get_fd(&ctx->socket), f.sort_order, f.flags_filter, f.last_modified_after);
    struct evr_resp_header resp;
    resp.status_code = evr_status_code_ok;
    resp.body_size = 0;
    if(evr_format_resp_header(buf, &resp) != evr_ok){
        goto out;
    }
    if(write_n(&ctx->socket, buf, evr_resp_header_n_size) != evr_ok){
        goto out;
    }
    const int live_watch = f.sort_order == evr_cmd_watch_sort_order_last_modified;
    struct evr_queue *mod_blobs = NULL;
    if(live_watch){
        mod_blobs = evr_persister_add_watcher(&f);
        if(!mod_blobs){
            log_error("Worker %d can't add watcher because list full", ctx->socket.get_fd(&ctx->socket));
            goto out;
        }
    }
    if(evr_ensure_worker_rctx_exists(rctx, ctx) != evr_ok){
        goto out_with_rm_watcher;
    }
    struct evr_list_blobs_ctx lctx;
    lctx.connection = ctx;
    lctx.blobs_used = 0;
    if(evr_glacier_list_blobs(*rctx, evr_handle_blob_list, &f, &lctx) != evr_ok){
        goto out_with_rm_watcher;
    }
    if(evr_flush_list_blobs_ctx(&lctx) != evr_ok){
        goto out_with_rm_watcher;
    }
    if(live_watch){
        struct evr_modified_blob blob;
        while(running){
            if(ctx->socket.received_shutdown(&ctx->socket) == 1){
                log_debug("Worker %d retrieved shutdown request from peer", ctx->socket.get_fd(&ctx->socket));
                ret = evr_end;
                goto out_with_rm_watcher;
            }
            while(running){
                int take_res = evr_queue_take(mod_blobs, &blob);
                if(take_res == evr_not_found){
                    break;
                } else if(take_res != evr_ok){
                    goto out_with_rm_watcher;
                }
#ifdef EVR_LOG_DEBUG
                {
                    evr_blob_ref_str fmt_key;
                    evr_fmt_blob_ref(fmt_key, blob.key);
                    log_debug("Worker %d watch indicates blob with key %s modified", ctx->socket.get_fd(&ctx->socket), fmt_key);
                }
#endif
                struct evr_buf_pos bp;
                evr_init_buf_pos(&bp, buf);
                memcpy(bp.pos, blob.key, evr_blob_ref_size);
                bp.pos += evr_blob_ref_size;
                evr_push_map(&bp, &blob.last_modified, uint64_t, htobe64);
                int flags = evr_watch_flag_eob;
                evr_push_as(&bp, &flags, uint8_t);
                if(write_n(&ctx->socket, buf, evr_blob_ref_size + sizeof(uint64_t) + sizeof(uint8_t)) != evr_ok){
                    goto out_with_rm_watcher;
                }
            }
            if(!running){
                break;
            }
            int hang_up_res = evr_peer_hang_up(&ctx->socket);
            if(hang_up_res == evr_end){
                ret = evr_end;
                goto out_with_rm_watcher;
            } else if(hang_up_res != evr_ok){
                goto out_with_rm_watcher;
            }
        }
    }
    ret = evr_ok;
 out_with_rm_watcher:
    if(mod_blobs && evr_persister_rm_watcher(mod_blobs) != evr_ok){
        evr_panic("Worker %d is unable to remove a persister watcher", ctx->socket.get_fd(&ctx->socket));
        ret = evr_error;
    }
 out:
    log_debug("Worker %d watch ends with status %d", ctx->socket.get_fd(&ctx->socket), ret);
    return ret;
}

int evr_work_configure_connection(struct evr_connection *ctx, struct evr_cmd_header *cmd){
    char buf[max(512, evr_resp_header_n_size)];
    struct evr_buf_pos bp;
    int sync_strategy;
    struct evr_resp_header resp;
    if(cmd->body_size < 1 || cmd->body_size > sizeof(buf)){
        log_error("Worker %d received illegal configure connection body size %zu", ctx->socket.get_fd(&ctx->socket), cmd->body_size);
        return evr_error;
    }
    if(read_n(&ctx->socket, buf, cmd->body_size, NULL, NULL) != evr_ok){
        return evr_error;
    }
    evr_init_buf_pos(&bp, buf);
    evr_pull_as(&bp, &sync_strategy, uint8_t);
    if(sync_strategy != evr_sync_strategy_default && sync_strategy != evr_sync_strategy_per_blob && sync_strategy != evr_sync_strategy_avoid){
        log_error("Worker %d received unknown sync strategy 0x%02x", ctx->socket.get_fd(&ctx->socket), sync_strategy);
        sync_strategy = evr_sync_strategy_default;
    }
#ifdef EVR_LOG_DEBUG
    if(ctx->sync_strategy != sync_strategy){
        log_debug("Worker %d switches from sync strategy 0x%02x to 0x%02x", ctx->socket.get_fd(&ctx->socket), ctx->sync_strategy, sync_strategy);
    }
#endif
    ctx->sync_strategy = sync_strategy;
    resp.status_code = evr_status_code_ok;
    resp.body_size = 0;
    if(evr_format_resp_header(buf, &resp) != evr_ok){
        return evr_error;
    }
    if(write_n(&ctx->socket, buf, evr_resp_header_n_size) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_handle_blob_list(void *ctx0, const evr_blob_ref key, int flags, evr_time last_modified, int last_blob){
    int ret = evr_error;
    struct evr_list_blobs_ctx *ctx = ctx0;
    if(ctx->blobs_used == evr_list_blobs_blobs_len){
        if(evr_flush_list_blobs_ctx(ctx) != evr_ok){
            goto out;
        }
    }
    struct evr_modified_blob *b = &ctx->blobs[ctx->blobs_used];
    memcpy(b->key, key, evr_blob_ref_size);
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
        char buf[ctx->blobs_used * (evr_blob_ref_size + sizeof(uint64_t) + sizeof(uint8_t))];
        struct evr_buf_pos bp;
        evr_init_buf_pos(&bp, buf);
        for(size_t i = 0; i < ctx->blobs_used; ++i){
            struct evr_modified_blob *b = &ctx->blobs[i];
            memcpy(bp.pos, b->key, evr_blob_ref_size);
            bp.pos += evr_blob_ref_size;
            evr_push_map(&bp, &b->last_modified, uint64_t, htobe64);
            evr_push_as(&bp, &b->flags, uint8_t);
        }
        if(write_n(&ctx->connection->socket, buf, sizeof(buf)) != evr_ok){
            goto out;
        }
        ctx->blobs_used = 0;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_ensure_worker_rctx_exists(struct evr_glacier_read_ctx **rctx, struct evr_connection *ctx){
    if(*rctx){
        return evr_ok;
    }
    log_debug("Worker %d creates a glacier read ctx", ctx->socket.get_fd(&ctx->socket));
    *rctx = evr_create_glacier_read_ctx(cfg);
    if(!*rctx){
        return evr_error;
    }
    return evr_ok;
}

int send_get_response(void *arg, int exists, int flags, size_t blob_size){
    int ret = evr_error;
    struct evr_file *f = arg;
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
    if(write_n(f, buffer, sizeof(buffer)) != evr_ok){
        goto end;
    }
    ret = evr_ok;
 end:
    return ret;
}

int pipe_data(void *arg, const char *data, size_t data_size){
    struct evr_file *f = arg;
    return write_n(f, data, data_size);
}
