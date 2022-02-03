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

#include "basics.h"
#include "configuration.h"
#include "errors.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "glacier.h"
#include "files.h"

typedef struct {
    int socket;
} evr_connection_t;

int evr_glacier_tcp_server(const evr_glacier_storage_configuration *config);
int evr_glacier_make_tcp_socket();
int evr_connection_worker(void *context);
int send_get_response(void *arg, int exists, size_t blob_size);
int pipe_data(void *arg, const char *data, size_t data_size);

/**
 * config exists until the program is terminated.
 */
evr_glacier_storage_configuration *config;

int main(){
    config = create_evr_glacier_storage_configuration();
    if(!config){
        return 1;
    }
    const char *config_paths[] = {
        "~/.config/everarch/glacier-storage.json",
        "glacier-storage.json",
    };
    if(load_evr_glacier_storage_configurations(config, config_paths, sizeof(config_paths) / sizeof(char*)) != evr_ok){
        log_error("Failed to load configuration");
        return 1;
    }
    if(evr_quick_check_glacier(config) != evr_ok){
        log_error("Glacier quick check failed");
        return 1;
    }
    if(evr_glacier_tcp_server(config) != evr_ok){
        log_error("TCP server failed");
        return 1;
    }
    return 0;
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
    while(1){
        if(select(FD_SETSIZE, &active_fd_set, NULL, NULL, NULL) < 0){
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
                    evr_connection_t *context = malloc(sizeof(evr_connection_t));
                    if(!context){
                        goto context_alloc_fail;
                    }
                    context->socket = c;
                    thrd_t t;
                    if(thrd_create(&t, evr_connection_worker, context) != thrd_success){
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
    int result = evr_ok;
    evr_connection_t ctx = *(evr_connection_t*)context;
    free(context);
    log_debug("Started worker %d", ctx.socket);
    evr_glacier_read_ctx *rctx = NULL;
    const size_t buffer_size = max(evr_cmd_header_t_n_size, evr_resp_header_t_n_size);
    char buffer[buffer_size];
    evr_cmd_header_t cmd;
    while(1){
        const int header_result = read_n(ctx.socket, buffer, evr_cmd_header_t_n_size);
        if(header_result == evr_end){
            log_debug("Worker %d ends because of remote termination", ctx.socket);
            goto end;
        } else if (header_result != evr_ok){
            result = evr_error;
            goto end;
        }
        if(evr_parse_cmd_header(&cmd, buffer) != evr_ok){
            result = evr_error;
            goto end;
        }
        log_debug("Worker %d retrieved cmd 0x%x with body size %d", ctx.socket, cmd.type, cmd.body_size);
        switch(cmd.type){
        default:
            // unknown command
            log_error("Worker %d retieved unknown cmd 0x%x", ctx.socket, cmd.type);
            // TODO respond evr_status_code_unknown_cmd
            goto end;
        case evr_cmd_type_get_blob: {
            size_t body_size = evr_blob_key_size;
            if(cmd.body_size != body_size){
                result = evr_error;
                goto end;
            }
            evr_blob_key_t key;
            const int body_result = read_n(ctx.socket, (char*)&key, body_size);
            if(body_result != evr_ok){
                result = evr_error;
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
                    result = evr_error;
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
        case evr_cmd_type_put_blob: {
            if(cmd.body_size < evr_blob_key_size){
                result = evr_error;
                goto end;
            }
            size_t blob_size = cmd.body_size - evr_blob_key_size;
            if(blob_size > evr_max_blob_data_size){
                // TODO should we send a client error here?
                result = evr_error;
                goto end;
            }
            evr_blob_key_t key;
            const int key_result = read_n(ctx.socket, (char*)&key, evr_blob_key_size);
            if(key_result != evr_ok){
                result = evr_error;
                goto end;
            }
#ifdef EVR_LOG_DEBUG
            {
                evr_fmt_blob_key_t fmt_key;
                evr_fmt_blob_key(fmt_key, key);
                log_debug("Worker %d retrieved cmd put %s with %d bytes blob", ctx.socket, fmt_key, blob_size);
            }
#endif
            chunk_set_t *blob = read_into_chunks(ctx.socket, blob_size);
            if(!blob){
                result = evr_error;
                goto end;
            }
            evr_blob_key_t calced_key;
            if(evr_calc_blob_key(calced_key, blob_size, blob->chunks) != evr_ok){
                goto out_free_blob;
            }
            if(memcmp(key, calced_key, 0)){
                // TODO indicate to the client that the key does not
                // match the blob's hash
                goto out_free_blob;
            }
            // TODO put blob
            // TODO respond ok
            break;
            out_free_blob:
            evr_free_chunk_set(blob);
            goto end;
        }
        }
    }
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
