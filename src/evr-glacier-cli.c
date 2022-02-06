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
#include <argp.h>
#include <string.h>

#include "basics.h"
#include "errors.h"
#include "keys.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "files.h"

const char *argp_program_version = "evr-glacier-cli " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] =
    "evr-glacier-cli is a command line client for interacting with evr-glacier-storage servers.\n\n"
    "Possible commands are get and put.\n\n"
    "The get command expects the key of the to be fetched blob as second argument. The blob content will be written to stdout\n\n"
    "The put command retrieves a blob via stdin and sends it to the evr-glacier-storage.";

static char args_doc[] = "CMD";

#define cli_cmd_none 0
#define cli_cmd_get 1
#define cli_cmd_put 2

typedef struct {
    int cmd;
    char *key;
} cli_args_t;

static error_t parse_opt(int key, char *arg, struct argp_state *state){
    cli_args_t *cli_args = (cli_args_t*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            argp_usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            if(strcmp("get", arg) == 0){
                cli_args->cmd = cli_cmd_get;
            } else if(strcmp("put", arg) == 0){
                cli_args->cmd = cli_cmd_put;
            } else {
                argp_usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case 1:
            if(cli_args->cmd == cli_cmd_get){
                cli_args->key = arg;
            } else {
                argp_usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        }
        break;
    case ARGP_KEY_END:
        switch(cli_args->cmd){
        default:
            argp_usage (state);
            return ARGP_ERR_UNKNOWN;
        case cli_cmd_get:
            if (state->arg_num < 2) {
                // not enough arguments
                argp_usage (state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case cli_cmd_put:
            break;
        }
        break;
    }
    return 0;
}

static struct argp argp = { 0, parse_opt, args_doc, doc };

int evr_cli_get(char *fmt_key);
int evr_cli_put();
int evr_connect_to_storage();

int main(int argc, char **argv){
    evr_log_fd = STDERR_FILENO;
    cli_args_t cli_args;
    cli_args.cmd = cli_cmd_none;
    cli_args.key = NULL;
    argp_parse(&argp, argc, argv, 0, 0, &cli_args);
    switch(cli_args.cmd){
    default:
        return 1;
    case cli_cmd_get:
        return evr_cli_get(cli_args.key);
    case cli_cmd_put:
        return evr_cli_put();
    }
    return 0;
}

int evr_cli_get(char *fmt_key){
    int result = evr_error;
    evr_blob_key_t key;
    if(evr_parse_blob_key(key, fmt_key) != evr_ok){
        log_error("Invalid key format");
        goto fail;
    }
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto fail;
    }
    char buffer[max(evr_cmd_header_n_size, evr_resp_header_t_n_size)];
    struct evr_cmd_header cmd;
    cmd.type = evr_cmd_type_get_blob;
    cmd.body_size = evr_blob_key_size;
    if(evr_format_cmd_header(buffer, &cmd) != evr_ok){
        goto cmd_format_fail;
    }
    log_debug("Sending get %s command to server", fmt_key);
    // TODO combine the following two write_n calls into one as we
    // want to only create one ip data packet and not two
    if(write_n(c, buffer, evr_cmd_header_n_size) != evr_ok){
        goto cmd_format_fail;
    }
    if(write_n(c, key, evr_blob_key_size) != evr_ok){
        goto cmd_format_fail;
    }
    log_debug("Reading storage response");
    if(read_n(c, buffer, evr_resp_header_t_n_size) != evr_ok){
        goto cmd_format_fail;
    }
    evr_resp_header_t resp;
    if(evr_parse_resp_header(&resp, buffer) != evr_ok){
        goto cmd_format_fail;
    }
    log_debug("Storage responded with status code 0x%x and body size %d", resp.status_code, resp.body_size);
    if(resp.status_code == evr_status_code_blob_not_found){
        log_error("not found");
        goto cmd_format_fail;
    } else if(resp.status_code != evr_status_code_ok){
        goto cmd_format_fail;
    }
    if(pipe_n(STDOUT_FILENO, c, resp.body_size) != evr_ok){
        goto cmd_format_fail;
    }
    result = evr_ok;
 cmd_format_fail:
    if(close(c)){
        result = evr_error;
    }
 fail:
    return result;
}

int evr_cli_put(){
    int ret = evr_error;
    struct chunk_set *blob = evr_allocate_chunk_set(0);
    if(!blob){
        goto out;
    }
    if(append_into_chunk_set(blob, STDIN_FILENO) != evr_ok){
        goto out_with_free_blob;
    }
    log_debug("Read blob with %d bytes from stdin", blob->size_used);
    if(blob->size_used > evr_max_blob_data_size){
        log_error("Input exceeds maximum blob size of %d bytes", evr_max_blob_data_size);
        goto out_with_free_blob;
    }
    evr_blob_key_t key;
    if(evr_calc_blob_key(key, blob->size_used, blob->chunks) != evr_ok){
        goto out_with_free_blob;
    }
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_blob;
    }
    char buffer[max(evr_cmd_header_n_size + evr_blob_key_size, evr_resp_header_t_n_size)];
    struct evr_cmd_header cmd;
    cmd.type = evr_cmd_type_put_blob;
    cmd.body_size = evr_blob_key_size + blob->size_used;
    if(evr_format_cmd_header(buffer, &cmd) != evr_ok){
        goto out_with_close_c;
    }
    memcpy(&buffer[evr_cmd_header_n_size], key, evr_blob_key_size);
#ifdef EVR_LOG_DEBUG
    {
        evr_fmt_blob_key_t fmt_key;
        evr_fmt_blob_key(fmt_key, key);
        log_debug("Sending put %s command for %d bytes blob", fmt_key, blob->size_used);
    }
#endif
    if(write_n(c, buffer, evr_cmd_header_n_size + evr_blob_key_size) != evr_ok){
        goto out_with_close_c;
    }
    if(write_chunk_set(c, blob) != evr_ok){
        goto out_with_close_c;
    }
    log_debug("Reading storage response");
    if(read_n(c, buffer, evr_resp_header_t_n_size) != evr_ok){
        goto out_with_close_c;
    }
    evr_resp_header_t resp;
    if(evr_parse_resp_header(&resp, buffer) != evr_ok){
        goto out_with_close_c;
    }
    log_debug("Storage responded with status code 0x%x", resp.status_code);
    if(resp.status_code != evr_status_code_ok){
        goto out_with_close_c;
    }
    ret = evr_ok;
 out_with_close_c:
    if(close(c)){
        ret = evr_error;
    }
 out_with_free_blob:
    evr_free_chunk_set(blob);
 out:
    return ret;
}

int evr_connect_to_storage(){
    int s = socket(PF_INET, SOCK_STREAM, 0);
    if(s < 0){
        goto socket_fail;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(evr_glacier_storage_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if(connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        goto connect_fail;
    }
    return s;
 connect_fail:
    close(s);
 socket_fail:
    return -1;
}
