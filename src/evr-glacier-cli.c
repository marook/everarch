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
#include <netdb.h>
#include <arpa/inet.h>
#include <argp.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>

#include "basics.h"
#include "errors.h"
#include "keys.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "files.h"
#include "claims.h"
#include "signatures.h"
#include "evr-glacier-client.h"

const char *argp_program_version = "evr-glacier-cli " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] =
    "evr-glacier-cli is a command line client for interacting with evr-glacier-storage servers.\n\n"
    "Possible commands are get, put, sign-put, post-file or watch.\n\n"
    "The get command expects the key of the to be fetched blob as second argument. The blob content will be written to stdout\n\n"
    "The put command retrieves a blob via stdin and sends it to the evr-glacier-storage.\n\n"
    "The sign-put command retrieves textual content via stdin, signs it and sends it to the evr-glacier-storage.\n\n"
    "The get-file command expects one file claim key argument. If found the first file in the claim will be written to stdout.\n\n"
    "The post-file command expects one file name argument for upload to the evr-glacier-storage.\n\n"
    "The watch command prints modified blob keys.";

static char args_doc[] = "CMD";

static struct argp_option options[] = {
    {"flags", 'f', "F", 0, "Use the given flags when put a blob to evr-glacier-storage."},
    {"flags-filter", 'f', "F", 0, "Only watch blobs which have set at least the given flag bits."},
    {"last-modified-after", 'm', "T", 0, "Start watching blobs after T. T is in unix epoch format in seconds."},
    {"title", 't', "T", 0, "Title of the created claim. Might be used together with post-file."},
    {0}
};

#define cli_cmd_none 0
#define cli_cmd_get 1
#define cli_cmd_put 2
#define cli_cmd_sign_put 3
#define cli_cmd_get_file 4
#define cli_cmd_post_file 5
#define cli_cmd_watch_blobs 6

struct cli_arguments {
    int cmd;
    char *key;
    char *file;
    int flags;
    char *title;
    unsigned long long last_modified_after;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state){
    struct cli_arguments *cli_args = (struct cli_arguments*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'f': {
        size_t arg_len = strlen(arg);
        size_t parsed_len = sscanf(arg, "%d", &cli_args->flags);
        if(arg_len == 0 || parsed_len != 1){
            argp_usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    case 'm': {
        size_t arg_len = strlen(arg);
        size_t parsed_len = sscanf(arg, "%llu", &cli_args->last_modified_after);
        if(arg_len == 0 || parsed_len != 1){
            argp_usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    case 't':
        cli_args->title = strdup(arg);
        break;
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
            } else if(strcmp("sign-put", arg) == 0){
                cli_args->cmd = cli_cmd_sign_put;
            } else if(strcmp("get-file", arg) == 0){
                cli_args->cmd = cli_cmd_get_file;
            } else if(strcmp("post-file", arg) == 0){
                cli_args->cmd = cli_cmd_post_file;
            } else if(strcmp("watch", arg) == 0){
                cli_args->cmd = cli_cmd_watch_blobs;
            } else {
                argp_usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case 1:
            if(cli_args->cmd == cli_cmd_get || cli_args->cmd == cli_cmd_get_file){
                cli_args->key = arg;
            } else if(cli_args->cmd == cli_cmd_post_file){
                cli_args->file = arg;
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
        case cli_cmd_get_file:
        case cli_cmd_post_file:
            if (state->arg_num < 2) {
                // not enough arguments
                argp_usage (state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case cli_cmd_put:
        case cli_cmd_sign_put:
        case cli_cmd_watch_blobs:
            break;
        }
        break;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int evr_cli_get(char *fmt_key);
int evr_cli_put(int flags);
int evr_cli_sign_put(int flags);
int evr_cli_get_file(char *fmt_key);
int evr_write_cmd_get_blob(int fd, evr_blob_ref key);
int evr_cli_post_file(char *file, char *title);
int evr_cli_watch_blobs(int flags_filter, unsigned long long last_modified_after);
int evr_stat_and_put(int c, evr_blob_ref key, int flags, struct chunk_set *blob);

int main(int argc, char **argv){
    evr_log_fd = STDERR_FILENO;
    struct cli_arguments cli_args;
    cli_args.cmd = cli_cmd_none;
    cli_args.key = NULL;
    cli_args.file = NULL;
    cli_args.flags = 0;
    cli_args.title = NULL;
    // LLONG_MAX instead of ULLONG_MAX because of limitations in
    // glacier's sqlite.
    cli_args.last_modified_after = LLONG_MAX;
    argp_parse(&argp, argc, argv, 0, 0, &cli_args);
    int ret;
    switch(cli_args.cmd){
    default:
        ret = 1;
        break;
    case cli_cmd_get:
        ret = evr_cli_get(cli_args.key);
        break;
    case cli_cmd_put:
        ret = evr_cli_put(cli_args.flags);
        break;
    case cli_cmd_sign_put:
        ret = evr_cli_sign_put(cli_args.flags);
        break;
    case cli_cmd_get_file:
        ret = evr_cli_get_file(cli_args.key);
        break;
    case cli_cmd_post_file:
        ret = evr_cli_post_file(cli_args.file, cli_args.title);
        break;
    case cli_cmd_watch_blobs:
        ret = evr_cli_watch_blobs(cli_args.flags, cli_args.last_modified_after);
        break;
    }
    if(cli_args.title){
        free(cli_args.title);
    }
    return ret;
}

int evr_cli_get(char *fmt_key){
    int result = evr_error;
    evr_blob_ref key;
    if(evr_parse_blob_ref(key, fmt_key) != evr_ok){
        log_error("Invalid key format");
        goto fail;
    }
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto fail;
    }
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(c, key, &resp) != evr_ok){
        goto cmd_format_fail;
    }
    if(resp.status_code == evr_status_code_blob_not_found){
        log_error("not found");
        goto cmd_format_fail;
    } else if(resp.status_code != evr_status_code_ok){
        goto cmd_format_fail;
    }
    // read flags but don't use them
    char buf[1];
    if(read_n(c, buf, sizeof(buf)) != evr_ok){
        goto cmd_format_fail;
    }
    if(pipe_n(STDOUT_FILENO, c, resp.body_size - 1) != evr_ok){
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

int evr_cli_put(int flags){
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
    evr_blob_ref key;
    if(evr_calc_blob_ref(key, blob->size_used, blob->chunks) != evr_ok){
        goto out_with_free_blob;
    }
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_blob;
    }
    if(evr_stat_and_put(c, key, flags, blob) != evr_ok){
        goto out_with_close_c;
    }
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
    printf("%s\n", fmt_key);
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

int evr_cli_sign_put(int flags){
    int ret = evr_error;
    evr_init_signatures();
    struct dynamic_array *raw_buf = alloc_dynamic_array(16 << 10);
    if(!raw_buf){
        goto out;
    }
    int read_res = read_fd(&raw_buf, STDIN_FILENO, evr_max_blob_data_size + 1);
    if(read_res == evr_ok){
        log_error("Input exceeds maximum blob size of %d bytes", evr_max_blob_data_size);
        goto out_with_free_raw_buf;
    } else if(read_res != evr_end){
        goto out_with_free_raw_buf;
    }
    if(raw_buf->size_used + 1 > raw_buf->size_allocated){
        raw_buf = grow_dynamic_array_at_least(raw_buf, raw_buf->size_used + 1);
        if(!raw_buf){
            goto out;
        }
    }
    raw_buf->data[raw_buf->size_used] = '\0';
    struct dynamic_array *signed_buf = NULL;
    if(evr_sign(&signed_buf, raw_buf->data) != evr_ok){
        goto out_with_free_signed_buf;
    }
    if(signed_buf->size_used > evr_max_blob_data_size){
        log_error("Signed input exceeds maximum blob size of %d bytes", evr_max_blob_data_size);
        goto out_with_free_signed_buf;
    }
    struct chunk_set signed_cs;
    if(evr_chunk_setify(&signed_cs, signed_buf->data, signed_buf->size_used) != evr_ok){
        goto out_with_free_signed_buf;
    }
    evr_blob_ref key;
    if(evr_calc_blob_ref(key, signed_cs.size_used, signed_cs.chunks) != evr_ok){
        goto out_with_free_signed_buf;
    }
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_signed_buf;
    }
    if(evr_stat_and_put(c, key, flags, &signed_cs) != evr_ok){
        goto out_with_close_c;
    }
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
    printf("%s\n", fmt_key);
    ret = evr_ok;
 out_with_close_c:
    close(c);
 out_with_free_signed_buf:
    if(signed_buf){
        free(signed_buf);
    }
 out_with_free_raw_buf:
    if(raw_buf){
        free(raw_buf);
    }
 out:
    return ret;
}

struct post_file_ctx {
    int c;
    struct dynamic_array *slices;
};

int evr_post_and_collect_file_slice(char* buf, size_t size, void *ctx0);

int evr_cli_get_file(char *fmt_key){
    int ret = evr_error;
    evr_init_signatures();
    xmlInitParser();
    evr_blob_ref key;
    if(evr_parse_blob_ref(key, fmt_key) != evr_ok){
        goto out;
    }
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out;
    }
    xmlDocPtr doc = evr_fetch_signed_xml(c, key);
    if(!doc){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("No validly signed XML found for key %s", fmt_key);
        goto out;
    }
    xmlNode *cs = evr_get_root_claim_set(doc);
    if(!cs){
        log_error("No claim set found in blob");
        goto out_with_free_doc;
    }
    xmlNode *fc = evr_first_claim(cs);
    while(1){
        if(!fc){
            log_error("No file claim found in claim set");
            goto out_with_free_doc;
        }
        if(evr_is_evr_element(fc, "file")){
            break;
        }
        fc = evr_next_claim(fc);
    }
    xmlNode *fbody = evr_find_next_element(fc->children, "body");
    if(!fbody){
        log_error("No body found in file claim");
        goto out_with_free_doc;
    }
    xmlNode *slice = evr_find_next_element(fbody->children, "slice");
    evr_blob_ref ref;
    struct evr_resp_header resp;
    char buf[1];
    while(1){
        if(!slice){
            break;
        }
        char *fmt_ref = (char*)xmlGetProp(slice, BAD_CAST "ref");
        if(!fmt_ref){
            goto out_with_free_doc;
        }
        int pkret = evr_parse_blob_ref(ref, fmt_ref);
        xmlFree(fmt_ref);
        if(pkret != evr_ok){
            goto out_with_free_doc;
        }
        if(evr_write_cmd_get_blob(c, ref) != evr_ok){
            goto out_with_free_doc;
        }
        if(evr_read_resp_header(c, &resp) != evr_ok){
            goto out_with_free_doc;
        }
        if(resp.status_code != evr_status_code_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, ref);
            log_error("Failed to fetch file slice blob with key %s. Response status code was 0x%02x.", fmt_key, resp.status_code);
            goto out_with_free_doc;
        }
        // read flags but don't use them
        if(read_n(c, buf, 1) != evr_ok){
            goto out_with_free_doc;
        }
        if(pipe_n(STDOUT_FILENO, c, resp.body_size - 1) != evr_ok){
            goto out_with_free_doc;
        }
        slice = evr_find_next_element(slice->next, "slice");
    }
    ret = evr_ok;
 out_with_free_doc:
    xmlFreeDoc(doc);
 out:
    xmlCleanupParser();
    return ret;
}

int evr_cli_post_file(char *file, char *title){
    int ret = evr_error;
    evr_init_signatures();
    int f = open(file, O_RDONLY);
    if(f < 0){
        goto out;
    }
    struct post_file_ctx ctx;
    ctx.c = evr_connect_to_storage();
    if(ctx.c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_close_f;
    }
    ctx.slices = alloc_dynamic_array(100 * sizeof(struct evr_file_slice));
    if(!ctx.slices){
        goto out_with_close_c;
    }
    if(evr_rollsum_split(f, SIZE_MAX, evr_post_and_collect_file_slice, &ctx) != evr_end){
        goto out_with_free_slice_keys;
    }
    struct evr_file_claim fc;
    // warning to future me: at the following expression we modify the
    // content of file
    fc.title = title ? title : basename(file);
    fc.slices_len = ctx.slices->size_used / sizeof(struct evr_file_slice);
    fc.slices = (struct evr_file_slice*)ctx.slices->data;
    log_debug("Uploaded %d file segments", fc.slices_len);
    time_t t;
    time(&t);
    struct evr_claim_set cs;
    if(evr_init_claim_set(&cs, &t) != evr_ok){
        goto out_with_free_slice_keys;
    }
    if(evr_append_file_claim(&cs, &fc) != evr_ok){
        goto out_with_free_claim_set;
    }
    if(evr_finalize_claim_set(&cs) != evr_ok){
        goto out_with_free_claim_set;
    }
    struct dynamic_array *sc = NULL;
    if(evr_sign(&sc, (char*)cs.out->content) != evr_ok){
        log_error("Failed to sign file claim");
        goto out_with_free_claim_set;
    }
    struct chunk_set sc_blob;
    if(evr_chunk_setify(&sc_blob, sc->data, sc->size_used) != evr_ok){
        goto out_with_free_sc;
    }
    evr_blob_ref key;
    if(evr_calc_blob_ref(key, sc_blob.size_used, sc_blob.chunks) != evr_ok){
        goto out_with_free_sc;
    }
    if(evr_stat_and_put(ctx.c, key, evr_blob_flag_claim, &sc_blob) != evr_ok){
        goto out_with_free_sc;
    }
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
    printf("%s\n", fmt_key);
    ret = evr_ok;
 out_with_free_sc:
    if(sc){
        free(sc);
    }
 out_with_free_claim_set:
    if(evr_free_claim_set(&cs) != evr_ok){
        ret = evr_error;
    }
 out_with_free_slice_keys:
    if(ctx.slices){
        free(ctx.slices);
    }
 out_with_close_c:
    if(close(ctx.c)){
        ret = evr_error;
    }
 out_with_close_f:
    if(close(f)){
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_post_and_collect_file_slice(char* buf, size_t size, void *ctx0){
    int ret = evr_error;
    struct post_file_ctx *ctx = ctx0;
    size_t allocated_slices_len = ctx->slices->size_allocated / sizeof(struct evr_file_slice);
    size_t used_slices_len = ctx->slices->size_used / sizeof(struct evr_file_slice);
    if(allocated_slices_len <= used_slices_len){
        ctx->slices = grow_dynamic_array_at_least(ctx->slices, ctx->slices->size_allocated + 100 * sizeof(struct evr_file_slice));
        if(!ctx->slices){
            log_error("Failed to grow slices buffer");
            goto out;
        }
        used_slices_len = ctx->slices->size_used / sizeof(struct evr_file_slice);
    }
    struct evr_file_slice *fs = &((struct evr_file_slice*)ctx->slices->data)[used_slices_len];
    struct chunk_set blob;
    if(evr_chunk_setify(&blob, buf, size) != evr_ok){
        goto out;
    }
    if(evr_calc_blob_ref(fs->ref, size, blob.chunks) != evr_ok){
        goto out;
    }
    if(evr_stat_and_put(ctx->c, fs->ref, 0, &blob) != evr_ok){
        goto out;
    }
    fs->size = size;
    ctx->slices->size_used += sizeof(struct evr_file_slice);
    ret = evr_ok;
 out:
    return ret;
}

int evr_cli_watch_blobs(int flags_filter, unsigned long long last_modified_after){
    int ret = evr_error;
    struct evr_blob_filter f;
    f.flags_filter = flags_filter;
    f.last_modified_after = last_modified_after;
    int c = evr_connect_to_storage();
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out;
    }
    if(evr_req_cmd_watch_blobs(c, &f) != evr_ok){
        goto out_with_close_c;
    }
    struct evr_watch_blobs_body body;
    evr_blob_ref_str fmt_key;
    while(1){
        if(evr_read_watch_blobs_body(c, &body) != evr_ok){
            goto out_with_close_c;
        }
        evr_fmt_blob_ref(fmt_key, body.key);
        printf("%s %llu %02x\n", fmt_key, body.last_modified, body.flags);
        fflush(stdout);
    }
    ret = evr_ok;
 out_with_close_c:
    if(close(c)){
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_stat_and_put(int c, evr_blob_ref key, int flags, struct chunk_set *blob){
    int ret = evr_error;
    char buffer[max(max(evr_cmd_header_n_size + evr_blob_ref_size + sizeof(uint8_t), evr_resp_header_n_size), evr_stat_blob_resp_n_size)];
#ifdef EVR_LOG_DEBUG
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
#endif
    {
        struct evr_buf_pos bp;
        evr_init_buf_pos(&bp, buffer);
        struct evr_cmd_header cmd;
        cmd.type = evr_cmd_type_stat_blob;
        cmd.body_size = evr_blob_ref_size;
        if(evr_format_cmd_header(bp.pos, &cmd) != evr_ok){
            goto out;
        }
        bp.pos += evr_cmd_header_n_size;
        evr_push_n(&bp, key, evr_blob_ref_size);
        log_debug("Sending stat %s command", fmt_key);
        if(write_n(c, buffer, evr_cmd_header_n_size + evr_blob_ref_size) != evr_ok){
            goto out;
        }
    }
    {
        log_debug("Reading storage response");
        if(read_n(c, buffer, evr_resp_header_n_size) != evr_ok){
            goto out;
        }
        struct evr_resp_header resp;
        if(evr_parse_resp_header(&resp, buffer) != evr_ok){
            goto out;
        }
        log_debug("Storage responded with status code 0x%x", resp.status_code);
        if(resp.status_code == evr_status_code_ok){
            log_debug("blob already exists");
            if(resp.body_size != evr_stat_blob_resp_n_size){
                goto out;
            }
            // TODO update flags in storage if necessary
            if(dump_n(c, evr_stat_blob_resp_n_size) != evr_ok){
                goto out;
            }
            ret = evr_ok;
            goto out;
        }
        if(resp.status_code != evr_status_code_blob_not_found){
            goto out;
        }
        log_debug("Storage indicated blob does not yet exist");
        if(resp.body_size != 0){
            goto out;
        }
    }
    {
        char *p = buffer;
        struct evr_cmd_header cmd;
        cmd.type = evr_cmd_type_put_blob;
        cmd.body_size = evr_blob_ref_size + sizeof(uint8_t) + blob->size_used;
        if(evr_format_cmd_header(p, &cmd) != evr_ok){
            goto out;
        }
        p += evr_cmd_header_n_size;
        memcpy(p, key, evr_blob_ref_size);
        p += evr_blob_ref_size;
        *(uint8_t*)p = flags;
        log_debug("Sending put %s command for %d bytes blob", fmt_key, blob->size_used);
        if(write_n(c, buffer, evr_cmd_header_n_size + evr_blob_ref_size + sizeof(uint8_t)) != evr_ok){
            goto out;
        }
        if(write_chunk_set(c, blob) != evr_ok){
            goto out;
        }
    }
    {
        log_debug("Reading storage response");
        if(read_n(c, buffer, evr_resp_header_n_size) != evr_ok){
            goto out;
        }
        struct evr_resp_header resp;
        if(evr_parse_resp_header(&resp, buffer) != evr_ok){
            goto out;
        }
        log_debug("Storage responded with status code 0x%x", resp.status_code);
        if(resp.status_code != evr_status_code_ok){
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}
