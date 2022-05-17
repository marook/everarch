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
#include "configp.h"
#include "handover.h"

const char *argp_program_version = "evr-glacier-cli " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

#define sort_order_last_modified_key "last-modified"
#define sort_order_blob_ref_key "blob-ref"

static char doc[] =
    "evr-glacier-cli is a command line client for interacting with evr-glacier-storage servers.\n\n"
    "Possible commands are get, put, sign-put, post-file or watch.\n\n"
    "The get command expects the key of the to be fetched blob as second argument. The blob content will be written to stdout\n\n"
    "The get-claim command expects the key of the to be fetched claim as second argument. The claim will be written to stdout\n\n"
    "The put command retrieves a blob via stdin and sends it to the evr-glacier-storage.\n\n"
    "The sign-put command retrieves textual content via stdin, signs it and sends it to the evr-glacier-storage.\n\n"
    "The get-file command expects one file claim key argument. If found the first file in the claim will be written to stdout.\n\n"
    "The post-file command expects one optional file name argument for upload to the evr-glacier-storage. File will be read from stdin if no file name argument is given.\n\n"
    "The watch command prints modified blob keys.\n\n"
    "The sync command synchronizes the blobs of two evr-glacier-storage instances either in one or in both directions. Expects the arguments SRC_HOST SRC_PORT DST_HOST DST_PORT after the sync argument."
    ;

static char args_doc[] = "CMD";

#define arg_storage_host 256
#define arg_storage_port 257
#define arg_blobs_sort_order 258
#define arg_two_way 259

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glalier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"flags", 'f', "F", 0, "Use the given flags when put a blob to evr-glacier-storage."},
    {"flags-filter", 'f', "F", 0, "Only watch blobs which have set at least the given flag bits."},
    {"last-modified-after", 'm', "T", 0, "Start watching blobs after T. T is in unix epoch format in seconds."},
    {"title", 't', "T", 0, "Title of the created claim. Might be used together with post-file."},
    {"seed", 's', "REF", 0, "Makes the created claim reference another claim as seed."},
    {"blobs-sort-order", arg_blobs_sort_order, "ORDER", 0, "Prints watched blobs in this order. Possible values are '" sort_order_last_modified_key "' and '" sort_order_blob_ref_key "'. The sort-order '" sort_order_last_modified_key "' will continue to emit changed blobs as they change live. Other sort orders will end the connection after all relevant blob refs have been emitted. Default is '" sort_order_last_modified_key "'."},
    {"two-way", arg_two_way, NULL, 0, "Synchronizes also from destination server to source server instead of just from source to destination server."},
    {0}
};

#define cli_cmd_none 0
#define cli_cmd_get 1
#define cli_cmd_get_claim 2
#define cli_cmd_put 3
#define cli_cmd_sign_put 4
#define cli_cmd_get_file 5
#define cli_cmd_post_file 6
#define cli_cmd_watch_blobs 7
#define cli_cmd_sync 8

struct cli_cfg {
    int cmd;
    char *storage_host;
    char *storage_port;
    char *key;
    char *file;
    int flags;
    char *title;
    int has_seed;
    evr_claim_ref seed;
    unsigned long long last_modified_after;
    int two_way;

    /**
     * blobs_sort_order must be one of evr_cmd_watch_sort_order_*.
     */
    int blobs_sort_order;

    char *src_storage_host;
    char *src_storage_port;
    char *dst_storage_host;
    char *dst_storage_port;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct cli_cfg *cfg = (struct cli_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'f': {
        size_t arg_len = strlen(arg);
        size_t parsed_len = sscanf(arg, "%d", &cfg->flags);
        if(arg_len == 0 || parsed_len != 1){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    case 'm': {
        size_t arg_len = strlen(arg);
        size_t parsed_len = sscanf(arg, "%llu", &cfg->last_modified_after);
        if(arg_len == 0 || parsed_len != 1){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    case 't':
        evr_replace_str(cfg->title, arg);
        break;
    case 's': {
        if(evr_parse_claim_ref(cfg->seed, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->has_seed = 1;
        break;
    }
    case arg_storage_host:
        evr_replace_str(cfg->storage_host, arg);
        break;
    case arg_storage_port:
        evr_replace_str(cfg->storage_port, arg);
        break;
    case arg_blobs_sort_order:
        if(strcmp(arg, sort_order_last_modified_key) == 0){
            cfg->blobs_sort_order = evr_cmd_watch_sort_order_last_modified;
        } else if(strcmp(arg, sort_order_blob_ref_key) == 0){
            cfg->blobs_sort_order = evr_cmd_watch_sort_order_ref;
        } else {
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case arg_two_way:
        cfg->two_way = 1;
        break;
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            if(strcmp("get", arg) == 0){
                cfg->cmd = cli_cmd_get;
            } else if(strcmp("get-claim", arg) == 0){
                cfg->cmd = cli_cmd_get_claim;
            } else if(strcmp("put", arg) == 0){
                cfg->cmd = cli_cmd_put;
            } else if(strcmp("sign-put", arg) == 0){
                cfg->cmd = cli_cmd_sign_put;
            } else if(strcmp("get-file", arg) == 0){
                cfg->cmd = cli_cmd_get_file;
            } else if(strcmp("post-file", arg) == 0){
                cfg->cmd = cli_cmd_post_file;
            } else if(strcmp("watch", arg) == 0){
                cfg->cmd = cli_cmd_watch_blobs;
            } else if(strcmp("sync", arg) == 0){
                cfg->cmd = cli_cmd_sync;
            } else {
                usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case 1:
            switch(cfg->cmd){
            default:
                usage(state);
                return ARGP_ERR_UNKNOWN;
            case cli_cmd_get:
            case cli_cmd_get_claim:
            case cli_cmd_get_file:
                evr_replace_str(cfg->key, arg);
                break;
            case cli_cmd_post_file:
                evr_replace_str(cfg->file, arg);
                break;
            case cli_cmd_sync:
                evr_replace_str(cfg->src_storage_host, arg);
                break;
            }
            break;
        case 2:
            switch(cfg->cmd){
            default:
                usage(state);
                return ARGP_ERR_UNKNOWN;
            case cli_cmd_sync:
                evr_replace_str(cfg->src_storage_port, arg);
                break;
            }
            break;
        case 3:
            switch(cfg->cmd){
            default:
                usage(state);
                return ARGP_ERR_UNKNOWN;
            case cli_cmd_sync:
                evr_replace_str(cfg->dst_storage_host, arg);
                break;
            }
            break;
        case 4:
            switch(cfg->cmd){
            default:
                usage(state);
                return ARGP_ERR_UNKNOWN;
            case cli_cmd_sync:
                evr_replace_str(cfg->dst_storage_port, arg);
                break;
            }
            break;
        }
        break;
    case ARGP_KEY_END:
        // not enough arguments?
        switch(cfg->cmd){
        default:
            usage (state);
            return ARGP_ERR_UNKNOWN;
        case cli_cmd_get:
        case cli_cmd_get_claim:
        case cli_cmd_get_file:
            if(state->arg_num < 2){
                usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case cli_cmd_sync:
            if(state->arg_num < 5){
                usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case cli_cmd_put:
        case cli_cmd_sign_put:
        case cli_cmd_post_file:
        case cli_cmd_watch_blobs:
            break;
        }
        break;
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

int evr_cli_get(struct cli_cfg *cfg);
int evr_cli_get_claim(struct cli_cfg *cfg);
int evr_cli_put(struct cli_cfg *cfg);
int evr_cli_sign_put(struct cli_cfg *cfg);
int evr_cli_get_file(struct cli_cfg *cfg);
int evr_write_cmd_get_blob(int fd, evr_blob_ref key);
int evr_cli_post_file(struct cli_cfg *cfg);
int evr_cli_watch_blobs(struct cli_cfg *cfg);
int evr_stat_and_put(int c, evr_blob_ref key, int flags, struct chunk_set *blob);
int evr_cli_sync(struct cli_cfg *cfg);

int main(int argc, char **argv){
    int ret = 1;
    evr_log_fd = STDERR_FILENO;
    struct cli_cfg cfg;
    cfg.cmd = cli_cmd_none;
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.key = NULL;
    cfg.file = NULL;
    cfg.flags = 0;
    cfg.title = NULL;
    cfg.has_seed = 0;
    // LLONG_MAX instead of ULLONG_MAX because of limitations in
    // glacier's sqlite.
    cfg.last_modified_after = LLONG_MAX;
    cfg.two_way = 0;
    cfg.blobs_sort_order = evr_cmd_watch_sort_order_last_modified;
    cfg.src_storage_host = NULL;
    cfg.src_storage_port = NULL;
    cfg.dst_storage_host = NULL;
    cfg.dst_storage_port = NULL;
    char *config_paths[] = {
        "evr.conf",
        "~/.config/everarch/evr.conf",
        "/etc/everarch/evr.conf",
        NULL,
    };
    struct configp configp = { options, parse_opt, args_doc, doc };
    if(configp_parse(&configp, config_paths, &cfg) != 0){
        goto out_with_free_cfg;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    switch(cfg.cmd){
    case cli_cmd_get:
        ret = evr_cli_get(&cfg);
        break;
    case cli_cmd_get_claim:
        ret = evr_cli_get_claim(&cfg);
        break;
    case cli_cmd_put:
        ret = evr_cli_put(&cfg);
        break;
    case cli_cmd_sign_put:
        ret = evr_cli_sign_put(&cfg);
        break;
    case cli_cmd_get_file:
        ret = evr_cli_get_file(&cfg);
        break;
    case cli_cmd_post_file:
        ret = evr_cli_post_file(&cfg);
        break;
    case cli_cmd_watch_blobs:
        ret = evr_cli_watch_blobs(&cfg);
        break;
    case cli_cmd_sync:
        ret = evr_cli_sync(&cfg);
    }
    void *tbfree[] = {
        cfg.storage_host,
        cfg.storage_port,
        cfg.key,
        cfg.file,
        cfg.title,
        cfg.src_storage_host,
        cfg.src_storage_port,
        cfg.dst_storage_host,
        cfg.dst_storage_port,
    };
    void **tbfree_end = &tbfree[sizeof(tbfree) / sizeof(void*)];
 out_with_free_cfg:
    for(void **it = tbfree; it != tbfree_end; ++it){
        if(*it){
            free(*it);
        }
    }
    return ret;
}

int evr_cli_get(struct cli_cfg *cfg){
    int result = evr_error;
    evr_blob_ref key;
    if(evr_parse_blob_ref(key, cfg->key) != evr_ok){
        log_error("Invalid key format");
        goto fail;
    }
    int c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto fail;
    }
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(c, key, &resp) != evr_ok){
        goto out_with_close_c;
    }
    if(resp.status_code == evr_status_code_blob_not_found){
        log_error("not found");
        goto out_with_close_c;
    } else if(resp.status_code != evr_status_code_ok){
        goto out_with_close_c;
    }
    // read flags but don't use them
    char buf[1];
    if(read_n(c, buf, sizeof(buf)) != evr_ok){
        goto out_with_close_c;
    }
    int pipe_res = pipe_n(STDOUT_FILENO, c, resp.body_size - 1);
    if(pipe_res != evr_ok && pipe_res != evr_end){
        goto out_with_close_c;
    }
    result = evr_ok;
 out_with_close_c:
    if(close(c)){
        result = evr_error;
    }
 fail:
    return result;
}

int evr_cli_get_claim(struct cli_cfg *cfg){
    int ret = evr_error;
    evr_init_signatures();
    xmlInitParser();
    evr_claim_ref claim_ref;
    if(evr_parse_claim_ref(claim_ref, cfg->key) != evr_ok){
        log_error("Invalid key format");
        goto out;
    }
    int c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out;
    }
    evr_blob_ref blob_ref;
    int claim_index;
    evr_split_claim_ref(blob_ref, &claim_index, claim_ref);
    xmlDocPtr doc = evr_fetch_signed_xml(c, blob_ref);
    if(!doc){
        log_error("No validly signed XML found for ref %s", cfg->key);
        goto out_with_close_c;
    }
    xmlNode *cs = evr_get_root_claim_set(doc);
    if(!cs){
        log_error("No claim set found in blob");
        goto out_with_free_doc;
    }
    xmlNode *cn = evr_nth_claim(cs, claim_index);
    if(!c){
        log_error("There is no claim with index %d in claim-set with ref %s", claim_index, cfg->key);
        goto out_with_free_doc;
    }
    xmlDocPtr out_doc = xmlNewDoc(BAD_CAST "1.0");
    if(!out_doc){
        goto out_with_free_doc;
    }
    if(xmlDOMWrapAdoptNode(NULL, doc, cn, out_doc, NULL, 0)){
        goto out_with_free_out_doc;
    }
    if(xmlDocSetRootElement(out_doc, cn) != 0){
        goto out_with_free_out_doc;
    }
    xmlDOMWrapReconcileNamespaces(NULL, cn, 0);
    char *out_doc_str = NULL;
    int out_doc_str_size;
    xmlDocDumpMemoryEnc(out_doc, (xmlChar**)&out_doc_str, &out_doc_str_size, "UTF-8");
    if(!out_doc_str){
        log_error("Failed to format output doc");
        goto out_with_free_out_doc;
    }
    if(write_n(STDOUT_FILENO, out_doc_str, out_doc_str_size) != evr_ok){
        goto out_with_free_out_doc_str;
    }
    ret = evr_ok;
 out_with_free_out_doc_str:
    xmlFree(out_doc_str);
 out_with_free_out_doc:
    xmlFreeDoc(out_doc);
 out_with_free_doc:
    xmlFreeDoc(doc);
 out_with_close_c:
    if(close(c)){
        ret = evr_error;
    }
 out:
    xmlCleanupParser();
    return ret;
}

int evr_cli_put(struct cli_cfg *cfg){
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
    int c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_blob;
    }
    if(evr_stat_and_put(c, key, cfg->flags, blob) != evr_ok){
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

int evr_cli_sign_put(struct cli_cfg *cfg){
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
    int c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_signed_buf;
    }
    if(evr_stat_and_put(c, key, cfg->flags, &signed_cs) != evr_ok){
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

int evr_cli_get_file(struct cli_cfg *cfg){
    int ret = evr_error;
    evr_init_signatures();
    xmlInitParser();
    evr_claim_ref cref;
    if(evr_parse_claim_ref(cref, cfg->key) != evr_ok){
        goto out;
    }
    int c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
    if(c < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out;
    }
    evr_blob_ref bref;
    int claim;
    evr_split_claim_ref(bref, &claim, cref);
    xmlDocPtr doc = evr_fetch_signed_xml(c, bref);
    if(!doc){
        log_error("No validly signed XML found for ref %s", cfg->key);
        goto out_with_close_c;
    }
    xmlNode *cs = evr_get_root_claim_set(doc);
    if(!cs){
        log_error("No claim set found in blob");
        goto out_with_free_doc;
    }
    xmlNode *fc = evr_nth_claim(cs, claim);
    if(!fc){
        log_error("There is no claim with index %d in claim-set with ref %s", claim, cfg->key);
        goto out_with_free_doc;
    }
    if(!evr_is_evr_element(fc, "file")){
        log_error("The claim with index %d in claim-set with ref %s is not a file claim", claim, cfg->key);
        goto out_with_free_doc;
    }
    xmlNode *fbody = evr_find_next_element(fc->children, "body");
    if(!fbody){
        log_error("No body found in file claim");
        goto out_with_free_doc;
    }
    xmlNode *slice = evr_find_next_element(fbody->children, "slice");
    evr_blob_ref sref;
    struct evr_resp_header resp;
    char buf[1];
    while(1){
        if(!slice){
            break;
        }
        char *fmt_sref = (char*)xmlGetProp(slice, BAD_CAST "ref");
        if(!fmt_sref){
            goto out_with_free_doc;
        }
        int pkret = evr_parse_blob_ref(sref, fmt_sref);
        xmlFree(fmt_sref);
        if(pkret != evr_ok){
            goto out_with_free_doc;
        }
        if(evr_write_cmd_get_blob(c, sref) != evr_ok){
            goto out_with_free_doc;
        }
        if(evr_read_resp_header(c, &resp) != evr_ok){
            goto out_with_free_doc;
        }
        if(resp.status_code != evr_status_code_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, sref);
            log_error("Failed to fetch file slice blob with ref %s. Response status code was 0x%02x.", fmt_key, resp.status_code);
            goto out_with_free_doc;
        }
        // read flags but don't use them
        if(read_n(c, buf, 1) != evr_ok){
            goto out_with_free_doc;
        }
        int pipe_res = pipe_n(STDOUT_FILENO, c, resp.body_size - 1);
        if(pipe_res == evr_end){
            break;
        }
        if(pipe_res != evr_ok){
            goto out_with_free_doc;
        }
        slice = evr_find_next_element(slice->next, "slice");
    }
    ret = evr_ok;
 out_with_free_doc:
    xmlFreeDoc(doc);
 out_with_close_c:
    if(close(c)){
        ret = evr_error;
    }
 out:
    xmlCleanupParser();
    return ret;
}

int evr_cli_post_file(struct cli_cfg *cfg){
    int ret = evr_error;
    evr_init_signatures();
    int f = STDIN_FILENO;
    if(cfg->file){
        f = open(cfg->file, O_RDONLY);
        if(f < 0){
            goto out;
        }
    }
    struct post_file_ctx ctx;
    ctx.c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
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
    fc.has_seed = cfg->has_seed;
    if(cfg->has_seed){
        memcpy(fc.seed, cfg->seed, evr_claim_ref_size);
    }
    fc.title = NULL;
    if(cfg->title){
        fc.title = cfg->title;
    } else if (cfg->file){
        // warning to future me: at the following expression we modify the
        // content of cfg->file
        fc.title = basename(cfg->file);
    }
    fc.slices_len = dynamic_array_len(ctx.slices, sizeof(struct evr_file_slice));
    fc.slices = (struct evr_file_slice*)ctx.slices->data;
    log_debug("Uploaded %d file segments", fc.slices_len);
    evr_time t;
    evr_now(&t);
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
    evr_claim_ref cref;
    evr_build_claim_ref(cref, key, 0);
    evr_claim_ref_str fmt_cref;
    evr_fmt_claim_ref(fmt_cref, cref);
    printf("%s\n", fmt_cref);
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
    if(f != STDIN_FILENO && close(f)){
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

int evr_cli_watch_blobs(struct cli_cfg *cfg){
    int ret = evr_error;
    struct evr_blob_filter f;
    f.sort_order = cfg->blobs_sort_order;
    f.flags_filter = cfg->flags;
    f.last_modified_after = cfg->last_modified_after;
    int c = evr_connect_to_storage(cfg->storage_host, cfg->storage_port);
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
#ifdef EVR_LOG_DEBUG
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
#endif
    struct evr_resp_header resp;
    if(evr_req_cmd_stat_blob(c, key, &resp) != evr_ok){
        goto out;
    }
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
    if(evr_write_cmd_put_blob(c, key, flags, blob->size_used) != evr_ok){
        goto out;
    }
    if(write_chunk_set(c, blob) != evr_ok){
        goto out;
    }
    if(evr_read_resp_header(c, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code != evr_status_code_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

#define sync_dir_src_to_dst 1
#define sync_dir_dst_to_src 2

struct evr_blob_sync_handover {
    struct evr_handover_ctx handover;

    struct cli_cfg *cfg;

    /**
     * sync_dir must be one of sync_dir_*.
     */
    int sync_dir;
    evr_blob_ref ref;
};

#define evr_init_blob_sync_handover(ctx) evr_init_handover_ctx(&(ctx)->handover)
#define evr_free_blob_sync_handover(ctx) evr_free_handover_ctx(&(ctx)->handover)

#define sync_state_want_ref 1
#define sync_state_has_ref 2
#define sync_state_end 3

int blob_sync_worker(void *ctx);

int evr_cli_sync(struct cli_cfg *cfg) {
    int ret = evr_error;
    const size_t sync_thrd_count = 4;
    thrd_t sync_thrds[sync_thrd_count];
    int src_c = evr_connect_to_storage(cfg->src_storage_host, cfg->src_storage_port);
    if(src_c < 0){
        log_error("Failed to connect to source evr-glacier-storage server");
        goto out;
    }
    int dst_c = evr_connect_to_storage(cfg->dst_storage_host, cfg->dst_storage_port);
    if(dst_c < 0){
        log_error("Failed to connect to destination evr-glacier-storage-server");
        goto out_with_close_src_c;
    }
    struct evr_blob_filter f;
    f.sort_order = evr_cmd_watch_sort_order_ref;
    f.flags_filter = cfg->flags;
    f.last_modified_after = 0;
    if(evr_req_cmd_watch_blobs(src_c, &f) != evr_ok){
        goto out_with_close_dst_c;
    }
    if(evr_req_cmd_watch_blobs(dst_c, &f) != evr_ok){
        goto out_with_close_dst_c;
    }
    struct evr_blob_sync_handover sync_ho;
    if(evr_init_blob_sync_handover(&sync_ho) != evr_ok){
        goto out_with_close_dst_c;
    }
    sync_ho.cfg = cfg;
    thrd_t *sync_thrds_end = &sync_thrds[sync_thrd_count];
    thrd_t *st = sync_thrds;
    for(; st != sync_thrds_end; ++st){
        if(thrd_create(st, blob_sync_worker, &sync_ho) != thrd_success){
            goto out_with_join_sync_thrds;
        }
    }
    int src_state = sync_state_want_ref;
    struct evr_watch_blobs_body src_next_blob;
    int dst_state = sync_state_want_ref;
    struct evr_watch_blobs_body dst_next_blob;
    fd_set fds;
    size_t blob_count = 0;
    while(1){
        FD_ZERO(&fds);
        if(src_state == sync_state_want_ref){
            FD_SET(src_c, &fds);
        }
        if(dst_state == sync_state_want_ref){
            FD_SET(dst_c, &fds);
        }
        int sel_ret = select(max(src_c, dst_c) + 1, &fds, NULL, NULL, NULL);
        if(sel_ret < 0){
            goto out_with_close_dst_c;
        }
        for(int i = 0; i < FD_SETSIZE; ++i){
            if(FD_ISSET(i, &fds)){
                struct evr_watch_blobs_body *body;
                int *state;
                if(i == src_c){
                    body = &src_next_blob;
                    state = &src_state;
                } else if(i == dst_c) {
                    body = &dst_next_blob;
                    state = &dst_state;
                } else {
                    evr_panic("Unknown file descriptor is set: %d", i);
                    goto out_with_close_dst_c;
                }
                int read_res = evr_read_watch_blobs_body(i, body);
                if(read_res == evr_ok){
                    *state = sync_state_has_ref;
                } else if(read_res == evr_end){
                    *state = sync_state_end;
                } else {
                    goto out_with_close_dst_c;
                }
            }
        }
        if(src_state == sync_state_want_ref || dst_state == sync_state_want_ref){
            continue;
        }
        if(src_state == sync_state_end && dst_state == sync_state_end){
            break;
        }
        int ref_cmp;
        if(src_state == sync_state_end){
            ref_cmp = 1;
        } else if(dst_state == sync_state_end){
            ref_cmp = -1;
        } else {
            ref_cmp = memcmp(src_next_blob.key, dst_next_blob.key, evr_blob_ref_size);
        }
        ++blob_count;
        if(ref_cmp == 0){
            src_state = sync_state_want_ref;
            dst_state = sync_state_want_ref;
        } else if(ref_cmp < 0){
#ifdef EVR_LOG_DEBUG
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, src_next_blob.key);
            log_debug("Sync %s from src to dst", ref_str);
#endif
            if(evr_wait_for_handover_available(&sync_ho.handover) != evr_ok){
                goto out_with_join_sync_thrds;
            }
            sync_ho.sync_dir = sync_dir_src_to_dst;
            memcpy(sync_ho.ref, src_next_blob.key, evr_blob_ref_size);
            if(evr_occupy_handover(&sync_ho.handover) != evr_ok){
                goto out_with_join_sync_thrds;
            }
            src_state = sync_state_want_ref;
        } else { // if(ref_cmp > 0)
            if(cfg->two_way){
#ifdef EVR_LOG_DEBUG
                evr_blob_ref_str ref_str;
                evr_fmt_blob_ref(ref_str, dst_next_blob.key);
                log_debug("Sync %s from dst to src", ref_str);
#endif
                if(evr_wait_for_handover_available(&sync_ho.handover) != evr_ok){
                    goto out_with_join_sync_thrds;
                }
                sync_ho.sync_dir = sync_dir_dst_to_src;
                memcpy(sync_ho.ref, dst_next_blob.key, evr_blob_ref_size);
                if(evr_occupy_handover(&sync_ho.handover) != evr_ok){
                    goto out_with_join_sync_thrds;
                }
            }
            dst_state = sync_state_want_ref;
        }
    }
    log_info("Visited %lu blobs in two storages", blob_count);
    ret = evr_ok;
 out_with_join_sync_thrds:
    log_debug("Sync blob ref compare done. Waiting for sync threads.");
    if(evr_finish_handover(&sync_ho.handover, sync_thrd_count) != evr_ok){
        ret = evr_error;
    }
    int thrd_res;
    for(--st; st >= sync_thrds; --st){
        if(thrd_join(*st, &thrd_res) != thrd_success){
            evr_panic("Failed to join sync thread");
            ret = evr_error;
        }
        if(thrd_res != evr_ok){
            ret = evr_error;
        }
    }
    if(evr_free_blob_sync_handover(&sync_ho) != evr_ok){
        ret = evr_error;
    }
 out_with_close_dst_c:
    if(close(dst_c) != 0){
        evr_panic("Unable to close connection to destination server");
        ret = evr_error;
    }
 out_with_close_src_c:
    if(close(src_c) != 0){
        evr_panic("Unable to close connection to source server");
        ret = evr_error;
    }
 out:
    return ret;
}

int blob_sync_worker(void *context){
    int ret = evr_error;
    struct evr_blob_sync_handover *ctx = context;
    int c_src = -1;
    int c_dst = -1;
    int sync_dir;
    evr_blob_ref ref;
    struct evr_resp_header get_resp;
    struct evr_resp_header put_resp;
    while(1){
        int wait_res = evr_wait_for_handover_occupied(&ctx->handover);
        if(wait_res == evr_end){
            break;
        } else if(wait_res != evr_ok){
            goto out;
        }
        sync_dir = ctx->sync_dir;
        memcpy(ref, ctx->ref, evr_blob_ref_size);
        if(evr_empty_handover(&ctx->handover) != evr_ok){
            goto out;
        }
        const int max_tries = 3;
        int tries = 0;
        for(; tries < max_tries; ++tries){
            if(tries > 0){
#ifdef EVR_LOG_DEBUG
                evr_blob_ref_str ref_str;
                evr_fmt_blob_ref(ref_str, ref);
                log_debug("Retry sync %s for the %d try", ref_str, tries);
#endif
            }
            if(c_src == -1){
                c_src = evr_connect_to_storage(ctx->cfg->src_storage_host, ctx->cfg->src_storage_port);
                if(c_src < 0){
                    log_error("Failed to connect to source evr-glacier-storage server");
                    goto continue_with_retry;
                }
            }
            if(c_dst == -1){
                c_dst = evr_connect_to_storage(ctx->cfg->dst_storage_host, ctx->cfg->dst_storage_port);
                if(c_dst < 0){
                    log_error("Failed to connect to destination evr-glacier-storage server");
                    goto continue_with_retry;
                }
            }
            int cg;
            int cp;
            switch(sync_dir){
            default:
                evr_panic("Unknown sync_dir %d", sync_dir);
                goto out_with_close_c;
            case sync_dir_src_to_dst:
                cg = c_src;
                cp = c_dst;
                break;
            case sync_dir_dst_to_src:
                cg = c_dst;
                cp = c_src;
                break;
            }
            if(evr_req_cmd_get_blob(cg, ref, &get_resp) != evr_ok){
                goto continue_with_retry;
            }
            char buf[sizeof(uint8_t)];
            if(read_n(cg, buf, sizeof(buf)) != evr_ok){
                goto continue_with_retry;
            }
            struct evr_buf_pos bp;
            evr_init_buf_pos(&bp, buf);
            int flags;
            evr_pull_as(&bp, &flags, uint8_t);
            if(get_resp.status_code != evr_status_code_ok){
                goto continue_with_retry;
            }
            const size_t blob_size = get_resp.body_size - sizeof(uint8_t);
            if(evr_write_cmd_put_blob(cp, ref, flags, blob_size) != evr_ok){
                goto continue_with_retry;
            }
            if(pipe_n(cp, cg, blob_size) != evr_ok){
                goto continue_with_retry;
            }
            if(evr_read_resp_header(cp, &put_resp) != evr_ok){
                goto continue_with_retry;
            }
            if(put_resp.status_code != evr_status_code_ok){
                goto continue_with_retry;
            }
            break;
        continue_with_retry:
            if(c_dst >= 0){
                if(close(c_dst) != 0){
                    c_dst = -1;
                    goto out_with_close_c;
                }
                c_dst = -1;
            }
            if(c_src >= 0){
                if(close(c_src) != 0){
                    c_src = -1;
                    goto out_with_close_c;
                }
                c_src = -1;
            }
        }
        if(tries >= max_tries){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, ref);
            log_error("Giving up synchronizing %s after %d failed tries.", ref_str, tries);
            goto out_with_close_c;
        }
    }
    ret = evr_ok;
 out_with_close_c:
    if(c_dst >= 0){
        if(close(c_dst) != 0){
            ret = evr_error;
        }
    }
    if(c_src >= 0){
        if(close(c_src) != 0){
            ret = evr_error;
        }
    }
 out:
    log_debug("blob_sync_worker ending with status %d", ret);
    return ret;
}
