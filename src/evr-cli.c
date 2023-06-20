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
#include "evr-tls.h"
#include "auth.h"
#include "seed-desc.h"
#include "evr-attr-index-client.h"

#define program_name "evr"

const char *argp_program_version = program_name " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

#define sort_order_last_modified_key "last-modified"
#define sort_order_blob_ref_key "blob-ref"

static char doc[] =
    program_name " is a command line client for interacting with evr-glacier-storage and evr-attr-index servers.\n\n"
    "The concrete operation is specified by a set of possible commands listed in brief below.\n\n"
    // commands start here
    "The get command expects the key of the to be fetched blob as second argument. The blob content will be written to stdout.\n\n"
    "The get-verify command expects the key of the to be fetched claim-set blob as second argument. The claim-set XML will be written to stdout.\n\n"
    "The get-claim command expects the key of the to be fetched claim as second argument. The claim will be written to stdout.\n\n"
    "The put command retrieves a blob via stdin and sends it to the evr-glacier-storage.\n\n"
    "The sign-put command retrieves textual content via stdin, signs it and sends it to the evr-glacier-storage.\n\n"
    "The get-file command expects one file claim key argument. If found the first file in the claim will be written to stdout.\n\n"
    "The post-file command expects one optional file name argument for upload to the evr-glacier-storage. File will be read from stdin if no file name argument is given.\n\n"
    "The search command executes the given query on the default evr-attr-index server. The results are written to stdout.\n\n"
    "The desc-seed command provides a seed description for the given seed. Expects the seed ref as argument.\n\n"
    "The watch command prints modified blob keys.\n\n"
    "The sync command synchronizes the blobs of two evr-glacier-storage instances either in one or in both directions. Expects the arguments SRC_HOST:SRC_PORT DST_HOST:DST_PORT after the sync argument.\n\n"
    // exit code starts here
    "The program's exit code indicates success or failure. The exit code 0 represents a successful execution. The exit code 1 indicates a general no further specificed error. The exit code 2 indicates that the requested data was not found. The exit code 5 indicates that the operation failed because it stumbled over syntactically invalid data once provided by the user."
    ;

static char args_doc[] = "CMD";

#define arg_storage_host 256
#define arg_storage_port 257
#define arg_ssl_cert 258
#define arg_blobs_sort_order 259
#define arg_two_way 260
#define arg_auth_token 261
#define arg_accepted_gpg_key 262
#define arg_signing_gpg_key 263
#define arg_index_host 264
#define arg_index_port 265
#define arg_metadata_file 266

#define max_traces_len 64

#define default_limit 100

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glacier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"index-host", arg_index_host, "HOST", 0, "The hostname of the evr-attr-index server to connect to. Default hostname is " evr_attr_index_host "."},
    {"index-port", arg_index_port, "PORT", 0, "The port of the evr-attr-index server to connect to. Default port is " to_string(evr_attr_index_port) "."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of the server. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"auth-token", arg_auth_token, "HOST:PORT:TOKEN", 0, "A hostname, port and authorization token which is presented to the server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {"flags", 'f', "F", 0, "Use the given flags when put a blob to evr-glacier-storage."},
    {"flags-filter", 'f', "F", 0, "Only watch blobs which have set at least the given flag bits."},
    {"last-modified-after", 'm', "T", 0, "Start watching blobs after T. T is in unix epoch format in seconds."},
    {"title", 't', "T", 0, "Title of the created claim. Might be used together with post-file."},
    {"seed", 's', "REF", 0, "Makes the created claim reference another claim as seed."},
    {"trace", 'T', "T", 0, "Trace of the produced seed-description set. May be specified multiple times for multiple traces. No more than " to_string(max_traces_len) " traces are allowed right now."},
    {"blobs-sort-order", arg_blobs_sort_order, "ORDER", 0, "Prints watched blobs in this order. Possible values are '" sort_order_last_modified_key "' and '" sort_order_blob_ref_key "'. The sort-order '" sort_order_last_modified_key "' will continue to emit changed blobs as they change live. Other sort orders will end the connection after all relevant blob refs have been emitted. Default is '" sort_order_last_modified_key "'."},
    {"two-way", arg_two_way, NULL, 0, "Synchronizes also from destination server to source server instead of just from source to destination server."},
    {"accepted-gpg-key", arg_accepted_gpg_key, "FINGERPRINT", 0, "A GPG key fingerprint of claim signatures which will be accepted as valid. Can be specified multiple times to accept multiple keys. You can call 'gpg --list-public-keys' to see your known keys."},
    {"signing-gpg-key", arg_signing_gpg_key, "FINGERPRINT", 0, "Fingerprint of the GPG key which is used for signing claims. You can call 'gpg --list-secret-keys' to see your known keys."},
    {"limit", 'l', "LIMIT", 0, "Sets an upper limit for the maximum number results for evr-attr-index search queries. A value of 0 will not limit the number of results. Default is " to_string(default_limit) "."},
    {"meta", arg_metadata_file, "FILE", 0, "Appends metadata obtained via processing the get command into the given file. Some data might be written to the file even if the evr process fails."},
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
#define cli_cmd_get_verify 9
#define cli_cmd_desc_seed 10
#define cli_cmd_search 11

struct cli_cfg {
    int cmd;
    char *storage_host;
    char *storage_port;
    char *index_host;
    char *index_port;
    struct evr_auth_token_cfg *auth_tokens;
    struct evr_cert_cfg *ssl_certs;
    char *key;
    char *file;
    int flags;
    char *title;
    int has_seed;
    evr_claim_ref seed;
    size_t traces_len;
    char *traces[max_traces_len];
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

    /**
     * accepted_gpg_fprs contains the accepted gpg fingerprints for
     * signed claims.
     *
     * The llbuf data points to a fingerprint string.
     *
     * This field is only filled during the initialization of the
     * application. During runtime verify_ctx should be used.
     */
    struct evr_llbuf *accepted_gpg_fprs;

    struct evr_verify_ctx *verify_ctx;

    char *signing_gpg_fpr;

    char *query;
    size_t limit;

    char *meta_path;
    struct evr_file *meta;
};

int evr_replace_host_port(char **host, char **port, char *host_port_expr);

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
    case 'T':
        if(cfg->traces_len == static_len(cfg->traces)){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->traces[cfg->traces_len] = strdup(arg);
        if(!cfg->traces[cfg->traces_len]){
            return ARGP_ERR_UNKNOWN;
        }
        cfg->traces_len += 1;
        break;
    case 'l': {
        size_t arg_len = strlen(arg);
        size_t parsed_len = sscanf(arg, "%zu", &cfg->limit);
        if(arg_len == 0 || parsed_len != 1){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    case arg_storage_host:
        evr_replace_str(cfg->storage_host, arg);
        break;
    case arg_storage_port:
        evr_replace_str(cfg->storage_port, arg);
        break;
    case arg_index_host:
        evr_replace_str(cfg->index_host, arg);
        break;
    case arg_index_port:
        evr_replace_str(cfg->index_port, arg);
        break;
    case arg_auth_token:
        if(evr_parse_and_push_auth_token(&cfg->auth_tokens, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case arg_ssl_cert:
        if(evr_parse_and_push_cert(&cfg->ssl_certs, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
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
    case arg_accepted_gpg_key: {
        const size_t arg_size = strlen(arg) + 1;
        struct evr_buf_pos bp;
        if(evr_llbuf_prepend(&cfg->accepted_gpg_fprs, &bp, arg_size) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        evr_push_n(&bp, arg, arg_size);
        break;
    }
    case arg_signing_gpg_key:
        evr_replace_str(cfg->signing_gpg_fpr, arg);
        break;
    case arg_metadata_file:
        evr_replace_str(cfg->meta_path, arg);
        break;
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            if(strcmp("get", arg) == 0){
                cfg->cmd = cli_cmd_get;
            } else if(strcmp("get-verify", arg) == 0){
                cfg->cmd = cli_cmd_get_verify;
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
            } else if(strcmp("search", arg) == 0){
                cfg->cmd = cli_cmd_search;
            } else if(strcmp("desc-seed", arg) == 0){
                cfg->cmd = cli_cmd_desc_seed;
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
            case cli_cmd_get_verify:
            case cli_cmd_get_claim:
            case cli_cmd_get_file:
                evr_replace_str(cfg->key, arg);
                break;
            case cli_cmd_post_file:
                evr_replace_str(cfg->file, arg);
                break;
            case cli_cmd_search:
                evr_replace_str(cfg->query, arg);
                break;
            case cli_cmd_desc_seed:
                if(evr_parse_claim_ref(cfg->seed, arg) != evr_ok){
                    usage(state);
                    return ARGP_ERR_UNKNOWN;
                }
                cfg->has_seed = 1;
                break;
            case cli_cmd_sync:
                if(evr_replace_host_port(&cfg->src_storage_host, &cfg->src_storage_port, arg) != evr_ok){
                    usage(state);
                    return ARGP_ERR_UNKNOWN;
                }
                break;
            }
            break;
        case 2:
            switch(cfg->cmd){
            default:
                usage(state);
                return ARGP_ERR_UNKNOWN;
            case cli_cmd_sync:
                if(evr_replace_host_port(&cfg->dst_storage_host, &cfg->dst_storage_port, arg) != evr_ok){
                    usage(state);
                    return ARGP_ERR_UNKNOWN;
                }
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
        case cli_cmd_get_verify:
        case cli_cmd_get_claim:
        case cli_cmd_get_file:
        case cli_cmd_search:
        case cli_cmd_desc_seed:
            if(state->arg_num < 2){
                usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case cli_cmd_sync:
            if(state->arg_num < 3){
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

int evr_replace_host_port(char **host, char **port, char *host_port_expr){
    const size_t fragments_len = 2;
    char *fragments[fragments_len];
    if(evr_split_n(fragments, fragments_len, host_port_expr, ':') != evr_ok){
        log_error("Expected colon separated host and port expression but got: %s", host_port_expr);
        return evr_error;
    }
    if(*host){
        free(*host);
    }
    *host = strdup(fragments[0]);
    if(!*host){
        return evr_error;
    }
    if(*port){
        free(*port);
    }
    *port = strdup(fragments[1]);
    if(!*port){
        return evr_error;
    }
    return evr_ok;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

int evr_cli_get(struct cli_cfg *cfg);
int evr_cli_get_verify(struct cli_cfg *cfg);
int evr_cli_get_claim(struct cli_cfg *cfg);
int evr_cli_put(struct cli_cfg *cfg);
int evr_cli_sign_put(struct cli_cfg *cfg);
int evr_cli_get_file(struct cli_cfg *cfg);
int evr_write_cmd_get_blob(struct evr_file *f, evr_blob_ref key);
int evr_cli_post_file(struct cli_cfg *cfg);
int evr_cli_search(struct cli_cfg *cfg);
int evr_cli_desc_seed(struct cli_cfg *cfg);
int evr_cli_watch_blobs(struct cli_cfg *cfg);
int evr_cli_sync(struct cli_cfg *cfg);

int main(int argc, char **argv){
    int ret = 1;
    evr_log_fd = STDERR_FILENO;
    evr_log_app = "e";
    evr_init_basics();
    evr_tls_init();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    evr_init_xml_error_logging();
    struct cli_cfg cfg;
    cfg.cmd = cli_cmd_none;
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.index_host = strdup(evr_attr_index_host);
    cfg.index_port = strdup(to_string(evr_attr_index_port));
    cfg.auth_tokens = NULL;
    cfg.ssl_certs = NULL;
    cfg.key = NULL;
    cfg.file = NULL;
    cfg.flags = 0;
    cfg.title = NULL;
    cfg.has_seed = 0;
    // LLONG_MAX instead of ULLONG_MAX because of limitations in
    // glacier's sqlite.
    cfg.traces_len = 0;
    cfg.last_modified_after = LLONG_MAX;
    cfg.two_way = 0;
    cfg.blobs_sort_order = evr_cmd_watch_sort_order_last_modified;
    cfg.src_storage_host = NULL;
    cfg.src_storage_port = NULL;
    cfg.dst_storage_host = NULL;
    cfg.dst_storage_port = NULL;
    cfg.accepted_gpg_fprs = NULL;
    cfg.verify_ctx = NULL;
    cfg.signing_gpg_fpr = NULL;
    cfg.query = NULL;
    cfg.limit = default_limit;
    cfg.meta_path = NULL;
    cfg.meta = NULL;
    if(evr_push_cert(&cfg.ssl_certs, evr_glacier_storage_host, to_string(evr_glacier_storage_port), default_storage_ssl_cert_path) != evr_ok){
        goto out_with_free_cfg;
    }
    if(evr_push_cert(&cfg.ssl_certs, evr_attr_index_host, to_string(evr_attr_index_port), default_index_ssl_cert_path) != evr_ok){
        goto out_with_free_cfg;
    }
    char *config_paths[] = evr_program_config_paths();
    struct configp configp = { options, parse_opt, args_doc, doc };
    if(configp_parse(&configp, config_paths, &cfg) != 0){
        goto out_with_free_cfg;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    cfg.verify_ctx = evr_build_verify_ctx(cfg.accepted_gpg_fprs);
    if(!cfg.verify_ctx){
        goto out_with_free_cfg;
    }
    struct evr_file meta;
    if(cfg.meta_path){
        if(evr_meta_open(&meta, cfg.meta_path) != evr_ok){
            goto out_with_free_cfg;
        }
        cfg.meta = &meta;
    }
    evr_free_llbuf_chain(cfg.accepted_gpg_fprs, NULL);
    cfg.accepted_gpg_fprs = NULL;
    switch(cfg.cmd){
    case cli_cmd_get:
        ret = evr_cli_get(&cfg);
        break;
    case cli_cmd_get_verify:
        ret = evr_cli_get_verify(&cfg);
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
    case cli_cmd_search:
        ret = evr_cli_search(&cfg);
        break;
    case cli_cmd_desc_seed:
        ret = evr_cli_desc_seed(&cfg);
        break;
    case cli_cmd_watch_blobs:
        ret = evr_cli_watch_blobs(&cfg);
        break;
    case cli_cmd_sync:
        ret = evr_cli_sync(&cfg);
        break;
    }
    void *tbfree[] = {
        cfg.storage_host,
        cfg.storage_port,
        cfg.index_host,
        cfg.index_port,
        cfg.key,
        cfg.file,
        cfg.title,
        cfg.src_storage_host,
        cfg.src_storage_port,
        cfg.dst_storage_host,
        cfg.dst_storage_port,
        cfg.signing_gpg_fpr,
        cfg.query,
        cfg.meta_path,
    };
    void **tbfree_end = &tbfree[static_len(tbfree)];
 out_with_free_cfg:
    for(void **it = tbfree; it != tbfree_end; ++it){
        if(*it){
            free(*it);
        }
    }
    for(size_t i = 0; i < cfg.traces_len; ++i){
        free(cfg.traces[i]);
    }
    if(cfg.meta){
        cfg.meta->close(cfg.meta);
    }
    evr_free_auth_token_chain(cfg.auth_tokens);
    evr_free_cert_chain(cfg.ssl_certs);
    evr_free_llbuf_chain(cfg.accepted_gpg_fprs, NULL);
    if(cfg.verify_ctx){
        evr_free_verify_ctx(cfg.verify_ctx);
    }
    evr_tls_free();
    return ret;
}

int evr_connect_to_storage(struct evr_file *f, struct cli_cfg *cfg, char *host, char *port);
int evr_connect_to_index(struct evr_file *c, struct evr_buf_read **r, struct cli_cfg *cfg, char *host, char *port);

int evr_cli_get(struct cli_cfg *cfg){
    int result = evr_error;
    evr_blob_ref key;
    if(evr_parse_blob_ref(key, cfg->key) != evr_ok){
        log_error("Invalid key format");
        goto fail;
    }
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto fail;
    }
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(&c, key, &resp) != evr_ok){
        goto out_with_close_c;
    }
    if(resp.status_code == evr_status_code_blob_not_found){
        log_error("not found");
        goto out_with_close_c;
    } else if(resp.status_code != evr_status_code_ok){
        goto out_with_close_c;
    }
    struct evr_file stdout;
    evr_file_bind_fd(&stdout, STDOUT_FILENO);
    int pipe_res = evr_pipe_cmd_get_resp_blob(&stdout, &c, resp.body_size, key);
    if(pipe_res != evr_ok && pipe_res != evr_end){
        goto out_with_close_c;
    }
    result = evr_ok;
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection");
        result = evr_error;
    }
 fail:
    return result;
}

int evr_cli_get_verify(struct cli_cfg *cfg){
    int ret = evr_error;
    evr_init_signatures();
    xmlInitParser();
    evr_blob_ref blob_ref;
    if(evr_parse_blob_ref(blob_ref, cfg->key) != evr_ok){
        log_error("Invalid key format");
        goto out;
    }
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto out;
    }
    xmlDocPtr doc = NULL;
    int fetch_res = evr_fetch_signed_xml(&doc, cfg->verify_ctx, &c, blob_ref, cfg->meta);
    if(fetch_res != evr_ok){
        log_error("No validly signed XML found for ref %s", cfg->key);
        ret = fetch_res;
        goto out_with_close_c;
    }
    char *doc_str = NULL;
    int doc_str_size;
    xmlDocDumpMemoryEnc(doc, (xmlChar**)&doc_str, &doc_str_size, "UTF-8");
    if(!doc_str){
        log_error("Failed to format output doc");
        goto out_with_free_doc;
    }
    struct evr_file stdout;
    evr_file_bind_fd(&stdout, STDOUT_FILENO);
    if(write_n(&stdout, doc_str, doc_str_size) != evr_ok){
        goto out_with_free_doc_str;
    }
    ret = evr_ok;
 out_with_free_doc_str:
    xmlFree(doc_str);
 out_with_free_doc:
    xmlFreeDoc(doc);
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection");
        ret = evr_error;
    }
 out:
    xmlCleanupParser();
    return ret;
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
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto out;
    }
    evr_blob_ref blob_ref;
    int claim_index;
    evr_split_claim_ref(blob_ref, &claim_index, claim_ref);
    xmlDocPtr doc = NULL;
    if(evr_fetch_signed_xml(&doc, cfg->verify_ctx, &c, blob_ref, cfg->meta) != evr_ok){
        log_error("No validly signed XML found for ref %s", cfg->key);
        goto out_with_close_c;
    }
    xmlNode *cs = evr_get_root_claim_set(doc);
    if(!cs){
        log_error("No claim set found in blob");
        goto out_with_free_doc;
    }
    xmlNode *cn = evr_nth_claim(cs, claim_index);
    if(!cn){
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
    struct evr_file stdout;
    evr_file_bind_fd(&stdout, STDOUT_FILENO);
    if(write_n(&stdout, out_doc_str, out_doc_str_size) != evr_ok){
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
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection");
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
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto out_with_free_blob;
    }
    int put_res = evr_stat_and_put(&c, key, cfg->flags, blob);
    if(put_res != evr_ok && put_res != evr_exists){
        goto out_with_close_c;
    }
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
    printf("%s\n", fmt_key);
    ret = evr_ok;
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection");
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
    if(evr_sign(cfg->signing_gpg_fpr, &signed_buf, raw_buf->data) != evr_ok){
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
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto out_with_free_signed_buf;
    }
    int put_res = evr_stat_and_put(&c, key, cfg->flags, &signed_cs);
    if(put_res != evr_ok && put_res != evr_exists){
        goto out_with_close_c;
    }
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
    printf("%s\n", fmt_key);
    ret = evr_ok;
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection");
        ret = evr_error;
    }
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
    struct evr_file c;
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
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto out;
    }
    evr_blob_ref bref;
    int claim;
    evr_split_claim_ref(bref, &claim, cref);
    xmlDocPtr doc = NULL;
    if(evr_fetch_signed_xml(&doc, cfg->verify_ctx, &c, bref, cfg->meta) != evr_ok){
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
    if(!evr_is_evr_element(fc, "file", evr_claims_ns)){
        log_error("The claim with index %d in claim-set with ref %s is not a file claim", claim, cfg->key);
        goto out_with_free_doc;
    }
    xmlNode *fbody = evr_find_next_element(fc->children, "body", evr_claims_ns);
    if(!fbody){
        log_error("No body found in file claim");
        goto out_with_free_doc;
    }
    xmlNode *slice = evr_find_next_element(fbody->children, "slice", evr_claims_ns);
    evr_blob_ref sref;
    struct evr_resp_header resp;
    struct evr_file stdout;
    evr_file_bind_fd(&stdout, STDOUT_FILENO);
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
        if(evr_write_cmd_get_blob(&c, sref) != evr_ok){
            goto out_with_free_doc;
        }
        if(evr_read_resp_header(&c, &resp) != evr_ok){
            goto out_with_free_doc;
        }
        if(resp.status_code != evr_status_code_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, sref);
            log_error("Failed to fetch file slice blob with ref %s. Response status code was 0x%02x.", fmt_key, resp.status_code);
            goto out_with_free_doc;
        }
        int pipe_res = evr_pipe_cmd_get_resp_blob(&stdout, &c, resp.body_size, sref);
        if(pipe_res == evr_end){
            break;
        }
        if(pipe_res != evr_ok){
            goto out_with_free_doc;
        }
        slice = evr_find_next_element(slice->next, "slice", evr_claims_ns);
    }
    ret = evr_ok;
 out_with_free_doc:
    xmlFreeDoc(doc);
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close connection");
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
    if(evr_connect_to_storage(&ctx.c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
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
    if(evr_sign(cfg->signing_gpg_fpr, &sc, (char*)cs.out->content) != evr_ok){
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
    int put_res = evr_stat_and_put(&ctx.c, key, evr_blob_flag_claim, &sc_blob);
    if(put_res != evr_ok && put_res != evr_exists){
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
    if(ctx.c.close(&ctx.c) != 0){
        evr_panic("Unable to close storage connection");
        ret = evr_error;
    }
 out_with_close_f:
    if(f != STDIN_FILENO && close(f)){
        ret = evr_error;
    }
 out:
    return ret;
}

struct evr_cli_search_ctx {
    size_t seeds_visited;
    struct cli_cfg *cfg;
};

int evr_cli_search_visit_seed(void *ctx, evr_claim_ref seed);
int evr_cli_search_visit_attr(void *ctx, evr_claim_ref seed, char *key, char *val);

int evr_cli_search(struct cli_cfg *cfg){
    int ret = evr_error;
    if(evr_attri_validate_argument(cfg->query) != evr_ok){
        log_error("The search query is invalid.");
        goto out;
    }
    struct evr_file c;
    struct evr_buf_read *r = NULL;
    if(evr_connect_to_index(&c, &r, cfg, cfg->index_host, cfg->index_port) != evr_ok){
        goto out;
    }
    struct evr_cli_search_ctx ctx;
    ctx.seeds_visited = 0;
    ctx.cfg = cfg;
    if(evr_attri_search(r, cfg->query, evr_cli_search_visit_seed, evr_cli_search_visit_attr, &ctx) != evr_ok){
        goto out_with_free_r;
    }
    ret = evr_ok;
 out_with_free_r:
    if(r){
        evr_free_buf_read(r);
        if(c.close(&c) != 0){
            evr_panic("Unable to close evr-attr-index connection");
            ret = evr_error;
        }
    }
 out:
    return ret;
}

int evr_cli_search_visit_seed(void *_ctx, evr_claim_ref seed){
    struct evr_cli_search_ctx *ctx = _ctx;
    ctx->seeds_visited += 1;
    if(ctx->cfg->limit != 0 && ctx->seeds_visited > ctx->cfg->limit) {
        return evr_end;
    }
    char buf[evr_claim_ref_str_len + 1];
    evr_fmt_claim_ref(buf, seed);
    buf[evr_claim_ref_str_len] = '\n';
    struct evr_file f;
    evr_file_bind_fd(&f, STDOUT_FILENO);
    return write_n(&f, buf, sizeof(buf));
}

int evr_cli_search_visit_attr(void *_ctx, evr_claim_ref seed, char *key, char *val){
    struct evr_cli_search_ctx *ctx = _ctx;
    if(ctx->cfg->limit != 0 && ctx->seeds_visited > ctx->cfg->limit) {
        return evr_ok;
    }
    size_t key_len = strlen(key);
    size_t val_len = strlen(val);
    char buf[1 + key_len + 1 + val_len + 1];
    buf[0] = '\t';
    memcpy(&buf[1], key, key_len);
    buf[1 + key_len] = '=';
    memcpy(&buf[1 + key_len + 1], val, val_len);
    buf[1 + key_len + 1 + val_len] = '\n';
    struct evr_file f;
    evr_file_bind_fd(&f, STDOUT_FILENO);
    return write_n(&f, buf, sizeof(buf));
}

int evr_cli_desc_seed(struct cli_cfg *cfg){
    int ret = evr_error;
    struct evr_file c;
    struct evr_buf_read *r = NULL;
    if(evr_connect_to_index(&c, &r, cfg, cfg->index_host, cfg->index_port) != evr_ok){
        goto out;
    }
    xmlDoc *doc;
    if(evr_seed_desc_build(&doc, r, cfg->seed, cfg->traces_len, cfg->traces) != evr_ok){
        goto out_with_free_r;
    }
    char *seed_desc_str = NULL;
    int seed_desc_size;
    xmlDocDumpMemoryEnc(doc, (xmlChar**)&seed_desc_str, &seed_desc_size, "UTF-8");
    if(!seed_desc_str){
        goto out_with_free_doc;
    }
    printf("%s", seed_desc_str);
    ret = evr_ok;
 out_with_free_doc:
    xmlFreeDoc(doc);
 out_with_free_r:
    if(r){
        evr_free_buf_read(r);
        if(c.close(&c) != 0){
            evr_panic("Unable to close evr-attr-index connection");
            ret = evr_error;
        }
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
    int put_res = evr_stat_and_put(&ctx->c, fs->ref, 0, &blob);
    if(put_res != evr_ok && put_res != evr_exists){
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
    struct evr_file c;
    if(evr_connect_to_storage(&c, cfg, cfg->storage_host, cfg->storage_port) != evr_ok){
        goto out;
    }
    if(evr_req_cmd_watch_blobs(&c, &f) != evr_ok){
        goto out_with_close_c;
    }
    struct evr_watch_blobs_body body;
    evr_blob_ref_str fmt_key;
    while(1){
        if(evr_read_watch_blobs_body(&c, &body) != evr_ok){
            // TODO differientiate between closed connection and other
            // errors. right now evr-cli program ends with errorno !=
            // 0 even if the server perfectly closed the connection.
            goto out_with_close_c;
        }
        evr_fmt_blob_ref(fmt_key, body.key);
        printf("%s %llu %02x\n", fmt_key, body.last_modified, body.flags);
        fflush(stdout);
    }
    ret = evr_ok;
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection");
        ret = evr_error;
    }
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
    struct evr_file src_c;
    if(evr_connect_to_storage(&src_c, cfg, cfg->src_storage_host, cfg->src_storage_port) != evr_ok){
        goto out;
    }
    struct evr_file dst_c;
    if(evr_connect_to_storage(&dst_c, cfg, cfg->dst_storage_host, cfg->dst_storage_port) != evr_ok){
        goto out_with_close_src_c;
    }
    struct evr_blob_filter f;
    f.sort_order = evr_cmd_watch_sort_order_ref;
    f.flags_filter = cfg->flags;
    f.last_modified_after = 0;
    if(evr_req_cmd_watch_blobs(&src_c, &f) != evr_ok){
        goto out_with_close_dst_c;
    }
    if(evr_req_cmd_watch_blobs(&dst_c, &f) != evr_ok){
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
        int src_fd = src_c.get_fd(&src_c);
        int dst_fd = dst_c.get_fd(&dst_c);
        const int fd_limit = max(src_fd, dst_fd) + 1;
        FD_ZERO(&fds);
        if(src_state == sync_state_want_ref){
            FD_SET(src_fd, &fds);
        }
        if(dst_state == sync_state_want_ref){
            FD_SET(dst_fd, &fds);
        }
        int wait_res;
        if((src_state == sync_state_want_ref && src_c.pending(&src_c) > 0)
           || (dst_state == sync_state_want_ref && dst_c.pending(&dst_c) > 0)){
            wait_res = evr_ok;
        } else {
            int sel_ret = select(fd_limit, &fds, NULL, NULL, NULL);
            wait_res = sel_ret < 0 ? evr_error : evr_ok;
        }
        if(wait_res != evr_ok){
            goto out_with_close_dst_c;
        }
        for(int i = 0; i < fd_limit; ++i){
            if(FD_ISSET(i, &fds)){
                struct evr_watch_blobs_body *body;
                int *state;
                struct evr_file *f;
                if(i == src_fd){
                    body = &src_next_blob;
                    state = &src_state;
                    f = &src_c;
                } else if(i == dst_fd) {
                    body = &dst_next_blob;
                    state = &dst_state;
                    f = &dst_c;
                } else {
                    evr_panic("Unknown file descriptor is set: %d", i);
                    goto out_with_close_dst_c;
                }
                int read_res = evr_read_watch_blobs_body(f, body);
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
            ref_cmp = evr_cmp_blob_ref(src_next_blob.key, dst_next_blob.key);
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
    if(dst_c.close(&dst_c) != 0){
        evr_panic("Unable to close connection to destination server");
        ret = evr_error;
    }
 out_with_close_src_c:
    if(src_c.close(&src_c) != 0){
        evr_panic("Unable to close connection to source server");
        ret = evr_error;
    }
 out:
    return ret;
}

int blob_sync_worker(void *context){
    int ret = evr_error;
    evr_init_xml_error_logging();
    struct evr_blob_sync_handover *ctx = context;
    struct evr_file c_src;
    evr_file_bind_fd(&c_src, -1);
    struct evr_file c_dst;
    evr_file_bind_fd(&c_dst, -1);
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
            if(c_src.get_fd(&c_src) == -1){
                // TODO reuse SSL_CTX and auth-token from outside worker
                if(evr_connect_to_storage(&c_src, ctx->cfg, ctx->cfg->src_storage_host, ctx->cfg->src_storage_port) != evr_ok){
                    goto continue_with_retry;
                }
            }
            if(c_dst.get_fd(&c_dst) == -1){
                // TODO reuse SSL_CTX and auth-token from outside worker
                if(evr_connect_to_storage(&c_dst, ctx->cfg, ctx->cfg->dst_storage_host, ctx->cfg->dst_storage_port) != evr_ok){
                    goto continue_with_retry;
                }
            }
            struct evr_file *cg;
            struct evr_file *cp;
            switch(sync_dir){
            default:
                evr_panic("Unknown sync_dir %d", sync_dir);
                goto out_with_close_c;
            case sync_dir_src_to_dst:
                cg = &c_src;
                cp = &c_dst;
                break;
            case sync_dir_dst_to_src:
                cg = &c_dst;
                cp = &c_src;
                break;
            }
            if(evr_req_cmd_get_blob(cg, ref, &get_resp) != evr_ok){
                goto continue_with_retry;
            }
            char buf[sizeof(uint8_t)];
            if(read_n(cg, buf, sizeof(buf), NULL, NULL) != evr_ok){
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
            // here we don't need to validate if the piped blob data
            // matches the blob's ref hash because the receiving
            // evr-glacier-storage server also performes this check.
            if(pipe_n(cp, cg, blob_size, NULL, NULL) != evr_ok){
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
            if(c_dst.get_fd(&c_dst) >= 0){
                if(c_dst.close(&c_dst) != 0){
                    evr_file_bind_fd(&c_dst, -1);
                    goto out_with_close_c;
                }
                evr_file_bind_fd(&c_dst, -1);
            }
            if(c_src.get_fd(&c_src) >= 0){
                if(c_src.close(&c_src) != 0){
                    evr_file_bind_fd(&c_src, -1);
                    goto out_with_close_c;
                }
                evr_file_bind_fd(&c_src, -1);
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
    if(c_dst.get_fd(&c_dst) >= 0){
        if(c_dst.close(&c_dst) != 0){
            evr_panic("Unable to close dest connection");
            ret = evr_error;
        }
    }
    if(c_src.get_fd(&c_src) >= 0){
        if(c_src.close(&c_src) != 0){
            evr_panic("Unable to close source connection");
            ret = evr_error;
        }
    }
 out:
    log_debug("blob_sync_worker ending with status %d", ret);
    return ret;
}

int evr_connect_to_storage(struct evr_file *c, struct cli_cfg *cfg, char *host, char *port){
    struct evr_auth_token_cfg *t_cfg;
    if(evr_find_auth_token(&t_cfg, cfg->auth_tokens, host, port) != evr_ok){
        log_error("No auth token found for server %s:%s", host, port);
        return evr_error;
    }
    if(evr_tls_connect_once(c, host, port, cfg->ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server %s:%s", host, port);
        return evr_error;
    }
    if(evr_write_auth_token(c, t_cfg->token) != evr_ok){
        if(c->close(c) != 0){
            evr_panic("Unable to close evr-glacier-storage connection");
        }
        return evr_error;
    }
    return evr_ok;
}

int evr_connect_to_index(struct evr_file *c, struct evr_buf_read **r, struct cli_cfg *cfg, char *host, char *port){
    struct evr_auth_token_cfg *t_cfg;
    if(evr_find_auth_token(&t_cfg, cfg->auth_tokens, host, port) != evr_ok){
        log_error("No auth token found for server %s:%s", host, port);
        goto fail;
    }
    if(evr_tls_connect_once(c, host, port, cfg->ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-attr-index server %s:%s", host, port);
        goto fail;
    }
    *r = evr_create_buf_read(c, 12);
    if(!*r){
        goto fail_with_close_c;
    }
    if(evr_attri_write_auth_token(c, t_cfg->token) != evr_ok){
        goto fail_with_free_r;
    }
    return evr_ok;
 fail_with_free_r:
    evr_free_buf_read(*r);
 fail_with_close_c:
    if(c->close(c) != 0){
        evr_panic("Unable to close evr-attr-index connection");
    }
 fail:
    return evr_error;
}
