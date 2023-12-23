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

#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>
#include <threads.h>
#include <libxslt/xslt.h>
#include <arpa/inet.h>
#include <fcntl.h>

#ifdef EVR_HAS_HTTPD
#include <microhttpd.h>
#endif

#include "basics.h"
#include "claims.h"
#include "errors.h"
#include "logger.h"
#include "evr-glacier-client.h"
#include "signatures.h"
#include "server.h"
#include "attr-index-db.h"
#include "configurations.h"
#include "files.h"
#include "file-mem.h"
#include "configp.h"
#include "handover.h"
#include "evr-tls.h"
#include "notify.h"
#include "daemon.h"

#ifdef EVR_HAS_HTTPD
#include "httpd.h"
#endif

#define program_name "evr-attr-index"
#define server_name program_name "/" VERSION

const char *argp_program_version = program_name " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " provides an index over a evr-glacier-storage server.";

static char args_doc[] = "";

#define default_state_dir_path EVR_PREFIX "/var/everarch/" program_name
#define default_ssl_cert_path default_index_ssl_cert_path
#define default_ssl_key_path EVR_PREFIX "/etc/everarch/" program_name "-key.pem"

#define arg_host 256
#define arg_storage_host 257
#define arg_storage_port 258
#define arg_ssl_cert_path 259
#define arg_ssl_key_path 260
#define arg_ssl_cert 261
#define arg_storage_auth_token 262
#define arg_auth_token 263
#define arg_gpg_key 264
#define arg_log_path 265
#define arg_pid_path 266
#ifdef EVR_HAS_HTTPD
#define arg_http_port 267
#endif

static struct argp_option options[] = {
    {"state-dir", 'd', "DIR", 0, "State directory path. This is the place where the index is persisted. Default path is " default_state_dir_path "."},
    {"host", arg_host, "HOST", 0, "The network interface at which the attr index server will listen on. The default is " evr_attr_index_host "."},
    {"port", 'p', "PORT", 0, "The tcp port at which the attr index server will listen. The default port is " to_string(evr_attr_index_port) "."},
    {"cert", arg_ssl_cert_path, "FILE", 0, "The path to the pem file which contains the public SSL certificate. Default path is " default_ssl_cert_path "."},
    {"key", arg_ssl_key_path, "FILE", 0, "The path to the pem file which contains the private SSL key. Default path is " default_ssl_key_path "."},
#ifdef EVR_HAS_HTTPD
    {"http-port", arg_http_port, "PORT", 0, "The tcp port at which the attr index server will listen for http connections. Using the port number 0 will disable the http server. The default port is " to_string(evr_attr_index_http_port) "."},
#endif
    {"auth-token", arg_auth_token, "TOKEN", 0, "An authorization token which must be presented by clients so their requests are accepted. Must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret. You can call 'openssl rand -hex 32' to generate a good token."},
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glalier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"storage-auth-token", arg_storage_auth_token, "TOKEN", 0, "An authorization token which is presented to the storage server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of remote servers. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"accepted-gpg-key", arg_gpg_key, "FINGERPRINT", 0, "A GPG key fingerprint of claim signatures which will be accepted as valid. Can be specified multiple times to accept multiple keys. You can call 'gpg --list-public-keys' to see your known keys."},
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"log", arg_log_path, "FILE", 0, "A file to which log output messages will be appended. By default logs are written to stdout."},
    {"pid", arg_pid_path, "FILE", 0, "A file to which the daemon's pid is written."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_attr_index_cfg *cfg = (struct evr_attr_index_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'd':
        evr_replace_str(cfg->state_dir_path, arg);
        break;
    case arg_host:
        evr_replace_str(cfg->host, arg);
        break;
    case 'p':
        evr_replace_str(cfg->port, arg);
        break;
#ifdef EVR_HAS_HTTPD
    case arg_http_port:
        evr_replace_str(cfg->http_port, arg);
        break;
#endif
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
    case arg_storage_host:
        evr_replace_str(cfg->storage_host, arg);
        break;
    case arg_storage_port:
        evr_replace_str(cfg->storage_port, arg);
        break;
    case arg_storage_auth_token:
        if(evr_parse_auth_token(cfg->storage_auth_token, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->storage_auth_token_set = 1;
        break;
    case arg_ssl_cert:
        if(evr_parse_and_push_cert(&cfg->ssl_certs, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case arg_auth_token:
        if(evr_parse_auth_token(cfg->auth_token, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->auth_token_set = 1;
        break;
    case arg_gpg_key: {
        const size_t arg_size = strlen(arg) + 1;
        struct evr_buf_pos bp;
        if(evr_llbuf_prepend(&cfg->accepted_gpg_fprs, &bp, arg_size) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        evr_push_n(&bp, arg, arg_size);
        break;
    }
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

static sig_atomic_t running = 1;
static mtx_t stop_lock;
static cnd_t stop_signal;
static struct evr_notify_ctx *watchers = NULL;

struct evr_connection {
    struct evr_file socket;
    int authenticated;
};

/**
 * watch_overlap defines the overlap of claim watches in seconds.
 */
#define watch_overlap (10 * 60)
#define apply_watch_overlap(t) (t <= watch_overlap ? 0 : t - watch_overlap)

struct evr_attr_index_cfg *cfg;

SSL_CTX *ssl_server_ctx;

struct evr_attr_spec_handover_ctx {
    struct evr_handover_ctx handover;

    struct evr_attr_spec_claim *claim;
    evr_blob_ref claim_key;
    evr_time created;
};

struct evr_index_handover_ctx {
    struct evr_handover_ctx handover;

    evr_blob_ref index_ref;
};

struct evr_current_index_ctx {
    struct evr_handover_ctx handover;
    evr_blob_ref index_ref;
};

struct evr_current_index_ctx current_index_ctx;

struct evr_search_ctx {
    struct evr_connection *con;
    int parse_res;
};

struct evr_modified_seed {
    evr_time change_time;
    evr_blob_ref index_ref;
    evr_claim_ref seed;
};

int evr_load_attr_index_cfg(int argc, char **argv);

void handle_sigterm(int signum);
#define evr_init_attr_spec_handover_ctx(ctx) evr_init_handover_ctx(&(ctx)->handover)
int evr_free_attr_spec_handover_ctx(struct evr_attr_spec_handover_ctx *ctx);
#define evr_init_index_handover_ctx(ctx) evr_init_handover_ctx(&(ctx)->handover)
#define evr_free_index_handover_ctx(ctx) evr_free_handover_ctx(&(ctx)->handover)
#define evr_init_current_index_ctx(ctx) evr_init_handover_ctx(&(ctx)->handover)
#define evr_free_current_index_ctx(ctx) evr_free_handover_ctx(&(ctx)->handover)

int evr_watch_index_claims_worker(void *arg);
int evr_build_index_worker(void *arg);
int evr_index_sync_worker(void *arg);
int evr_bootstrap_db(evr_blob_ref claim_key, struct evr_attr_spec_claim *spec);
int evr_attr_index_tcp_server();
int evr_connection_worker(void *ctx);
int evr_work_cmd(struct evr_connection *ctx, char *line);
int evr_respond_search_status(void *context, int parse_res, char *parse_errer);
int evr_respond_search_result(void *context, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);
int evr_get_current_index_ref(evr_blob_ref index_ref);
int evr_respond_help(struct evr_connection *ctx);
int evr_respond_status(struct evr_connection *ctx, int ok, char *msg);
int evr_respond_message_end(struct evr_connection *ctx);
int evr_write_blob_to_file(void *ctx, char *path, mode_t mode, evr_blob_ref ref);

#ifdef EVR_HAS_HTTPD
static enum MHD_Result evr_attr_index_handle_http_request(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
#endif

int main(int argc, char **argv){
    int ret = evr_error;
    evr_log_app = "i";
    evr_init_basics();
    evr_tls_init();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    if(evr_load_attr_index_cfg(argc, argv) != evr_ok){
        goto out_with_free_tls;
    }
    ssl_server_ctx = evr_create_ssl_server_ctx(cfg->ssl_cert_path, cfg->ssl_key_path);
    if(!ssl_server_ctx){
        log_error("Unable to configure SSL context");
        goto out_with_free_cfg;
    }
    if(mtx_init(&stop_lock, mtx_plain) != thrd_success){
        goto out_with_free_ssl_server_ctx;
    }
    if(cnd_init(&stop_signal) != thrd_success){
        goto out_with_free_stop_lock;
    }
    watchers = evr_create_notify_ctx(32, 8, sizeof(struct evr_modified_seed));
    if(!watchers){
        goto out_with_free_stop_signal;
    }
    if(evr_init_current_index_ctx(&current_index_ctx) != evr_ok){
        goto out_with_free_watchers;
    }
    {
        struct sigaction action = { 0 };
        action.sa_handler = handle_sigterm;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    if(sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK){
        // read https://sqlite.org/threadsafe.html if you run into
        // this error
        log_error("Failed to configure multi-threaded mode for sqlite3");
        goto out_with_free_current_index;
    }
    evr_init_signatures();
    xmlInitParser();
    struct evr_attr_spec_handover_ctx attr_spec_handover_ctx;
    if(evr_init_attr_spec_handover_ctx(&attr_spec_handover_ctx) != evr_ok){
        goto out_with_cleanup_xml_parser;
    }
    struct evr_index_handover_ctx index_handover_ctx;
    if(evr_init_index_handover_ctx(&index_handover_ctx) != evr_ok){
        goto out_with_free_attr_spec_handover_ctx;
    }
    if(!cfg->foreground){
        if(evr_daemonize(cfg->pid_path) != evr_ok){
            goto out_with_free_index_handover_ctx;
        }
    }
    thrd_t watch_index_claims_thrd;
    if(thrd_create(&watch_index_claims_thrd, evr_watch_index_claims_worker, &attr_spec_handover_ctx) != thrd_success){
        goto out_with_free_index_handover_ctx;
    }
    thrd_t build_index_thrd;
    void *build_index_thrd_ctx[] = {
        &attr_spec_handover_ctx,
        &index_handover_ctx,
    };
    if(thrd_create(&build_index_thrd, evr_build_index_worker, &build_index_thrd_ctx) != thrd_success){
        goto out_with_join_watch_index_claims_thrd;
    }
    thrd_t index_sync_thrd;
    if(thrd_create(&index_sync_thrd, evr_index_sync_worker, &index_handover_ctx) != thrd_success){
        goto out_with_join_build_index_thrd;
    }
    thrd_t tcp_server_thrd;
    if(thrd_create(&tcp_server_thrd, evr_attr_index_tcp_server, NULL) != thrd_success){
        goto out_with_join_index_sync_thrd;
    }
#ifdef EVR_HAS_HTTPD
#define out_with_stop_httpd_conditional out_with_stop_httpd
    struct MHD_Daemon *httpd;
    long http_port;
    char *http_port_end;
    http_port = strtol(cfg->http_port, &http_port_end, 10);
    if(*http_port_end != '\0'){
        log_error("Expected a number as http port but got: %s", cfg->http_port);
        goto out_with_join_index_sync_thrd;
    }
    if(http_port < 0 || http_port > 65535){
        log_error("http port must be greater equal 0 and smaller equal 65535");
        goto out_with_join_index_sync_thrd;
    }
    if(http_port == 0){
        log_info("http server disabled");
        httpd = NULL;
    } else {
        // TODO use a thread pool
        httpd = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, (uint16_t)http_port, NULL, NULL, &evr_attr_index_handle_http_request, NULL, MHD_OPTION_END);
        if(!httpd){
            log_error("Unable to start http daemon");
            goto out_with_join_watch_index_claims_thrd;
        }
        log_info("http server listening on %s", cfg->http_port);
    }
#else
#define out_with_stop_httpd_conditional out_with_join_index_sync_thrd
#endif
    if(mtx_lock(&stop_lock) != thrd_success){
        evr_panic("Failed to lock stop lock");
    }
    while(running){
        if(cnd_wait(&stop_signal, &stop_lock) != thrd_success){
            evr_panic("Failed to wait for stop signal");
        }
    }
    if(mtx_unlock(&stop_lock) != thrd_success){
        evr_panic("Failed to unlock stop lock");
    }
    if(evr_abort_handover(&index_handover_ctx.handover, 1) != evr_ok){
        goto out_with_stop_httpd_conditional;
    }
    if(evr_abort_handover(&attr_spec_handover_ctx.handover, 1) != evr_ok){
        goto out_with_stop_httpd_conditional;
    }
    if(evr_abort_handover(&current_index_ctx.handover, 1) != evr_ok){
        goto out_with_stop_httpd_conditional;
    }
    ret = evr_ok;
    int thrd_res;
#ifdef EVR_HAS_HTTPD
 out_with_stop_httpd:
    if(httpd){
        MHD_stop_daemon(httpd);
    }
#endif
 out_with_join_index_sync_thrd:
    if(thrd_join(index_sync_thrd, &thrd_res) != thrd_success){
        evr_panic("Failed to join index sync thread");
        ret = evr_error;
    }
    if(thrd_res != evr_ok){
        ret = evr_error;
    }
 out_with_join_build_index_thrd:
    if(thrd_join(build_index_thrd, &thrd_res) != thrd_success){
        evr_panic("Failed to join build index thread");
        ret = evr_error;
    }
    if(thrd_res != evr_ok){
        ret = evr_error;
    }
 out_with_join_watch_index_claims_thrd:
    if(thrd_join(watch_index_claims_thrd, &thrd_res) != thrd_success){
        evr_panic("Failed to join watch index claims thread");
        ret = evr_error;
    }
    if(thrd_res != evr_ok){
        ret = evr_error;
    }
 out_with_free_index_handover_ctx:
    if(evr_free_index_handover_ctx(&index_handover_ctx) != evr_ok){
        evr_panic("Failed to free index handover context");
        ret = evr_error;
    }
 out_with_free_attr_spec_handover_ctx:
    if(evr_free_attr_spec_handover_ctx(&attr_spec_handover_ctx) != evr_ok){
        evr_panic("Failed to free attr-spec handover context");
        ret = evr_error;
    }
 out_with_cleanup_xml_parser:
    xsltCleanupGlobals();
    xmlCleanupParser();
 out_with_free_current_index:
    evr_free_current_index_ctx(&current_index_ctx);
 out_with_free_watchers:
    if(evr_free_notify_ctx(watchers) != evr_ok){
        evr_panic("Unable to free watchers");
        ret = evr_error;
    }
 out_with_free_stop_signal:
    cnd_destroy(&stop_signal);
 out_with_free_stop_lock:
    mtx_destroy(&stop_lock);
 out_with_free_ssl_server_ctx:
    SSL_CTX_free(ssl_server_ctx);
 out_with_free_cfg:
    evr_free_attr_index_cfg(cfg);
 out_with_free_tls:
    evr_tls_free();
    return ret;
}

int evr_load_attr_index_cfg(int argc, char **argv){
    cfg = malloc(sizeof(struct evr_attr_index_cfg));
    if(!cfg){
        evr_panic("Unable to allocate memory for configuration.");
        return evr_error;
    }
    cfg->state_dir_path = strdup(default_state_dir_path);
    cfg->host = strdup(evr_attr_index_host);
    cfg->port = strdup(to_string(evr_attr_index_port));
#ifdef EVR_HAS_HTTPD
    cfg->http_port = strdup(to_string(evr_attr_index_http_port));
    if(!cfg->http_port){
        evr_panic("Unable to allocate memory for configuration.");
    }
#endif
    cfg->ssl_cert_path = strdup(default_ssl_cert_path);
    cfg->ssl_key_path = strdup(default_ssl_key_path);
    cfg->auth_token_set = 0;
    cfg->ssl_certs = NULL;
    cfg->storage_host = strdup(evr_glacier_storage_host);
    cfg->storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg->storage_auth_token_set = 0;
    cfg->accepted_gpg_fprs = NULL;
    cfg->verify_ctx = NULL;
    cfg->foreground = 0;
    cfg->log_path = NULL;
    cfg->pid_path = NULL;
    if(!cfg->state_dir_path || !cfg->host || !cfg->port || !cfg->storage_host || !cfg->storage_port){
        evr_panic("Unable to allocate memory for configuration.");
        // TODO free memory allocated in this function even if program terminates after returning evr_error here
        return evr_error;
    }
    if(evr_push_cert(&cfg->ssl_certs, evr_glacier_storage_host, to_string(evr_glacier_storage_port), default_storage_ssl_cert_path) != evr_ok){
        evr_panic("Unable to configure SSL certs");
        // TODO free memory allocated in this function even if program terminates after returning evr_error here
        return evr_error;
    }
    struct configp configp = {
        options, parse_opt, args_doc, doc
    };
    char *config_paths[] = evr_program_config_paths();
    if(configp_parse(&configp, config_paths, cfg) != 0){
        evr_panic("Unable to parse config files");
        // TODO free memory allocated in this function even if program terminates after returning evr_error here
        return evr_error;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, cfg);
    if(evr_setup_log(cfg->log_path) != evr_ok){
        return evr_error;
    }
    evr_single_expand_property(cfg->state_dir_path, panic);
    if(cfg->auth_token_set == 0){
        log_error("Setting an auth-token is mandatory. Call " program_name " --help for details how to set the auth-token.");
        // TODO free memory allocated in this function even if program terminates after returning evr_error here
        return evr_error;
    }
    if(cfg->storage_auth_token_set == 0){
        log_error("Setting a storage-auth-token is mandatory. Call " program_name " --help for details how to set the storage-auth-token.");
        // TODO free memory allocated in this function even if program terminates after returning evr_error here
        return evr_error;
    }
    if(!cfg->accepted_gpg_fprs){
        log_error("Accepting at least one GPG fingerprint as accepted is mandatory. Otherwise nothing can be indexed. Call " program_name " --help for details how to accept GPG fingerprints.");
        return evr_error;
    }
    cfg->verify_ctx = evr_build_verify_ctx(cfg->accepted_gpg_fprs);
    if(!cfg->verify_ctx){
        log_error("Unable to build gpg verification context.");
        // TODO free memory allocated in this function even if program terminates after returning evr_error here
        return evr_error;
    }
    evr_free_llbuf_chain(cfg->accepted_gpg_fprs, NULL);
    cfg->accepted_gpg_fprs = NULL;
    return evr_ok;
 panic:
    evr_panic("Unable to expand configuration values");
    // TODO free memory allocated in this function even if program terminates after returning evr_error here
    return evr_error;
}

void handle_sigterm(int signum){
    if(mtx_lock(&stop_lock) != thrd_success){
        evr_panic("Failed to lock stop lock");
        return;
    }
    if(running){
        log_info("Shutting down");
        running = 0;
        if(cnd_signal(&stop_signal) != thrd_success){
            evr_panic("Failed to send stop signal");
            return;
        }
    }
    if(mtx_unlock(&stop_lock) != thrd_success){
        evr_panic("Failed to unlock stop lock");
        return;
    }
}

int evr_free_attr_spec_handover_ctx(struct evr_attr_spec_handover_ctx *ctx){
    int ret = evr_error;
    if(ctx->claim){
        free(ctx->claim);
    }
    if(evr_free_handover_ctx(&ctx->handover) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

#define evr_worker_ended(name, ret)                             \
    if(ret == evr_ok){                                          \
        log_debug("Ended " name " worker with result %d", ret); \
    } else {                                                    \
        evr_panic("Ended " name " worker with result %d", ret); \
    }                                                           \

int evr_watch_index_claims_worker(void *arg){
    int ret = evr_error;
    evr_init_xml_error_logging();
    struct evr_attr_spec_handover_ctx *ctx = arg;
    log_debug("Started watch index claims worker");
    SSL_CTX *ssl_ctx = evr_create_ssl_client_ctx(cfg->storage_host, cfg->storage_port, cfg->ssl_certs);
    if(!ssl_ctx){
        goto out;
    }
    // cw is the connection used for watching for blob changes.
    struct evr_file cw;
    if(evr_tls_connect(&cw, cfg->storage_host, cfg->storage_port, ssl_ctx) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_ssl_ctx;
    }
    if(evr_write_auth_token(&cw, cfg->storage_auth_token) != evr_ok){
        goto out_with_close_cw;
    }
    struct evr_blob_filter filter;
    filter.sort_order = evr_cmd_watch_sort_order_last_modified;
    filter.flags_filter = evr_blob_flag_index_rule_claim;
    filter.last_modified_after = 0;
    if(evr_req_cmd_watch_blobs(&cw, &filter) != evr_ok){
        goto out_with_close_cw;
    }
    struct evr_watch_blobs_body body;
    struct evr_attr_spec_claim *latest_spec = NULL;
    evr_blob_ref latest_spec_key;
    evr_time latest_spec_created = 0;
    // cs is the connection used for finding the most recent
    // attr-spec claim
    struct evr_file cs;
    evr_file_bind_fd(&cs, -1);
    log_debug("Watching index claims");
    while(running){
        int read_wait_res = cw.wait_for_data(&cw, 1);
        if(read_wait_res != evr_ok && read_wait_res != evr_end){
            goto out_with_close_cw;
        }
        if(!running){
            ret = evr_ok;
            goto out_with_close_cw;
        }
        if(read_wait_res == evr_end){
            continue;
        }
        if(evr_read_watch_blobs_body(&cw, &body) != evr_ok){
            goto out_with_free_latest_spec;
        }
#ifdef EVR_LOG_DEBUG
        do {
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_debug("Checking index claim %s for attr-spec", fmt_key);
        } while(0);
#endif
        if(cs.get_fd(&cs) == -1){
            if(evr_tls_connect(&cs, cfg->storage_host, cfg->storage_port, ssl_ctx) != evr_ok){
                log_error("Failed to connect to evr-glacier-storage server");
                goto out_with_free_latest_spec;
            }
            if(evr_write_auth_token(&cs, cfg->storage_auth_token) != evr_ok){
                goto out_with_free_latest_spec;
            }
        }
        xmlDocPtr claim_doc = NULL;
        int fetch_res = evr_fetch_signed_xml(&claim_doc, cfg->verify_ctx, &cs, body.key, NULL);
        if(fetch_res == evr_user_data_invalid){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_error("Index claim with blob key %s has invalid content. Ignoring this claim.", fmt_key);
            continue;
        } else if(fetch_res != evr_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_error("Index claim not fetchable for blob key %s", fmt_key);
            goto out_with_free_latest_spec;
        }
        xmlNode *cs_node = evr_get_root_claim_set(claim_doc);
        if(!cs_node){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_error("Index claim does not contain claim-set element for blob key %s", fmt_key);
            goto out_with_free_claim_doc;
        }
        evr_time created;
        if(evr_parse_created(&created, cs_node) != evr_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_error("Failed to parse created date from index claim-set for blob ref %s", fmt_key);
            goto out_with_free_claim_doc;
        }
        if(latest_spec == NULL || created > latest_spec_created){
            xmlNode *c_node = evr_find_next_element(evr_first_claim(cs_node), "attr-spec", evr_claims_ns);
            if(c_node){
                if(latest_spec){
                    free(latest_spec);
                }
                latest_spec = evr_parse_attr_spec_claim(c_node);
                if(!latest_spec){
                    goto out_with_free_claim_doc;
                }
                memcpy(latest_spec_key, body.key, evr_blob_ref_size);
                latest_spec_created = created;
            }
        }
        xmlFree(claim_doc);
        if((body.flags & evr_watch_flag_eob) == 0 || !latest_spec){
            continue;
        }
        cs.close(&cs);
        evr_file_bind_fd(&cs, -1);
        int handover_wait_res = evr_wait_for_handover_available(&ctx->handover);
        if(handover_wait_res == evr_end){
            break;
        } else if(handover_wait_res != evr_ok){
            goto out_with_free_latest_spec;
        }
        // handover ctx is available
#ifdef EVR_LOG_DEBUG
        {
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, latest_spec_key);
            log_debug("Handover latest attr-spec %s", fmt_key);
        }
#endif
        ctx->claim = latest_spec;
        memcpy(ctx->claim_key, latest_spec_key, evr_blob_ref_size);
        ctx->created = latest_spec_created;
        if(evr_occupy_handover(&ctx->handover) != evr_ok){
            goto out_with_free_latest_spec;
        }
        latest_spec = NULL;
        continue;
    out_with_free_claim_doc:
        xmlFree(claim_doc);
        goto out_with_free_latest_spec;
    }
    ret = evr_ok;
 out_with_free_latest_spec:
    if(latest_spec){
        free(latest_spec);
    }
    if(cs.get_fd(&cs) >= 0){
        if(cs.close(&cs) != 0){
            evr_panic("Unable to close the attr-spec connection");
            ret = evr_error;
        };
    }
 out_with_close_cw:
    if(cw.close(&cw) != 0){
        evr_panic("Unable to close the watch connection");
        ret = evr_error;
    }
 out_with_free_ssl_ctx:
    SSL_CTX_free(ssl_ctx);
 out:
    evr_worker_ended("watch index claims", ret);
    return ret;
}

int evr_build_index_worker(void *arg){
    int ret = evr_error;
    evr_init_xml_error_logging();
    void **evr_build_index_worker_ctx = arg;
    struct evr_attr_spec_handover_ctx *sctx = evr_build_index_worker_ctx[0];
    struct evr_index_handover_ctx *ictx = evr_build_index_worker_ctx[1];
    log_debug("Started build index worker");
    int wait_res;
    while(1){
        wait_res = evr_wait_for_handover_occupied(&sctx->handover);
        if(wait_res == evr_end){
            break;
        } else if(wait_res != evr_ok){
            goto out;
        }
        struct evr_attr_spec_claim *claim = sctx->claim;
        sctx->claim = NULL;
        evr_blob_ref claim_key;
        memcpy(claim_key, sctx->claim_key, evr_blob_ref_size);
        if(evr_empty_handover(&sctx->handover) != evr_ok){
            goto out;
        }
#ifdef EVR_LOG_INFO
        {
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, claim_key);
            log_info("Start building attr index for %s", fmt_key);
        }
#endif
        int bootstrap_res = evr_bootstrap_db(claim_key, claim);
        if(bootstrap_res == evr_user_data_invalid){
#ifdef EVR_LOG_INFO
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, claim_key);
            log_info("Ignoring attr index for %s because of user data errors", fmt_key);
#endif
            continue;
        }
        if(bootstrap_res != evr_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, claim_key);
            log_error("Failed building attr index for %s", fmt_key);
            goto out;
        }
#ifdef EVR_LOG_INFO
        {
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, claim_key);
            log_info("Finished building attr index for %s", fmt_key);
        }
#endif
        free(claim);
        wait_res = evr_wait_for_handover_available(&ictx->handover);
        if(wait_res == evr_end){
            break;
        } else if(wait_res != evr_ok){
            goto out;
        }
#ifdef EVR_LOG_DEBUG
        {
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, claim_key);
            log_debug("Handover attr index for %s", fmt_key);
        }
#endif
        memcpy(ictx->index_ref, claim_key, evr_blob_ref_size);
        if(evr_occupy_handover(&ictx->handover) != evr_ok){
            goto out;
        }
    }
    ret = evr_ok;
 out:
    evr_worker_ended("build index", ret);
    return ret;
}

int evr_index_claim_set(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr stylesheet, evr_blob_ref claim_set_ref, evr_time claim_set_last_modified, struct evr_file *c, struct evr_claim_ref_tiny_set *visited_seed_refs);

int evr_bootstrap_db(evr_blob_ref claim_key, struct evr_attr_spec_claim *spec){
    int ret = evr_error;
    evr_blob_ref_str claim_key_str;
    evr_fmt_blob_ref(claim_key_str, claim_key);
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, claim_key_str, evr_write_blob_to_file, NULL);
    if(!db){
        goto out;
    }
    if(evr_setup_attr_index_db(db, spec) != evr_ok){
        goto out_with_free_db;
    }
    if(evr_prepare_attr_index_db(db) != evr_ok){
        goto out_with_free_db;
    }
    sqlite3_int64 stage;
    if(evr_attr_index_get_state(db, evr_state_key_stage, &stage) != evr_ok){
        goto out_with_free_db;
    }
    if(stage >= evr_attr_index_stage_built){
        ret = evr_ok;
        goto out_with_free_db;
    }
    struct evr_file cw;
    if(evr_tls_connect_once(&cw, cfg->storage_host, cfg->storage_port, cfg->ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_db;
    }
    if(evr_write_auth_token(&cw, cfg->storage_auth_token) != evr_ok){
        goto out_with_close_cw;
    }
    xsltStylesheetPtr style = NULL;
    int style_res = evr_fetch_stylesheet(&style, &cw, spec->transformation_blob_ref);
    if(style_res == evr_user_data_invalid){
        ret = evr_user_data_invalid;
        goto out_with_close_cw;
    }
    if(style_res != evr_ok){
        goto out_with_close_cw;
    }
    sqlite3_int64 last_indexed_claim_ts;
    if(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &last_indexed_claim_ts) != evr_ok){
        goto out_with_free_style;
    }
    struct evr_blob_filter filter;
    filter.sort_order = evr_cmd_watch_sort_order_last_modified;
    filter.flags_filter = evr_blob_flag_claim;
    filter.last_modified_after = apply_watch_overlap(last_indexed_claim_ts);
    if(evr_req_cmd_watch_blobs(&cw, &filter) != evr_ok){
        log_error("Unable to request watch claims on evr-glacier-storage");
        goto out_with_free_style;
    }
    struct evr_watch_blobs_body wbody;
    struct evr_file cs;
    evr_file_bind_fd(&cs, -1);
    while(running){
        int wait_res = cw.wait_for_data(&cw, 1);
        if(wait_res != evr_ok && wait_res != evr_end){
            goto out_with_close_cs;
        }
        if(!running){
            ret = evr_ok;
            goto out_with_close_cs;
        }
        if(wait_res == evr_end){
            continue;
        }
        if(evr_read_watch_blobs_body(&cw, &wbody) != evr_ok){
            goto out_with_close_cs;
        }
        if(evr_index_claim_set(db, spec, style, wbody.key, wbody.last_modified, &cs, NULL) != evr_ok){
            goto out_with_close_cs;
        }
        if((wbody.flags & evr_watch_flag_eob) == evr_watch_flag_eob){
            break;
        }
    }
    if(evr_attr_index_set_state(db, evr_state_key_stage, evr_attr_index_stage_built) != evr_ok){
        goto out_with_close_cs;
    }
    ret = evr_ok;
 out_with_close_cs:
    if(cs.get_fd(&cs) >= 0){
        if(cs.close(&cs) != 0){
            evr_panic("Unable to close attr-spec connection");
            ret = evr_error;
        }
    }
 out_with_free_style:
    xsltFreeStylesheet(style);
 out_with_close_cw:
    if(cw.close(&cw) != 0){
        evr_panic("Unable to close evr-glacier-storage connection");
        ret = evr_error;
    }
 out_with_free_db:
    if(evr_free_attr_index_db(db) != evr_ok){
        ret = evr_error;
    }
 out:
    return ret;
}

#define evr_max_seeds_per_claim_set (2 << 7) // 256

int evr_index_claim_set(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_blob_ref claim_set_ref, evr_time claim_set_last_modified, struct evr_file *c, struct evr_claim_ref_tiny_set *visited_seed_refs){
    int ret = evr_error;
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_debug("Indexing claim set %s", ref_str);
    }
#endif
    if(c->get_fd(c) == -1){
        if(evr_tls_connect_once(c, cfg->storage_host, cfg->storage_port, cfg->ssl_certs) != evr_ok){
            log_error("Failed to connect to evr-glacier-storage server");
            goto out;
        }
        if(evr_write_auth_token(c, cfg->storage_auth_token) != evr_ok){
            goto out;
        }
    }
    xmlDocPtr claim_set = NULL;
    int fetch_res = evr_fetch_signed_xml(&claim_set, cfg->verify_ctx, c, claim_set_ref, NULL);
    if(fetch_res == evr_user_data_invalid){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("Claim set with blob ref %s has invalid content. Ignoring it.", ref_str);
        ret = evr_ok;
        goto out;
    } else if(fetch_res != evr_ok){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("Claim set not fetchable for blob ref %s", ref_str);
        goto out;
    }
    evr_time t;
    evr_now(&t);
    int merge_res = evr_merge_attr_index_claim_set(db, spec, style, t, claim_set_ref, claim_set, 0, visited_seed_refs);
    if(merge_res == evr_user_data_invalid){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("Claim set with blob ref %s is invalid. Ignoring it.", ref_str);
        ret = evr_ok;
        goto out;
    } else if(merge_res != evr_ok){
        goto out_with_free_claim_set;
    }
    if(evr_attr_index_set_state(db, evr_state_key_last_indexed_claim_ts, claim_set_last_modified) != evr_ok){
        goto out_with_free_claim_set;
    }
    ret = evr_ok;
 out_with_free_claim_set:
    xmlFreeDoc(claim_set);
 out:
    return ret;
}

xmlDocPtr get_claim_set_for_reindex(void *ctx, evr_blob_ref claim_set_ref);

int evr_notify_watchers(evr_blob_ref index_ref, evr_time change_time, evr_claim_ref *changed_seeds, size_t changed_seeds_len);

int evr_index_sync_worker(void *arg){
    int ret = evr_error;
    evr_init_xml_error_logging();
    struct evr_index_handover_ctx *ctx = arg;
    log_debug("Started index sync worker");
    int wait_res = evr_wait_for_handover_occupied(&ctx->handover);
    if(wait_res == evr_end){
        ret = evr_ok;
        goto out;
    } else if(wait_res != evr_ok){
        goto out;
    }
    evr_blob_ref index_ref;
    memcpy(index_ref, ctx->index_ref, evr_blob_ref_size);
    if(evr_empty_handover(&ctx->handover) != evr_ok){
        goto out;
    }
    struct evr_file cg; // connection get
    evr_file_bind_fd(&cg, -1);
    struct evr_file cw; // connection watch
    evr_file_bind_fd(&cw, -1);
    struct evr_attr_index_db *db = NULL;
    struct evr_watch_blobs_body wbody;
    struct evr_attr_spec_claim *spec = NULL;
    xsltStylesheetPtr style = NULL;
    evr_time last_reindex = 0;
    struct evr_claim_ref_tiny_set *visited_seed_refs = NULL;
    visited_seed_refs = evr_create_claim_ref_tiny_set(evr_max_seeds_per_claim_set * evr_max_claim_sets_per_reindex);
    if(!visited_seed_refs){
        goto out_with_free;
    }
    while(running){
        if(evr_lock_handover(&ctx->handover) != evr_ok){
            goto out_with_free;
        }
        if(ctx->handover.occupied){
            if(cw.get_fd(&cw) != -1){
#ifdef EVR_LOG_DEBUG
                evr_blob_ref_str index_ref_str;
                evr_fmt_blob_ref(index_ref_str, index_ref);
                log_debug("Index sync worker stop index %s", index_ref_str);
#endif
                if(cw.close(&cw) != 0){
                    evr_panic("Unable to close watch connection");
                    goto out_with_free;
                }
                evr_file_bind_fd(&cw, -1);
            }
            memcpy(index_ref, ctx->index_ref, evr_blob_ref_size);
            if(evr_empty_handover(&ctx->handover) != evr_ok){
                goto out_with_free;
            }
        } else {
            if(mtx_unlock(&ctx->handover.lock) != thrd_success){
                evr_panic("Failed to unlock evr_index_handover_ctx");
                goto out_with_free;
            }
        }
        if(cw.get_fd(&cw) == -1){
            if(style){
                xsltFreeStylesheet(style);
                style = NULL;
            }
            if(spec){
                free(spec);
                spec = NULL;
            }
            if(db){
                if(evr_free_attr_index_db(db) != evr_ok){
                    log_error("Failed to close stopped index db");
                    goto out;
                }
                db = NULL;
            }
            // after this point the former index should be cleaned up
            // with all it's dependant variables
            evr_blob_ref_str index_ref_str;
            evr_fmt_blob_ref(index_ref_str, index_ref);
            log_info("Index sync worker switches to index %s", index_ref_str);
            if(evr_lock_handover(&current_index_ctx.handover) != evr_ok){
                goto out_with_free;
            }
            memcpy(current_index_ctx.index_ref, index_ref, evr_blob_ref_size);
            if(evr_occupy_handover(&current_index_ctx.handover) != evr_ok){
                evr_panic("Failed to occupy current index handover");
                goto out_with_free;
            }
            db = evr_open_attr_index_db(cfg, index_ref_str, evr_write_blob_to_file, NULL);
            if(!db){
                goto out_with_free;
            }
            if(evr_tls_connect_once(&cw, cfg->storage_host, cfg->storage_port, cfg->ssl_certs) != evr_ok){
                log_error("Failed to connect to evr-glacier-storage server");
                goto out_with_free;
            }
            if(evr_write_auth_token(&cw, cfg->storage_auth_token) != evr_ok){
                goto out_with_free;
            }
            if(evr_prepare_attr_index_db(db) != evr_ok){
                goto out_with_free;
            }
            xmlDocPtr cs_doc = NULL;
            int fetch_res = evr_fetch_signed_xml(&cs_doc, cfg->verify_ctx, &cw, index_ref, NULL);
            if(fetch_res == evr_user_data_invalid){
                // this situation is somehow theoretical. it would
                // mean that when initially building the index db the
                // blob contained validly signed XML but now does no
                // longer. maybe the gpg signature is no longer
                // accepted?
                evr_blob_ref_str ref_str;
                evr_fmt_blob_ref(ref_str, index_ref);
                log_error("Index claim with blob key %s has invalid content.", ref_str);
                goto out_with_free;
            } else if(fetch_res != evr_ok){
                evr_blob_ref_str fmt_key;
                evr_fmt_blob_ref(fmt_key, index_ref);
                log_error("Index claim not fetchable for blob key %s", fmt_key);
                goto out_with_free;
            }
            xmlNode *cs_node = evr_get_root_claim_set(cs_doc);
            if(!cs_node){
                goto out_with_free_cs_doc;
            }
            xmlNode *c_node = evr_find_next_element(evr_first_claim(cs_node), "attr-spec", evr_claims_ns);
            if(!c_node){
                goto out_with_free_cs_doc;
            }
            spec = evr_parse_attr_spec_claim(c_node);
            xmlFree(cs_doc);
            if(!spec){
                goto out_with_free;
            }
            if(evr_fetch_stylesheet(&style, &cw, spec->transformation_blob_ref) != evr_ok){
                goto out_with_free;
            }
            sqlite3_int64 last_indexed_claim_ts;
            if(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &last_indexed_claim_ts) != evr_ok){
                goto out_with_free;
            }
            struct evr_blob_filter filter;
            filter.sort_order = evr_cmd_watch_sort_order_last_modified;
            filter.flags_filter = evr_blob_flag_claim;
            filter.last_modified_after = apply_watch_overlap(last_indexed_claim_ts);
            if(evr_req_cmd_watch_blobs(&cw, &filter) != evr_ok){
                goto out_with_free;
            }
            goto end_init_style;
        out_with_free_cs_doc:
            xmlFree(cs_doc);
            goto out_with_free;
        end_init_style:
            log_debug("Index sync worker switch done");
            do{} while(0);
        }
        int wait_res = cw.wait_for_data(&cw, 1);
        if(wait_res != evr_ok && wait_res != evr_end){
            goto out_with_free;
        }
        if(!running){
            break;
        }
        if(wait_res == evr_end){
            evr_time now;
            evr_now(&now);
            // TODO we should use a time source which does not jump on ntpd actions
            if(now - last_reindex >= evr_reindex_interval) {
                evr_reset_claim_ref_tiny_set(visited_seed_refs);
                last_reindex = now;
                if(evr_reindex_failed_claim_sets(db, spec, style, now, get_claim_set_for_reindex, &cg, visited_seed_refs) != evr_ok){
                    log_error("Error while reindexing failed claim-sets");
                    goto out_with_free;
                }
                if(evr_notify_watchers(index_ref, now, visited_seed_refs->refs, visited_seed_refs->refs_used) != evr_ok){
                    log_error("Unable to inform watchers after reindex");
                    goto out_with_free;
                }
            }
            // TODO close cg after n timeouts in a row and set to -1
            continue;
        }
        if(evr_read_watch_blobs_body(&cw, &wbody) != evr_ok){
            goto out_with_free;
        }
        evr_reset_claim_ref_tiny_set(visited_seed_refs);
        if(evr_index_claim_set(db, spec, style, wbody.key, wbody.last_modified, &cg, visited_seed_refs) != evr_ok){
            goto out_with_free;
        }
        {
            evr_time now;
            evr_now(&now);
            if(evr_notify_watchers(index_ref, now, visited_seed_refs->refs, visited_seed_refs->refs_used) != evr_ok){
                log_error("Unable to inform attr index watchers after blob change");
                goto out_with_free;
            }
        }
    }
    ret = evr_ok;
 out_with_free:
    evr_free_claim_ref_tiny_set(visited_seed_refs);
    if(cg.get_fd(&cg) >= 0){
        if(cg.close(&cg) != 0){
            evr_panic("Unable to close watch connection");
            ret = evr_error;
        }
    }
    if(cw.get_fd(&cw) >= 0){
        if(cw.close(&cw) != 0){
            evr_panic("Unable to close watch connection");
            ret = evr_error;
        }
    }
    if(style){
        xsltFreeStylesheet(style);
    }
    free(spec);
    if(db){
        if(evr_free_attr_index_db(db) != evr_ok){
            ret = evr_error;
        }
    }
 out:
    evr_worker_ended("index sync", ret);
    return ret;
}

int evr_notify_watchers(evr_blob_ref index_ref, evr_time change_time, evr_claim_ref *changed_seeds, size_t changed_seeds_len){
    struct evr_modified_seed mod_seed;
    mod_seed.change_time = change_time;
    memcpy(mod_seed.index_ref, index_ref, evr_blob_ref_size);
    evr_claim_ref *end = &changed_seeds[changed_seeds_len];
    for(evr_claim_ref *it = changed_seeds; it != end; ++it){
        memcpy(mod_seed.seed, *it, evr_claim_ref_size);
        if(evr_notify_send(watchers, &mod_seed, NULL, NULL) != evr_ok){
            return evr_error;
        }
    }
    return evr_ok;
}

xmlDocPtr get_claim_set_for_reindex(void *ctx, evr_blob_ref claim_set_ref){
    struct evr_file *c = ctx;
    if(c->get_fd(c) == -1){
        // TODO reuse SSL_CTX and migrate to evr_tls_connect
        if(evr_tls_connect_once(c, cfg->storage_host, cfg->storage_port, cfg->ssl_certs) != evr_ok){
            log_error("Failed to connect to evr-glacier-storage server");
            return NULL;
        }
        if(evr_write_auth_token(c, cfg->storage_auth_token) != evr_ok){
            if(c->close(c) != 0){
                evr_panic("Unable to close connection");
            }
            evr_file_bind_fd(c, -1);
            return NULL;
        }
    }
    xmlDocPtr doc = NULL;
    if(evr_fetch_signed_xml(&doc, cfg->verify_ctx, c, claim_set_ref, NULL) != evr_ok){
        return NULL;
    }
    return doc;
}

int evr_attr_index_tcp_server(){
    int ret = evr_error;
    int s = evr_make_tcp_socket(cfg->host, cfg->port);
    if(s < 0){
        goto out;
    }
    if(listen(s, 7) != 0){
        log_error("Failed to listen on %s:%s", cfg->host, cfg->port);
        goto out_with_close_s;
    }
    log_info("Listening on %s:%s", cfg->host, cfg->port);
    fd_set active_fd_set;
    struct timeval timeout;
    while(running){
        FD_ZERO(&active_fd_set);
        FD_SET(s, &active_fd_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int sret = select(s + 1, &active_fd_set, NULL, NULL, &timeout);
        if(sret < 0){
            goto out_with_close_s;
        }
        if(!running){
            break;
        }
        if(sret == 0){
            continue;
        }
        for(int i = 0; i < FD_SETSIZE; ++i){
            if(FD_ISSET(i, &active_fd_set)){
                if(i == s){
                    struct evr_connection *ctx = malloc(sizeof(struct evr_connection));
                    if(!ctx){
                        goto loop;
                    }
                    ctx->authenticated = 0;
                    if(evr_tls_accept(&ctx->socket, s, ssl_server_ctx) != evr_ok){
                        goto out_with_free_ctx;
                    }
                    thrd_t t;
                    if(thrd_create(&t, evr_connection_worker, ctx) != thrd_success){
                        goto out_with_free_ctx;
                    }
                    if(thrd_detach(t) != thrd_success){
                        evr_panic("Failed to detach connection worker thread for worker %d", ctx->socket.get_fd(&ctx->socket));
                        goto out_with_close_s;
                    }
                    goto loop;
                out_with_free_ctx:
                    if(ctx->socket.close(&ctx->socket) != 0){
                        evr_panic("Unable to close client connection");
                    }
                    free(ctx);
                loop:
                    continue;
                }
            }
        }
    }
    ret = evr_ok;
 out_with_close_s:
    close(s);
 out:
    return ret;
}

int evr_connection_worker(void *context) {
    int ret = evr_error;
    struct evr_connection ctx = *(struct evr_connection*)context;
    free(context);
    log_debug("Started connection worker %d", ctx.socket.get_fd(&ctx.socket));
    char query_str[8*1024];
    char *query_scanned = query_str;
    char *query_end = &query_str[sizeof(query_str)];
    while(running){
        size_t max_read = query_end - query_scanned;
        if(max_read == 0){
            log_debug("Connection worker %d retrieved too big query", ctx.socket.get_fd(&ctx.socket));
            goto out_with_close_socket;
        }
        ssize_t bytes_read = ctx.socket.read(&ctx.socket, query_scanned, max_read);
        if(bytes_read == 0){
            ret = evr_ok;
            goto out_with_close_socket;
        }
        if(bytes_read < 0){
            goto out_with_close_socket;
        }
        char *read_end = &query_scanned[bytes_read];
        while(query_scanned != read_end){
            if(*query_scanned != '\n'){
                ++query_scanned;
                continue;
            }
            *query_scanned = '\0';
            int cmd_res = evr_work_cmd(&ctx, query_str);
            if(cmd_res == evr_end){
                ret = evr_ok;
                goto out_with_close_socket;
            }
            if(cmd_res != evr_ok){
                goto out_with_close_socket;
            }
            size_t l = read_end - (query_scanned + 1);
            if(l > 0){
                memmove(query_str, query_scanned + 1, l);
            }
            read_end -= (query_scanned + 1) - query_str;
            query_scanned = query_str;
        }
    }
#ifdef EVR_LOG_DEBUG
    int fd;
#endif
 out_with_close_socket:
#ifdef EVR_LOG_DEBUG
    fd = ctx.socket.get_fd(&ctx.socket);
#endif
    ctx.socket.close(&ctx.socket);
    log_debug("Ended connection worker %d with result %d", fd, ret);
    return ret;
}

int evr_work_authenticate_cmd(struct evr_connection *ctx, char *query);
int evr_work_search_cmd(struct evr_connection *ctx, char *query);
int evr_list_claims_for_seed(struct evr_connection *ctx, char *seed_ref_str);
int evr_watch_index(struct evr_connection *ctx);
int evr_describe_index(struct evr_connection *ctx);

int evr_work_cmd(struct evr_connection *ctx, char *line){
    log_debug("Connection worker %d retrieved cmd: %s", ctx->socket.get_fd(&ctx->socket), line);
    char *cmd = line;
    char *args = index(line, ' ');
    if(args){
        *args = '\0';
        ++args;
    }
    if(strcmp(cmd, "a") == 0){
        return evr_work_authenticate_cmd(ctx, args);
    }
    if(ctx->authenticated) {
        if(strcmp(cmd, "s") == 0){
            return evr_work_search_cmd(ctx, args);
        }
        if(strcmp(cmd, "c") == 0){
            return evr_list_claims_for_seed(ctx, args);
        }
        if(strcmp(cmd, "w") == 0){
            return evr_watch_index(ctx);
        }
        if(strcmp(cmd, "i") == 0){
            return evr_describe_index(ctx);
        }
    }
    if(strcmp(cmd, "exit") == 0){
        return evr_end;
    }
    if(strcmp(cmd, "?") == 0 || strcmp(cmd, "help") == 0){
        return evr_respond_help(ctx);
    }
    if(evr_respond_status(ctx, 0, "No such command.") != evr_ok){
        return evr_error;
    }
    return evr_respond_message_end(ctx);
}

int evr_work_authenticate_cmd(struct evr_connection *ctx, char *args_str){
    const size_t args_len = 2;
    char *args[args_len];
    if(evr_split_n(args, args_len, args_str, ' ') != evr_ok){
        // no logging of actual arguments to prevent accidential leak
        // of credentials.
        log_error("Illegal authenticate arguments syntax");
        return evr_error;
    }
    if(strcmp(args[0], "token") != 0){
        log_error("Unknown authentication method requested: %s", args[0]);
        return evr_error;
    }
    evr_auth_token client_token;
    if(evr_parse_auth_token(client_token, args[1]) != evr_ok){
        return evr_error;
    }
    if(memcmp(cfg->auth_token, client_token, sizeof(evr_auth_token)) != 0){
        log_error("Client provided invalid authentication token");
        return evr_error;
    }
    ctx->authenticated = 1;
    return evr_ok;
}    

int evr_work_search_cmd(struct evr_connection *ctx, char *query){
    int ret = evr_error;
    if(query == NULL){
        query = "";
    }
    log_debug("Connection worker %d retrieved query: %s", ctx->socket.get_fd(&ctx->socket), query);
    evr_blob_ref index_ref;
    int res = evr_get_current_index_ref(index_ref);
    if(res == evr_end){
        ret = evr_end;
        goto out;
    }
    if(res != evr_ok){
        goto out;
    }
    evr_blob_ref_str index_ref_str;
    evr_fmt_blob_ref(index_ref_str, index_ref);
    log_debug("Connection worker %d is using index %s for query", ctx->socket.get_fd(&ctx->socket), index_ref_str);
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, index_ref_str, evr_write_blob_to_file, NULL);
    if(!db){
        goto out;
    }
    struct evr_search_ctx sctx;
    sctx.con = ctx;
    if(evr_attr_query_claims(db, query, evr_respond_search_status, evr_respond_search_result, &sctx) != evr_ok){
        goto out_with_free_db;
    }
    if(evr_respond_message_end(ctx) != evr_ok){
        goto out_with_free_db;
    }
    ret = evr_ok;
 out_with_free_db:
    if(evr_free_attr_index_db(db) != evr_ok){
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_respond_search_status(void *context, int parse_res, char *parse_error){
    struct evr_search_ctx *ctx = context;
    ctx->parse_res = parse_res;
    if(parse_res != evr_ok){
        return evr_respond_status(ctx->con, 0, parse_error);
    }
    return evr_respond_status(ctx->con, 1, NULL);
}

int evr_respond_search_result(void *context, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len){
    int ret = evr_error;
    size_t attrs_size = 0;
    if(attrs){
        struct evr_attr_tuple *end = &attrs[attrs_len];
        for(struct evr_attr_tuple *a = attrs; a != end; ++a){
            attrs_size += 1 + strlen(a->key) + 1 + strlen(a->value) + 1;
        }
    }
    struct evr_search_ctx *ctx = context;
    char buf[evr_claim_ref_str_size + attrs_size];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_fmt_claim_ref(bp.pos, ref);
    evr_inc_buf_pos(&bp, evr_claim_ref_str_size - 1);
    evr_push_concat(&bp, "\n");
    if(attrs){
        struct evr_attr_tuple *end = &attrs[attrs_len];
        for(struct evr_attr_tuple *a = attrs; a != end; ++a){
            evr_push_concat(&bp, "\t");
            evr_push_concat(&bp, a->key);
            evr_push_concat(&bp, "=");
            evr_push_concat(&bp, a->value);
            evr_push_concat(&bp, "\n");
        }
    }
    if(write_n(&ctx->con->socket, bp.buf, bp.pos - bp.buf) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_respond_claims_for_seed_result(void *ctx, const evr_claim_ref claim);

int evr_list_claims_for_seed(struct evr_connection *ctx, char *seed_ref_str){
    if(seed_ref_str == NULL){
        seed_ref_str = "";
    }
    log_debug("Connection worker %d retrieved list claims for seed %s", ctx->socket.get_fd(&ctx->socket), seed_ref_str);
    int ret = evr_error;
    evr_claim_ref seed_ref;
    if(evr_parse_claim_ref(seed_ref, seed_ref_str) != evr_ok){
        log_error("Failed to parse seed_ref %s", seed_ref_str);
        goto out;
    }
    evr_blob_ref index_ref;
    int res = evr_get_current_index_ref(index_ref);
    if(res == evr_end){
        ret = evr_end;
        goto out;
    }
    if(res != evr_ok){
        goto out;
    }
    evr_blob_ref_str index_ref_str;
    evr_fmt_blob_ref(index_ref_str, index_ref);
    log_debug("Connection worker %d is using index %s for list claims for seed", ctx->socket.get_fd(&ctx->socket), index_ref_str);
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, index_ref_str, evr_write_blob_to_file, NULL);
    if(!db){
        goto out;
    }
    if(evr_prepare_attr_index_db(db) != evr_ok){
        goto out;
    }
    if(evr_attr_visit_claims_for_seed(db, seed_ref, evr_respond_claims_for_seed_result, ctx) != evr_ok){
        goto out_with_free_db;
    }
    if(evr_respond_message_end(ctx) != evr_ok){
        goto out_with_free_db;
    }
    ret = evr_ok;
 out_with_free_db:
    if(evr_free_attr_index_db(db) != evr_ok){
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_respond_claims_for_seed_result(void *context, const evr_claim_ref claim){
    struct evr_connection *ctx = context;
    evr_claim_ref_str claim_str;
    evr_fmt_claim_ref(claim_str, claim);
    claim_str[evr_claim_ref_str_size - 1] = '\n';
    return write_n(&ctx->socket, claim_str, evr_claim_ref_str_size);
}

int evr_watch_index(struct evr_connection *ctx){
    int ret = evr_error;
    log_debug("Connection worker %d retrieved watch command", ctx->socket.get_fd(&ctx->socket));
    struct evr_queue *msgs = evr_notify_register(watchers, NULL);
    if(!msgs){
        goto out;
    }
    if(evr_respond_status(ctx, 1, NULL) != evr_ok){
        return evr_error;
    }
    struct evr_modified_seed mod_seed;
    char buf[evr_blob_ref_str_len + 1 + evr_claim_ref_str_len + 1 + (evr_max_time_iso8601_size - 1) + 1 + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    while(running){
        if(ctx->socket.received_shutdown(&ctx->socket) == 1){
            log_debug("Worker %d retrieved shutdown request from peer", ctx->socket.get_fd(&ctx->socket));
            ret = evr_end;
            goto out_with_rm_watcher;
        }
        while(running){
            int take_res = evr_queue_take(msgs, &mod_seed);
            if(take_res == evr_not_found){
                break;
            } else if(take_res != evr_ok){
                goto out_with_rm_watcher;
            }
#ifdef EVR_LOG_DEBUG
            {
                evr_blob_ref_str index_ref_str;
                evr_fmt_blob_ref(index_ref_str, mod_seed.index_ref);
                evr_claim_ref_str seed_str;
                evr_fmt_claim_ref(seed_str, mod_seed.seed);
                log_debug("Worker %d watch indicates index %s changed seed %s", ctx->socket.get_fd(&ctx->socket), index_ref_str, seed_str);
            }
#endif
            evr_reset_buf_pos(&bp);
            evr_fmt_blob_ref(bp.pos, mod_seed.index_ref);
            evr_inc_buf_pos(&bp, evr_blob_ref_str_len);
            evr_push_concat(&bp, " ");
            evr_fmt_claim_ref(bp.pos, mod_seed.seed);
            evr_inc_buf_pos(&bp, evr_claim_ref_str_len);
            evr_push_concat(&bp, " ");
            evr_time_to_iso8601(bp.pos, evr_max_time_iso8601_size, &mod_seed.change_time);
            evr_forward_to_eos(&bp);
            evr_push_concat(&bp, "\n");
            if(write_n(&ctx->socket, buf, bp.pos - bp.buf) != evr_ok){
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
    ret = evr_ok;
 out_with_rm_watcher:
    if(evr_notify_unregister(watchers, msgs) != evr_ok){
        evr_panic("Worker %d is unable to unregister watcher", ctx->socket.get_fd(&ctx->socket));
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_describe_index(struct evr_connection *ctx){
    log_debug("Connection worker %d retrieved describe index", ctx->socket.get_fd(&ctx->socket));
    evr_blob_ref index_ref;
    if(evr_get_current_index_ref(index_ref) != evr_ok){
        return evr_error;
    }
    if(evr_respond_status(ctx, 1, NULL) != evr_ok){
        return evr_error;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str index_ref_str;
        evr_fmt_blob_ref(index_ref_str, index_ref);
        log_debug("Worker %d reports index-ref %s", ctx->socket.get_fd(&ctx->socket), index_ref_str);
    }
#endif
    char index_ref_label[] = "index-ref: ";
    char buf[sizeof(index_ref_label) - 1 + evr_blob_ref_str_len + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, index_ref_label);
    evr_fmt_blob_ref(bp.pos, index_ref);
    evr_inc_buf_pos(&bp, evr_blob_ref_str_len);
    evr_push_concat(&bp, "\n");
    if(write_n(&ctx->socket, buf, sizeof(buf)) != evr_ok){
        return evr_error;
    }
    if(evr_respond_message_end(ctx) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_get_current_index_ref(evr_blob_ref index_ref){
    int wait_res = evr_wait_for_handover_occupied(&current_index_ctx.handover);
    if(wait_res == evr_end){
        return evr_end;
    } else if(wait_res != evr_ok){
        return evr_error;
    }
    memcpy(index_ref, current_index_ctx.index_ref, evr_blob_ref_size);
    if(evr_unlock_handover(&current_index_ctx.handover) != evr_ok){
        evr_panic("Failed to unlock current index handover");
        return evr_error;
    }
    return evr_ok;
}

int evr_respond_help(struct evr_connection *ctx){
    int ret = evr_error;
    if(evr_respond_status(ctx, 1, NULL) != evr_ok){
        goto out;
    }
    const char help[] = PACKAGE_STRING "\n"
        "These commands are defined.\n"
        "exit - closes the conneciton\n"
        "help - shows this help message\n"
        "a TOKEN - authenticates with given token.\n"
        "s QUERY - searches for claims matching the given query. Requires authentication.\n"
        "c REF - lists all claims referencing the given seed claim. Requires authentication.\n"
        "w - watch for changes within the index\n"
        "i - describe the currently used index\n"
        ;
    if(write_n(&ctx->socket, help, sizeof(help)) != evr_ok){
        goto out;
    }
    if(evr_respond_message_end(ctx) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_respond_status(struct evr_connection *ctx, int ok, char *msg){
    size_t msg_len = msg ? 1 + strlen(msg) : 0;
    char buf[5 + msg_len + 1 + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, ok ? "OK" : "ERROR");
    if(msg){
        evr_push_concat(&bp, " ");
        evr_push_concat(&bp, msg);
    }
    evr_push_concat(&bp, "\n");
    return write_n(&ctx->socket, buf, bp.pos - bp.buf);
}

int evr_respond_message_end(struct evr_connection *ctx){
    return write_n(&ctx->socket, "\n", 1);
}

int evr_write_blob_to_file(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    int ret = evr_error;
    int fd = creat(path, mode);
    if(fd < 0){
        goto out;
    }
    struct evr_file f;
    evr_file_bind_fd(&f, fd);
    struct evr_file c;
    if(evr_tls_connect_once(&c, cfg->storage_host, cfg->storage_port, cfg->ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_close_f;
    }
    if(evr_write_auth_token(&c, cfg->storage_auth_token) != evr_ok){
        goto out_with_close_c;
    }
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(&c, ref, &resp) != evr_ok){
        goto out_with_close_c;
        return evr_error;
    }
    if(resp.status_code != evr_status_code_ok){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, ref);
        log_error("Failed to read blob %s from server. Responded status code was 0x%02x", resp.status_code);
        goto out;
    }
    if(resp.body_size > evr_max_blob_data_size){
        log_error("Server indicated huge blob size of %ul bytes", resp.body_size);
        goto out_with_close_c;
    }
    // ignore one byte containing the flags
    char buf[1];
    if(read_n(&c, buf, sizeof(buf), NULL, NULL) != evr_ok){
        goto out_with_close_c;
    }
    evr_blob_ref_hd hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto out_with_close_c;
    }
    if(pipe_n(&f, &c, resp.body_size - sizeof(buf), evr_blob_ref_write_se, hd) != evr_ok){
        goto out_with_close_hd;
    }
    if(evr_blob_ref_hd_match(hd, ref) != evr_ok){
        goto out_with_close_hd;
    }
    ret = evr_ok;
 out_with_close_hd:
    evr_blob_ref_close(hd);
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close storage connection.");
        ret = evr_error;
    }
 out_with_close_f:
    if(f.close(&f) != 0){
        evr_panic("Unable to close file");
        ret = evr_error;
    }
 out:
    return ret;
}

#ifdef EVR_HAS_HTTPD
static const char evr_httpd_not_found[] = "Endpoint not found";
static const char evr_httpd_unauthorized[] = "No Bearer Authorization header with valid auth-token provided";
static const char evr_httpd_server_error[] = "Internal server error";
static const char evr_httpd_ending[] = "Service is being stopped";

static enum MHD_Result evr_httpd_handle_search(struct MHD_Connection *c);

static const char evr_httpd_search_path[] = "/search";

static enum MHD_Result evr_attr_index_handle_http_request(void *cls, struct MHD_Connection *c, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls){
    int res, is_get;
    log_debug("http request %s %s", method, url);
    res = evr_httpd_check_authentication(c, cfg->auth_token);
    if(res == evr_user_data_invalid) {
        return evr_httpd_respond_static_msg(c, 401, evr_httpd_unauthorized, server_name);
    } else if(res != evr_ok) {
        return evr_httpd_respond_static_msg(c, 500, evr_httpd_server_error, server_name);
    }
    // after this point the request is authenticated
    is_get = strcmp(method, "GET") == 0;
    if(is_get && strcmp(url, evr_httpd_search_path) == 0){
        return evr_httpd_handle_search(c);
    }
    return evr_httpd_respond_static_msg(c, 404, evr_httpd_not_found, server_name);
}

static int evr_httpd_handle_search_status(void *ctx, int parse_res, char *parse_error);
static struct MHD_Response *evr_httpd_create_heap_buffer_response(struct evr_file_mem *fm);

static enum MHD_Result evr_httpd_handle_search(struct MHD_Connection *c){
    int ret = evr_error, res;
    enum MHD_Result mhd_ret;
    const char *search_query;
    evr_blob_ref index_ref;
    evr_blob_ref_str index_ref_str;
    struct evr_attr_index_db *db;
    struct evr_connection con = { 0 };
    struct evr_search_ctx sctx = { &con, 0 };
    struct MHD_Response *resp;
    struct evr_file_mem fm = { 0 };
    search_query = MHD_lookup_connection_value(c, MHD_GET_ARGUMENT_KIND, "q");
    if(!search_query){
        search_query = "";
    }
    log_debug("http server retrieved query: %s", search_query);
    res = evr_get_current_index_ref(index_ref);
    if(res == evr_end){
        ret = evr_end;
        goto out_with_response;
    }
    if(res != evr_ok){
        goto out_with_response;
    }
    evr_fmt_blob_ref(index_ref_str, index_ref);
    log_debug("http server is using index %s for query", index_ref_str);
    db = evr_open_attr_index_db(cfg, index_ref_str, evr_write_blob_to_file, NULL);
    if(!db){
        goto out_with_response;
    }
    if(evr_init_file_mem(&fm, 64*1024, 1*1024*1024) != evr_ok){
        goto out_with_free_db;
    }
    evr_file_bind_file_mem(&sctx.con->socket, &fm);
    if(evr_attr_query_claims(db, search_query, evr_httpd_handle_search_status, evr_respond_search_result, &sctx) != evr_ok){
        goto out_with_free_db;
    }
    if(sctx.parse_res == evr_ok){
        ret = evr_ok;
    } else {
        // the syntax of the query expression was invalid
        ret = evr_user_data_invalid;
    }
 out_with_free_db:
    if(evr_free_attr_index_db(db) != evr_ok){
        ret = evr_error;
    }
 out_with_response:
    if(ret == evr_ok){
        resp = evr_httpd_create_heap_buffer_response(&fm);
        if(!resp){
            log_error("Unable to produce search results http response");
            ret = evr_error;
            goto out;
        }
        // after this outcome we don't evr_destroy_file_mem because
        // MHD_queue_response will free the buffer
        mhd_ret = MHD_queue_response(c, 200, resp);
        MHD_destroy_response(resp);
        return mhd_ret;
    } else if(ret == evr_end){
        evr_destroy_file_mem(&fm);
        return evr_httpd_respond_static_msg(c, 503, evr_httpd_ending, server_name);
    } else if(ret == evr_user_data_invalid){
        // the syntax of the query expression was invalid
        resp = evr_httpd_create_heap_buffer_response(&fm);
        if(!resp){
            log_error("Unable to produce illegal syntax http response");
            ret = evr_error;
            goto out;
        }
        // after this outcome we don't evr_destroy_file_mem because
        // MHD_queue_response will free the buffer
        mhd_ret = MHD_queue_response(c, 400, resp);
        MHD_destroy_response(resp);
        return mhd_ret;
    }
 out:
    evr_destroy_file_mem(&fm);
    return evr_httpd_respond_static_msg(c, 500, evr_httpd_server_error, server_name);
}

static int evr_httpd_handle_search_status(void *_ctx, int parse_res, char *parse_error){
    struct evr_search_ctx *ctx = _ctx;
    ssize_t parse_error_len;
    ctx->parse_res = parse_res;
    if(parse_res != evr_ok){
        parse_error_len = strlen(parse_error);
        if(ctx->con->socket.write(&ctx->con->socket, parse_error, parse_error_len) != parse_error_len){
            // we "know" that we write into a in memory file and also
            // we write only a few bytes. so we don't try multiple
            // times if we can't write all the bytes as permitted by
            // the write API.
            return evr_error;
        }
    }
    return evr_ok;
}

static struct MHD_Response *evr_httpd_create_heap_buffer_response(struct evr_file_mem *fm){
    struct MHD_Response *resp;
    resp = MHD_create_response_from_buffer(fm->used_size, (void*)fm->data, MHD_RESPMEM_MUST_FREE);
    if(!resp){
        return NULL;
    }
    // TODO what is the charset of our data? we should add it so that browser's wont start guessing
    if(evr_add_std_http_headers(resp, server_name, "text/plain") != evr_ok){
        goto fail_with_destroy_resp;
    }
    return resp;
 fail_with_destroy_resp:
    MHD_destroy_response(resp);
    return NULL;
}
#endif
