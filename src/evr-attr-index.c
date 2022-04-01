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

#include "basics.h"
#include "claims.h"
#include "errors.h"
#include "logger.h"
#include "evr-glacier-client.h"
#include "signatures.h"
#include "server.h"
#include "attr-index-db-configuration.h"
#include "attr-index-db.h"
#include "configurations.h"

sig_atomic_t running = 1;
mtx_t stop_lock;
cnd_t stop_signal;

/**
 * watch_overlap defines the overlap of claim watches in seconds.
 */
#define watch_overlap (10 * 60)
#define apply_watch_overlap(t) (t <= watch_overlap ? 0 : t - watch_overlap)

struct evr_attr_index_db_configuration *cfg;

struct evr_handover_ctx {
    int occupied;
    mtx_t lock;
    cnd_t on_push_spec;
    cnd_t on_empty_spec;
};

struct evr_attr_spec_handover_ctx {
    struct evr_handover_ctx handover;

    struct evr_attr_spec_claim *claim;
    evr_blob_ref claim_key;
    time_t created;
};

struct evr_index_handover_ctx {
    struct evr_handover_ctx handover;

    evr_blob_ref index_ref;
};

void handle_sigterm(int signum);
struct evr_attr_index_db_configuration *evr_load_attr_index_db_cfg();
#define evr_init_attr_spec_handover_ctx(ctx) evr_init_handover_ctx(&(ctx)->handover)
int evr_free_attr_spec_handover_ctx(struct evr_attr_spec_handover_ctx *ctx);
#define evr_init_index_handover_ctx(ctx) evr_init_handover_ctx(&(ctx)->handover)
#define evr_free_index_handover_ctx(ctx) evr_free_handover_ctx(&(ctx)->handover)

int evr_init_handover_ctx(struct evr_handover_ctx *ctx);
int evr_free_handover_ctx(struct evr_handover_ctx *ctx);
int evr_stop_handover(struct evr_handover_ctx *ctx);
int evr_wait_for_handover_available(struct evr_handover_ctx *ctx);
int evr_wait_for_handover_occupied(struct evr_handover_ctx *ctx);
int evr_lock_handover(struct evr_handover_ctx *ctx);
int evr_occupy_handover(struct evr_handover_ctx *ctx);
int evr_empty_handover(struct evr_handover_ctx *ctx);

int evr_watch_index_claims_worker(void *arg);
int evr_build_index_worker(void *arg);
int evr_index_sync_worker(void *arg);
int evr_bootstrap_db(evr_blob_ref claim_key, struct evr_attr_spec_claim *spec);
int evr_index_claim_set(struct evr_attr_index_db *db, xsltStylesheetPtr stylesheet, evr_blob_ref claim_set_ref, time_t claim_set_last_modified, int *c);
int evr_attr_index_tcp_server();

int main(){
    int ret = evr_error;
    cfg = evr_load_attr_index_db_cfg();
    if(!cfg){
        goto out;
    }
    if(mtx_init(&stop_lock, mtx_plain) != thrd_success){
        goto out_with_free_cfg;
    }
    if(cnd_init(&stop_signal) != thrd_success){
        goto out_with_free_stop_lock;
    }
    {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_sigterm;
        sigaction(SIGINT, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    if(sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK){
        // read https://sqlite.org/threadsafe.html if you run into
        // this error
        log_error("Failed to configure multi-threaded mode for sqlite3");
        goto out_with_free_stop_lock;
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
    if(thrd_create(&tcp_server_thrd, evr_attr_index_tcp_server, &index_handover_ctx) != thrd_success){
        goto out_with_join_index_sync_thrd;
    }
    if(mtx_lock(&stop_lock) != thrd_success){
        evr_panic("Failed to lock stop lock");
        goto out_with_join_watch_index_claims_thrd;
    }
    while(running){
        if(cnd_wait(&stop_signal, &stop_lock) != thrd_success){
            evr_panic("Failed to wait for stop signal");
            goto out_with_join_watch_index_claims_thrd;
        }
    }
    if(mtx_unlock(&stop_lock) != thrd_success){
        evr_panic("Failed to unlock stop lock");
        goto out_with_join_watch_index_claims_thrd;
    }
    if(evr_stop_handover(&index_handover_ctx.handover) != evr_ok){
        goto out_with_join_watch_index_claims_thrd;
    }
    if(evr_stop_handover(&attr_spec_handover_ctx.handover) != evr_ok){
        goto out_with_join_watch_index_claims_thrd;
    }
    ret = evr_ok;
    int thrd_res;
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
    cnd_destroy(&stop_signal);
 out_with_free_stop_lock:
    mtx_destroy(&stop_lock);
 out_with_free_cfg:
    evr_free_attr_index_db_configuration(cfg);
 out:
    return ret;
}

struct evr_attr_index_db_configuration *evr_load_attr_index_db_cfg(){
    struct evr_attr_index_db_configuration *cfg = evr_create_attr_index_db_configuration();
    const char *config_paths[] = {
        "~/.config/everarch/attr-index.json",
        "attr-index.json",
    };
    if(evr_load_configurations(cfg, config_paths, sizeof(config_paths) / sizeof(char*), evr_merge_attr_index_db_configuration, evr_expand_attr_index_db_configuration) != evr_ok){
        log_error("Failed to load configuration");
        goto out_with_free_cfg;
    }
    return cfg;
 out_with_free_cfg:
    evr_free_attr_index_db_configuration(cfg);
    return NULL;
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

int evr_init_handover_ctx(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    ctx->occupied = 0;
    if(mtx_init(&ctx->lock, mtx_plain) != thrd_success){
        goto out;
    }
    if(cnd_init(&ctx->on_push_spec) != thrd_success){
        goto out_with_free_lock;
    }
    if(cnd_init(&ctx->on_empty_spec) != thrd_success){
        goto out_with_free_on_push_spec;
    }
    ret = evr_ok;
 out:
    return ret;
 out_with_free_on_push_spec:
    cnd_destroy(&ctx->on_push_spec);
 out_with_free_lock:
    mtx_destroy(&ctx->lock);
    return ret;
}

int evr_free_handover_ctx(struct evr_handover_ctx *ctx){
    cnd_destroy(&ctx->on_empty_spec);
    cnd_destroy(&ctx->on_push_spec);
    mtx_destroy(&ctx->lock);
    return evr_ok;
}

int evr_stop_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    if(cnd_signal(&ctx->on_push_spec) != thrd_success){
        evr_panic("Failed to signal on_push on termination");
        goto out;
    }
    if(cnd_signal(&ctx->on_empty_spec) != thrd_success){
        evr_panic("Failed to signal on_empty on termination");
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_wait_for_handover_available(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    if(evr_lock_handover(ctx) != evr_ok){
        evr_panic("Failed to lock handover lock");
        goto out;
    }
    while(ctx->occupied){
        if(!running){
            if(mtx_unlock(&ctx->lock) != thrd_success){
                evr_panic("Failed to unlock handover lock");
                goto out;
            }
            break;
        }
        if(cnd_wait(&ctx->on_empty_spec, &ctx->lock) != thrd_success){
            evr_panic("Failed to wait for empty handover signal");
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_wait_for_handover_occupied(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    if(evr_lock_handover(ctx) != evr_ok){
        evr_panic("Failed to lock handover lock");
        goto out;
    }
    while(!ctx->occupied){
        if(!running){
            if(mtx_unlock(&ctx->lock) != thrd_success){
                evr_panic("Failed to unlock handover lock");
                goto out;
            }
            break;
        }
        if(cnd_wait(&ctx->on_push_spec, &ctx->lock) != thrd_success){
            evr_panic("Failed to wait for handover push");
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_lock_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    if(mtx_lock(&ctx->lock) != thrd_success){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_occupy_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    ctx->occupied = 1;
    if(cnd_signal(&ctx->on_push_spec) != thrd_success){
        evr_panic("Failed to signal spec pushed on occupy");
        goto out;
    }
    if(mtx_unlock(&ctx->lock) != thrd_success){
        evr_panic("Failed to unlock handover lock on occupy");
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_empty_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    ctx->occupied = 0;
    if(cnd_signal(&ctx->on_empty_spec) != thrd_success){
        evr_panic("Failed to signal handover empty");
        goto out;
    }
    if(mtx_unlock(&ctx->lock) != thrd_success){
        evr_panic("Failed to unlock handover lock on empty");
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_watch_index_claims_worker(void *arg){
    int ret = evr_error;
    struct evr_attr_spec_handover_ctx *ctx = arg;
    log_debug("Started watch index claims worker");
    // cw is the connection used for watching for blob changes.
    int cw = evr_connect_to_storage();
    if(cw < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out;
    }
    struct evr_blob_filter filter;
    filter.flags_filter = evr_blob_flag_index_rule_claim;
    filter.last_modified_after = 0;
    if(evr_req_cmd_watch_blobs(cw, &filter) != evr_ok){
        goto out_with_close_cw;
    }
    struct evr_watch_blobs_body body;
    struct evr_attr_spec_claim *latest_spec = NULL;
    evr_blob_ref latest_spec_key;
    time_t latest_spec_created = 0;
    // cs is the connection used for finding the most recent
    // attr-spec claim
    int cs = -1;
    log_debug("Watching index claims");
    fd_set active_fd_set;
    struct timeval timeout;
    while(running){
        FD_ZERO(&active_fd_set);
        FD_SET(cw, &active_fd_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int sret = select(cw + 1, &active_fd_set, NULL, NULL, &timeout);
        if(sret < 0){
            goto out_with_close_cw;
        }
        if(!running){
            ret = evr_ok;
            goto out_with_close_cw;
        }
        if(sret == 0){
            continue;
        }
        if(evr_read_watch_blobs_body(cw, &body) != evr_ok){
            goto out_with_free_latest_spec;
        }
#ifdef EVR_LOG_INFO
        do {
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_info("Checking index claim %s for attr-spec", fmt_key);
        } while(0);
#endif
        if(cs == -1){
            cs = evr_connect_to_storage();
            if(cs < 0){
                log_error("Failed to connect to evr-glacier-storage server");
                goto out_with_free_latest_spec;
            }
        }
        xmlDocPtr claim_doc = evr_fetch_signed_xml(cs, body.key);
        if(!claim_doc){
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
        time_t created;
        if(evr_parse_created(&created, cs_node) != evr_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, body.key);
            log_error("Failed to parse created date from claim-set for blob key %s", fmt_key);
            goto out_with_free_claim_doc;
        }
        if(latest_spec == NULL || created > latest_spec_created){
            xmlNode *c_node = evr_find_next_element(evr_first_claim(cs_node), "attr-spec");
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
        close(cs);
        cs = -1;
        if(evr_wait_for_handover_available(&ctx->handover) != evr_ok){
            goto out_with_free_latest_spec;
        }
        if(!running){
            break;
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
    if(cs >= 0){
        close(cs);
    }
 out_with_close_cw:
    close(cw);
 out:
    log_debug("Ended watch index claims worker with result %d", ret);
    return ret;
}

int evr_build_index_worker(void *arg){
    int ret = evr_error;
    void **evr_build_index_worker_ctx = arg;
    struct evr_attr_spec_handover_ctx *sctx = evr_build_index_worker_ctx[0];
    struct evr_index_handover_ctx *ictx = evr_build_index_worker_ctx[1];
    log_debug("Started build index worker");
    while(running){
        if(evr_wait_for_handover_occupied(&sctx->handover) != evr_ok){
            goto out;
        }
        if(!running){
            break;
        }
        struct evr_attr_spec_claim *claim = sctx->claim;
        evr_blob_ref claim_key;
        memcpy(claim_key, sctx->claim_key, evr_blob_ref_size);
        // TODO time_t created = sctx->created;;
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
        if(evr_bootstrap_db(claim_key, claim) != evr_ok){
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
        if(evr_wait_for_handover_available(&ictx->handover) != evr_ok){
            goto out;
        }
        if(!running){
            break;
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
    log_debug("Ended build index worker with result %d", ret);
    return ret;
}

int evr_bootstrap_db(evr_blob_ref claim_key, struct evr_attr_spec_claim *spec){
    int ret = evr_error;
    evr_blob_ref_str claim_key_str;
    evr_fmt_blob_ref(claim_key_str, claim_key);
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, claim_key_str);
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
    int cw = evr_connect_to_storage();
    if(cw < 0){
        log_error("Failed to connect to evr-glacier-storage server");
        goto out_with_free_db;
    }
    xsltStylesheetPtr style = evr_fetch_stylesheet(cw, spec->stylesheet_blob_ref);
    if(!style){
        goto out_with_close_cw;
    }
    sqlite3_int64 last_indexed_claim_ts;
    if(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &last_indexed_claim_ts) != evr_ok){
        goto out_with_free_style;
    }
    struct evr_blob_filter filter;
    filter.flags_filter = evr_blob_flag_claim;
    filter.last_modified_after = apply_watch_overlap(last_indexed_claim_ts);
    if(evr_req_cmd_watch_blobs(cw, &filter) != evr_ok){
        goto out_with_free_style;
    }
    struct evr_watch_blobs_body wbody;
    fd_set active_fd_set;
    int cs = -1;
    struct timeval timeout;
    while(running){
        FD_ZERO(&active_fd_set);
        FD_SET(cw, &active_fd_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int sret = select(cw + 1, &active_fd_set, NULL, NULL, &timeout);
        if(sret < 0){
            goto out_with_close_cs;
        }
        if(!running){
            ret = evr_ok;
            goto out_with_close_cs;
        }
        if(sret == 0){
            continue;
        }
        if(evr_read_watch_blobs_body(cw, &wbody) != evr_ok){
            goto out_with_close_cs;
        }
        if(evr_index_claim_set(db, style, wbody.key, wbody.last_modified, &cs) != evr_ok){
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
    if(cs >= 0){
        close(cs);
    }
 out_with_free_style:
    xsltFreeStylesheet(style);
 out_with_close_cw:
    close(cw);
 out_with_free_db:
    if(evr_free_attr_index_db(db) != evr_ok){
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_index_claim_set(struct evr_attr_index_db *db, xsltStylesheetPtr style, evr_blob_ref claim_set_ref, time_t claim_set_last_modified, int *c){
    int ret = evr_error;
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_debug("Indexing claim set %s", ref_str);
    }
#endif
    if(*c == -1){
        *c = evr_connect_to_storage();
        if(*c < 0){
            log_error("Failed to connect to evr-glacier-storage server");
            goto out;
        }
    }
    xmlDocPtr claim_set = evr_fetch_signed_xml(*c, claim_set_ref);
    if(!claim_set){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("Claim set not fetchable for blob key %s", ref_str);
        goto out;
    }
    if(evr_merge_attr_index_claim_set(db, style, claim_set_ref, claim_set_last_modified, claim_set) != evr_ok){
        goto out_with_free_claim_set;
    }
    ret = evr_ok;
 out_with_free_claim_set:
    xmlFreeDoc(claim_set);
 out:
    return ret;
}

int evr_index_sync_worker(void *arg){
    int ret = evr_error;
    struct evr_index_handover_ctx *ctx = arg;
    log_debug("Started index sync worker");
    if(evr_wait_for_handover_occupied(&ctx->handover) != evr_ok){
        goto out;
    }
    evr_blob_ref index_ref;
    memcpy(index_ref, ctx->index_ref, evr_blob_ref_size);
    if(evr_empty_handover(&ctx->handover) != evr_ok){
        goto out;
    }
    int cg = -1; // connection get
    int cw = -1; // connection watch
    struct evr_attr_index_db *db = NULL;
    fd_set active_fd_set;
    struct timeval timeout;
    struct evr_watch_blobs_body wbody;
    xsltStylesheetPtr style = NULL;
    while(running){
        if(evr_lock_handover(&ctx->handover) != evr_ok){
            goto out_with_free;
        }
        if(ctx->handover.occupied){
            if(cw != -1){
#ifdef EVR_LOG_DEBUG
                evr_blob_ref_str index_ref_str;
                evr_fmt_blob_ref(index_ref_str, index_ref);
                log_debug("Index sync worker stop index %s", index_ref_str);
#endif
                close(cw);
                cw = -1;
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
        if(cw == -1){
            if(style){
                xsltFreeStylesheet(style);
                style = NULL;
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
            db = evr_open_attr_index_db(cfg, index_ref_str);
            if(!db){
                goto out_with_free;
            }
            cw = evr_connect_to_storage();
            if(cw < 0){
                log_error("Failed to connect to evr-glacier-storage server");
                goto out_with_free;
            }
            if(evr_prepare_attr_index_db(db) != evr_ok){
                goto out_with_free;
            }
            xmlDocPtr cs_doc = evr_fetch_signed_xml(cw, index_ref);
            if(!cs_doc){
                evr_blob_ref_str fmt_key;
                evr_fmt_blob_ref(fmt_key, index_ref);
                log_error("Index claim not fetchable for blob key %s", fmt_key);
                goto out_with_free;
            }
            xmlNode *cs_node = evr_get_root_claim_set(cs_doc);
            if(!cs_node){
                goto out_with_free_cs_doc;
            }
            xmlNode *c_node = evr_find_next_element(evr_first_claim(cs_node), "attr-spec");
            if(!c_node){
                goto out_with_free_cs_doc;
            }
            struct evr_attr_spec_claim *spec = evr_parse_attr_spec_claim(c_node);
            xmlFree(cs_doc);
            if(!spec){
                goto out_with_free;
            }
            style = evr_fetch_stylesheet(cw, spec->stylesheet_blob_ref);
            free(spec);
            if(!style){
                goto out_with_free;
            }
            sqlite3_int64 last_indexed_claim_ts;
            if(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &last_indexed_claim_ts) != evr_ok){
                goto out_with_free;
            }
            struct evr_blob_filter filter;
            filter.flags_filter = evr_blob_flag_claim;
            filter.last_modified_after = apply_watch_overlap(last_indexed_claim_ts);
            if(evr_req_cmd_watch_blobs(cw, &filter) != evr_ok){
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
        FD_ZERO(&active_fd_set);
        FD_SET(cw, &active_fd_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int sret = select(cw + 1, &active_fd_set, NULL, NULL, &timeout);
        if(sret < 0){
            goto out_with_free;
        }
        if(!running){
            break;
        }
        if(sret == 0){
            // TODO close cg after n timeouts in a row and set to -1
            continue;
        }
        if(evr_read_watch_blobs_body(cw, &wbody) != evr_ok){
            goto out_with_free;
        }
        if(evr_index_claim_set(db, style, wbody.key, wbody.last_modified, &cg) != evr_ok){
            goto out_with_free;
        }
    }
    ret = evr_ok;
 out_with_free:
    if(cg >= 0){
        close(cg);
    }
    if(cw >= 0){
        close(cw);
    }
    if(style){
        xsltFreeStylesheet(style);
    }
    if(db){
        if(evr_free_attr_index_db(db) != evr_ok){
            ret = evr_error;
        }
    }
 out:
    log_debug("Ended index sync worker with result %d", ret);
    return ret;
}

int evr_attr_index_tcp_server(){
    int ret = evr_error;
    int s = evr_make_tcp_socket(evr_glacier_attr_index_port);
    if(s < 0){
        log_error("Failed to create socket");
        goto out;
    }
    if(listen(s, 7) < 0){
        log_error("Failed to listen on localhost:%d", evr_glacier_attr_index_port);
        goto out_with_close_s;
    }
    log_info("Listening on localhost:%d", evr_glacier_attr_index_port);
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
        // TODO check active_fd_set and accept connection
    }
    ret = evr_ok;
 out_with_close_s:
    close(s);
 out:
    return ret;
}
