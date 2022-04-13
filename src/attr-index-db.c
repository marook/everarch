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

#include "attr-index-db.h"

#include <stdlib.h>
#include <string.h>
#include <libxslt/transform.h>
#include <threads.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "dyn-mem.h"
#include "basics.h"
#include "logger.h"
#include "errors.h"
#include "db.h"
#include "attr-query-parser.h"
#include "attr-query-lexer.h"
#include "attr-query-sql.h"
#include "subprocess.h"
#include "files.h"

struct evr_attr_index_db *evr_init_attr_index_db(struct evr_attr_index_db *db);
int evr_attr_index_update_valid_until(sqlite3 *db, sqlite3_stmt *update_stmt, int rowid, evr_time valid_until);
int evr_attr_index_bind_find_siblings(sqlite3_stmt *find_stmt, evr_claim_ref ref, char *key, evr_time t);
int evr_get_attr_type_for_key(struct evr_attr_index_db *db, int *attr_type, char *key);
int evr_insert_attr(struct evr_attr_index_db *db, evr_claim_ref ref, char *key, char* value, evr_time valid_from, int is_valid_until, evr_time valid_until, int trunc);

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name, evr_blob_file_writer blob_file_writer, void *blob_file_writer_ctx){
    const char slash = '/';
    size_t slash_len = 1;
    size_t state_dir_path_len = strlen(cfg->state_dir_path);
    size_t name_len = strlen(name);
    size_t dir_size = state_dir_path_len + slash_len + name_len + slash_len + 1;
    struct evr_attr_index_db *db = malloc(sizeof(struct evr_attr_index_db) + dir_size);
    if(!db){
        return NULL;
    }
    db->dir = (char*)&db[1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, db->dir);
    evr_push_n(&bp, cfg->state_dir_path, state_dir_path_len);
    if(state_dir_path_len > 0 && cfg->state_dir_path[state_dir_path_len - 1] != slash){
        evr_push_as(&bp, &slash, char);
    }
    evr_push_n(&bp, name, name_len);
    evr_push_as(&bp, &slash, char);
    evr_push_eos(&bp);
    if(mkdir(db->dir, 0755)){
        // there is a chance that the dir already exists an hopefully
        // is not a file. if it is a file the sqlite open later will
        // fail.
        if(errno != EEXIST){
            log_error("Failed to create attr-index-db directory %s", db->dir);
            free(db);
            return NULL;
        }
    }
    db->blob_file_writer = blob_file_writer;
    db->blob_file_writer_ctx = blob_file_writer_ctx;
    return evr_init_attr_index_db(db);
}

struct evr_attr_index_db *evr_fork_attr_index_db(struct evr_attr_index_db *odb){
    size_t dir_size = strlen(odb->dir) + 1;
    struct evr_attr_index_db *fdb = malloc(sizeof(struct evr_attr_index_db) + dir_size);
    if(!fdb){
        return NULL;
    }
    fdb->dir = (char*)&fdb[1];
    memcpy(fdb->dir, odb->dir, dir_size);
    fdb->blob_file_writer = odb->blob_file_writer;
    fdb->blob_file_writer_ctx = odb->blob_file_writer_ctx;
    return evr_init_attr_index_db(fdb);
}

struct evr_attr_index_db *evr_init_attr_index_db(struct evr_attr_index_db *db){
    db->db = NULL;
    db->find_state = NULL;
    db->update_state = NULL;
    db->find_attr_type_for_key = NULL;
    db->find_past_attr_siblings = NULL;
    db->find_future_attr_siblings = NULL;
    db->insert_attr = NULL;
    db->insert_claim = NULL;
    db->insert_claim_set = NULL;
    db->update_attr_valid_until = NULL;
    db->find_ref_attrs = NULL;
    size_t dir_len = strlen(db->dir);
    const char filename[] = "index.db";
    char db_path[dir_len + sizeof(filename)];
    memcpy(db_path, db->dir, dir_len);
    memcpy(&db_path[dir_len], filename, sizeof(filename));
    int db_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
    if(sqlite3_open_v2(db_path, &db->db, db_flags, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db->db);
        log_error("Could not open %s sqlite database for attr-index: %s", db->dir, sqlite_error_msg);
        goto out_with_free_db;
    }
    if(sqlite3_busy_timeout(db->db, evr_sqlite3_busy_timeout) != SQLITE_OK){
        goto out_with_close_db;
    }
    return db;
 out_with_close_db:
    if(sqlite3_close(db->db) != SQLITE_OK){
        evr_panic("Failed to close attr-index sqlite db");
    }
 out_with_free_db:
    free(db);
    return NULL;
}

#define evr_finalize_stmt(stmt)                         \
    do {                                                \
        if(sqlite3_finalize(db->stmt) != SQLITE_OK){    \
            evr_panic("Could not finalize " #stmt);     \
            goto out;                                   \
        }                                               \
    } while(0)

int evr_free_attr_index_db(struct evr_attr_index_db *db){
    int ret = evr_error;
    evr_finalize_stmt(find_ref_attrs);
    evr_finalize_stmt(update_attr_valid_until);
    evr_finalize_stmt(insert_claim_set);
    evr_finalize_stmt(insert_claim);
    evr_finalize_stmt(insert_attr);
    evr_finalize_stmt(find_future_attr_siblings);
    evr_finalize_stmt(find_past_attr_siblings);
    evr_finalize_stmt(find_attr_type_for_key);
    evr_finalize_stmt(update_state);
    evr_finalize_stmt(find_state);
    if(sqlite3_close(db->db) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db->db);
        log_error("Could not close attr-index database: %s", sqlite_error_msg);
        goto out;
    }
    free(db);
    ret = evr_ok;
 out:
    return ret;
}

#undef evr_finalize_stmt

int evr_attr_index_get_state(struct evr_attr_index_db *db, int key, sqlite3_int64 *value){
    int ret = evr_error;
    if(sqlite3_bind_int(db->find_state, 1, key) != SQLITE_OK){
        goto out_with_reset_find_state;
    }
    if(evr_step_stmt(db->db, db->find_state) != SQLITE_ROW){
        goto out_with_reset_find_state;
    }
    *value = sqlite3_column_int64(db->find_state, 0);
    ret = evr_ok;
 out_with_reset_find_state:
    if(sqlite3_reset(db->find_state) != SQLITE_OK){
        evr_panic("Failed to reset find state statement");
        ret = evr_error;
    }
    return ret;
}

int evr_attr_index_set_state(struct evr_attr_index_db *db, int key, sqlite3_int64 value){
    int ret = evr_error;
    if(sqlite3_bind_int64(db->update_state, 1, value) != SQLITE_OK){
        goto out_with_reset_update_state;
    }
    if(sqlite3_bind_int(db->update_state, 2, key) != SQLITE_OK){
        goto out_with_reset_update_state;
    }
    if(evr_step_stmt(db->db, db->update_state) != SQLITE_DONE){
        goto out_with_reset_update_state;
    }
    ret = evr_ok;
 out_with_reset_update_state:
    if(sqlite3_reset(db->update_state) != SQLITE_OK){
        evr_panic("Failed to reset find state statement");
        ret = evr_error;
    }
    return ret;
}

#define attr_index_db_version 1

int evr_setup_attr_index_db(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec){
    int ret = evr_error;
    int db_setup = 0;
    char *error = NULL;
    if(sqlite3_exec(db->db, "select 1 from v" to_string(attr_index_db_version) "", NULL, NULL, NULL) == SQLITE_OK){
        db_setup = 1;
        log_debug("attr-index db already setup");
        goto prepare;
    }
    const char *sql[] = {
        "create table attr_def (key text primary key not null, type integer not null)",
        "create table attr (ref blob not null, key text not null, val_str text, val_int integer, valid_from integer not null, valid_until integer, trunc integer not null)",
        "create table claim (ref blob primary key not null)",
        "create table state (key integer primary key, value integer not null)",
        "insert into state (key, value) values (" to_string(evr_state_key_last_indexed_claim_ts) ", 0)",
        "insert into state (key, value) values (" to_string(evr_state_key_stage) ", " to_string(evr_attr_index_stage_initial) ")",
        "create table claim_set (ref blob primary key not null)",
        NULL
    };
    for(size_t i = 0; ; ++i){
        const char *s = sql[i];
        if(!s){
            break;
        }
        if(sqlite3_exec(db->db, s, NULL, NULL, &error) != SQLITE_OK){
            log_error("Failed to create attr-index db using \"%s\": %s", s, error);
            goto out_with_free_error;
        }
    }
    sqlite3_stmt *insert_attr_def;
 prepare:
    if(sqlite3_prepare_v2(db->db, "insert into attr_def (key, type) values (?, ?)", -1, &insert_attr_def, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db->db);
        log_error("Failed to prepare insert attr_def statement: %s", sqlite_error_msg);
        goto out;
    }
    if(!db_setup){
        struct evr_attr_def *attr_def_end = &spec->attr_def[spec->attr_def_len];
        for(struct evr_attr_def *ad = spec->attr_def; ad != attr_def_end; ++ad){
            if(sqlite3_bind_text(insert_attr_def, 1, ad->key, -1, NULL) != SQLITE_OK){
                goto out_with_free_insert_attr_def;
            }
            if(sqlite3_bind_int(insert_attr_def, 2, ad->type) != SQLITE_OK){
                goto out_with_free_insert_attr_def;
            }
            if(sqlite3_step(insert_attr_def) != SQLITE_DONE){
                goto out_with_free_insert_attr_def;
            }
            if(sqlite3_reset(insert_attr_def) != SQLITE_OK){
                goto out_with_free_insert_attr_def;
            }
        }
        if(sqlite3_exec(db->db, "create table v" to_string(attr_index_db_version) " (x integer)", NULL, NULL, &error) != SQLITE_OK){
            log_error("Failed to mark attr index db as prepared: %s", error);
            goto out_with_free_insert_attr_def;
        }
    }
    ret = evr_ok;
 out_with_free_insert_attr_def:
    if(sqlite3_finalize(insert_attr_def) != SQLITE_OK){
        ret = evr_error;
    }
 out_with_free_error:
    if(error){
        sqlite3_free(error);
    }
 out:
    return ret;
}

int evr_append_attr_factory_claims(struct evr_attr_index_db *db, xmlDocPtr raw_claim_set_doc, struct evr_attr_spec_claim *spec, evr_blob_ref claim_set_ref);

int evr_merge_attr_index_claim_set(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_blob_ref claim_set_ref, evr_time claim_set_last_modified, xmlDocPtr raw_claim_set_doc){
    int ret = evr_error;
    if(sqlite3_bind_blob(db->insert_claim_set, 1, claim_set_ref, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert_claim_set;
    }
    // sqlite3_step is called here instead of evr_step_stmt because we
    // don't want evr_step_stmt to report SQLITE_CONSTRAINT result as
    // an error.
    int step_res = sqlite3_step(db->insert_claim_set);
    if(step_res == SQLITE_CONSTRAINT){
        // SQLITE_CONSTRAINT is ok because it most likely tells us
        // that the same row already exists.
        {
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_debug("Claim set %s already indexed", ref_str);
        }
        ret = evr_ok;
        goto out_with_reset_insert_claim_set;
    }
    if(step_res != SQLITE_DONE){
        goto out_with_reset_insert_claim_set;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_debug("Indexing claim set %s", ref_str);
    }
#endif
    if(evr_add_claim_ref_attrs(raw_claim_set_doc, claim_set_ref) != evr_ok){
        goto out_with_reset_insert_claim_set;
    }
    if(evr_append_attr_factory_claims(db, raw_claim_set_doc, spec, claim_set_ref) != evr_ok){
        goto out_with_reset_insert_claim_set;
    }
    const char *xslt_params[] = {
        NULL
    };
    xmlDocPtr claim_set_doc = xsltApplyStylesheet(style, raw_claim_set_doc, xslt_params);
    if(!claim_set_doc){
        goto out_with_reset_insert_claim_set;
    }
    xmlNode *cs_node = evr_get_root_claim_set(claim_set_doc);
    if(!cs_node){
#ifdef EVR_LOG_INFO
        {
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_info("Transformed claim set blob %s does not contain claim-set element", ref_str);
        }
#endif
        ret = evr_ok;
        goto out_with_free_claim_set_doc;
    }
    evr_time created;
    if(evr_parse_created(&created, cs_node) != evr_ok){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("Failed to parse created date from transformed claim-set for blob ref %s", ref_str);
        goto out_with_free_claim_set_doc;
    }
    xmlNode *c_node = evr_first_claim(cs_node);
    struct evr_attr_claim *attr;
    while(c_node){
        c_node = evr_find_next_element(c_node, "attr");
        if(!c_node){
            break;
        }
        attr = evr_parse_attr_claim(c_node);
        if(!attr){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_error("Failed to parse attr claim from transformed claim-set for blob with ref %s", ref_str);
            goto out_with_free_claim_set_doc;
        }
        if(attr->ref_type == evr_ref_type_self){
            evr_build_claim_ref(attr->ref, claim_set_ref, attr->claim_index);
            attr->ref_type = evr_ref_type_claim;
        }
        int merge_res = evr_merge_attr_index_claim(db, created, attr);
        free(attr);
        if(merge_res != evr_ok){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_error("Failed to merge attr claim from transformed claim-set for blob with ref %s into attr index", ref_str);
            goto out_with_free_claim_set_doc;
        }
        c_node = c_node->next;
    }
    if(evr_attr_index_set_state(db, evr_state_key_last_indexed_claim_ts, claim_set_last_modified) != evr_ok){
        goto out_with_free_claim_set_doc;
    }
    ret = evr_ok;
 out_with_free_claim_set_doc:
    xmlFreeDoc(claim_set_doc);
    int reset_res;
 out_with_reset_insert_claim_set:
    reset_res = sqlite3_reset(db->insert_claim_set);
    if(reset_res != SQLITE_OK && reset_res != SQLITE_CONSTRAINT){
        evr_panic("Failed to reset insert_claim_set statement");
        ret = evr_error;
    }
    return ret;
}

struct evr_append_attr_factory_claims_worker_ctx {
    struct evr_attr_index_db *db;
    char *claim_set;
    size_t claim_set_len;
    evr_blob_ref claim_set_ref;
    evr_blob_ref attr_factory;
    int res;
    xmlDocPtr built_doc;
};

int evr_append_attr_factory_claims_worker(void *context);

int evr_merge_claim_set_docs(xmlDocPtr dest, xmlDocPtr src, char *dest_name, char *src_name);

int evr_append_attr_factory_claims(struct evr_attr_index_db *db, xmlDocPtr raw_claim_set_doc, struct evr_attr_spec_claim *spec, evr_blob_ref claim_set_ref){
    int ret = evr_ok; // BIG OTHER WAY ROUND WARNING!
    thrd_t thrds[spec->attr_factories_len];
    thrd_t *t = thrds;
    struct evr_append_attr_factory_claims_worker_ctx ctxs[spec->attr_factories_len];
    struct evr_append_attr_factory_claims_worker_ctx *c = ctxs;
    evr_blob_ref *af_end = &spec->attr_factories[spec->attr_factories_len];
    char *raw_claim_set = NULL;
    int raw_claim_set_size;
    xmlDocDumpMemoryEnc(raw_claim_set_doc, (xmlChar**)&raw_claim_set, &raw_claim_set_size, "UTF-8");
    if(!raw_claim_set){
        log_error("Failed to format raw claim-set doc");
        goto out;
    }
    for(evr_blob_ref *af = spec->attr_factories; af != af_end; ++af){
        c->db = db;
        c->claim_set = raw_claim_set;
        c->claim_set_len = raw_claim_set_size;
        memcpy(c->claim_set_ref, claim_set_ref, evr_blob_ref_size);
        memcpy(c->attr_factory, af, evr_blob_ref_size);
        c->res = evr_error;
        if(thrd_create(t, evr_append_attr_factory_claims_worker, c) != thrd_success){
            ret = evr_error;
            goto out_with_join_threads;
        }
        ++t;
        ++c;
    }
 out_with_join_threads:
    for(--t; t >= thrds; --t){
        if(thrd_join(*t, NULL) != thrd_success){
            evr_panic("Failed to join attr factory thread");
            ret = evr_error;
            goto out;
        }
    }
    xmlFree(raw_claim_set);
    struct evr_append_attr_factory_claims_worker_ctx *c_end = &ctxs[spec->attr_factories_len];
    if(ret == evr_ok){
        for(c = ctxs; c != c_end; ++c){
            if(c->res != evr_ok){
                evr_blob_ref_str claim_set_ref_str;
                evr_fmt_blob_ref(claim_set_ref_str, c->claim_set_ref);
                evr_blob_ref_str attr_factory_str;
                evr_fmt_blob_ref(attr_factory_str, c->attr_factory);
                log_error("attr-factory %s failed with claim set %s", attr_factory_str, claim_set_ref_str);
                continue;
            }
            if(evr_merge_claim_set_docs(raw_claim_set_doc, c->built_doc, "original", "dynamic") != evr_ok){
                evr_blob_ref_str claim_set_ref_str;
                evr_fmt_blob_ref(claim_set_ref_str, c->claim_set_ref);
                evr_blob_ref_str attr_factory_str;
                evr_fmt_blob_ref(attr_factory_str, c->attr_factory);
                log_error("Failed to merged attr-factory %s's dynamic claim-set for original claim-set %s", attr_factory_str, claim_set_ref_str);
                ret = evr_error;
                goto out_with_free_built_docs;
            }
        }
    }
 out_with_free_built_docs:
    for(c = ctxs; c != c_end; ++c){
        if(c->built_doc){
            xmlFreeDoc(c->built_doc);
        }
    }
 out:
    return ret;
}

int evr_ensure_attr_factory_exe_ready(struct evr_attr_index_db *db, evr_blob_ref attr_factory, char *exe_path);

int evr_append_attr_factory_claims_worker(void *context){
    struct evr_append_attr_factory_claims_worker_ctx *ctx = context;
    size_t dir_len = strlen(ctx->db->dir);
    char exe_path[dir_len + evr_blob_ref_str_size];
    memcpy(exe_path, ctx->db->dir, dir_len);
    evr_fmt_blob_ref(&exe_path[dir_len], ctx->attr_factory);
    if(evr_ensure_attr_factory_exe_ready(ctx->db, ctx->attr_factory, exe_path) != evr_ok){
        goto out;
    }
    evr_blob_ref_str claim_set_ref_str;
    evr_fmt_blob_ref(claim_set_ref_str, ctx->claim_set_ref);
    char *argv[] = {
        exe_path,
        claim_set_ref_str,
        NULL
    };
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str attr_factory_str;
        evr_fmt_blob_ref(attr_factory_str, ctx->attr_factory);
        log_debug("Spawn attr-factory %s for claim-set %s", attr_factory_str, claim_set_ref_str);
    }
#endif
    struct evr_subprocess sp;
    if(evr_spawn(&sp, argv) != evr_ok){
        goto out;
    }
    int write_res = write_n(sp.stdin, ctx->claim_set, ctx->claim_set_len);
    if(write_res != evr_ok && write_res != evr_end){
        goto out_with_join_sp;
    }
    if(close(sp.stdin)){
        goto out_with_join_sp;
    }
    struct dynamic_array *buf = alloc_dynamic_array(32 * 1024);
    if(!buf){
        goto out_with_join_sp;
    }
    int read_res = read_fd(&buf, sp.stdout, evr_max_blob_data_size);
    if(read_res != evr_ok && read_res != evr_end){
        if(buf){
            free(buf);
        }
        goto out_with_join_sp;
    }
    if(!buf){
        goto out_with_join_sp;
    }
    ctx->built_doc = evr_parse_claim_set(buf->data, buf->size_used);
    if(!ctx->built_doc){
        evr_blob_ref_str attr_factory_str;
        evr_fmt_blob_ref(attr_factory_str, ctx->attr_factory);
        char eos = '\0';
        buf = write_n_dynamic_array(buf, &eos, sizeof(eos));
        if(buf){
            log_error("Output from attr-factory %s for claim-set %s not parseable. Output claim set was: %s", attr_factory_str, claim_set_ref_str, buf->data);
            buf->size_used = 0;
        } else {
            log_error("Output from attr-factory %s for claim-set %s not parseable.", attr_factory_str, claim_set_ref_str);
            buf = alloc_dynamic_array(32 * 1024);
        }
        int err_read_res = read_fd(&buf, sp.stderr, evr_max_blob_data_size);
        if(err_read_res != evr_ok && err_read_res != evr_end){
            if(buf){
                free(buf);
            }
            goto out_with_join_sp;
        }
        buf = write_n_dynamic_array(buf, &eos, sizeof(eos));
        if(buf){
            log_error("Stderr output from attr-factory %s for claim-set %s was: %s", attr_factory_str, claim_set_ref_str, buf->data);
            free(buf);
        }
        goto out_with_join_sp;
    }
    free(buf);
 out_with_join_sp:
    if(waitpid(sp.pid, &ctx->res, WUNTRACED) < 0){
        evr_blob_ref_str attr_factory_str;
        evr_fmt_blob_ref(attr_factory_str, ctx->attr_factory);
        evr_panic("Failed to wait for attr-factory %s subprocess", attr_factory_str);
        goto out;
    }
    // TODO close sp.stdin, sp.stdout, sp.stderr
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str attr_factory_str;
        evr_fmt_blob_ref(attr_factory_str, ctx->attr_factory);
        log_debug("Joined attr-factory %s for claim-set %s with exit code %d", attr_factory_str, claim_set_ref_str, ctx->res);
    }
#endif
 out:
    return evr_ok;
}

int evr_ensure_attr_factory_exe_ready(struct evr_attr_index_db *db, evr_blob_ref attr_factory, char *exe_path){
    struct stat st;
    if(stat(exe_path, &st) != 0){
        if(errno != ENOENT){
            log_error("Failed to stat attr-factory executable %s", exe_path);
            return evr_error;
        }
#ifdef EVR_LOG_DEBUG
        {
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, attr_factory);
            log_debug("Caching attr-factory %s's executable", ref_str);
        }
#endif
        if(db->blob_file_writer(db->blob_file_writer_ctx, exe_path, 0755, attr_factory) != evr_ok){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, attr_factory);
            log_error("Failed to fetch executable for attr-factory %s", ref_str);
            return evr_error;
        }
    }
    return evr_ok;
}

int evr_merge_claim_set_docs(xmlDocPtr dest, xmlDocPtr src, char *dest_name, char *src_name){
    xmlNode *dcs = evr_get_root_claim_set(dest);
    if(!dcs){
        log_error("No claim-set found in %s document", dest_name);
        return evr_error;
    }
    xmlNode *d_last_claim = xmlGetLastChild(dcs);
    xmlNode *scs = evr_get_root_claim_set(src);
    if(!scs){
        log_error("No claim-set found in %s document", src_name);
        return evr_error;
    }
    xmlNode *sc = evr_first_claim(scs);
    while(sc){
        sc = evr_find_next_element(sc, NULL);
        if(!sc){
            break;
        }
        if(xmlDOMWrapAdoptNode(NULL, src, sc, dest, dcs, 0)){
            return evr_error;
        }
        if(d_last_claim){
            d_last_claim = xmlAddNextSibling(d_last_claim, sc);
            if(!d_last_claim){
                return evr_error;
            }
        } else {
            d_last_claim = xmlAddChild(dcs, sc);
            if(!d_last_claim){
                return evr_error;
            }
        }
        sc = sc->next;
    }
    return evr_ok;
}

int evr_merge_attr_index_claim(struct evr_attr_index_db *db, evr_time t, struct evr_attr_claim *claim){
    int ret = evr_error;
    if(claim->ref_type != evr_ref_type_claim){
        log_error("Only attr claims with claim ref can be merged into attr-index");
        goto out;
    }
    if(evr_merge_attr_index_attr(db, t, claim->ref, claim->attr, claim->attr_len) != evr_ok){
        goto out;
    }
    evr_claim_ref cref;
    evr_build_claim_ref(cref, claim->ref, claim->claim_index);
    if(sqlite3_bind_blob(db->insert_claim, 1, cref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert_claim;
    }
    // sqlite3_step is called here instead of evr_step_stmt because we
    // don't want evr_step_stmt to report SQLITE_CONSTRAINT result as
    // an error.
    int step_res = sqlite3_step(db->insert_claim);
    if(step_res != SQLITE_DONE && step_res != SQLITE_CONSTRAINT){
        // SQLITE_CONSTRAINT is ok because it most likely tells us
        // that the same row already exists.
        goto out_with_reset_insert_claim;
    }
    ret = evr_ok;
    int reset_res;
 out_with_reset_insert_claim:
    reset_res = sqlite3_reset(db->insert_claim);
    if(reset_res != SQLITE_OK && reset_res != SQLITE_CONSTRAINT){
        evr_panic("Failed to reset insert_claim statement");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_merge_attr_index_attr_replace(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, char *key, char* value);

int evr_merge_attr_index_attr_add(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, char *key, char* value);

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, char *key, char* value);

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, struct evr_attr *attr, size_t attr_len){
    int ret = evr_error;
    struct evr_attr *end = &attr[attr_len];
    for(struct evr_attr *a = attr; a != end; ++a){
#ifdef EVR_LOG_DEBUG
        do {
            char *value = a->attr.value ? a->attr.value : "null";
            log_debug("Merging attr op=0x%02x, k=%s, v=%s", a->op, a->attr.key, value);
        } while(0);
#endif
        switch(a->op){
        default:
            log_error("Requested to merge attr with unknown op 0x%02x", a->op);
            goto out;
        case evr_attr_op_replace:
            if(evr_merge_attr_index_attr_replace(db, t, ref, a->attr.key, a->attr.value) != evr_ok){
                goto out;
            }
            break;
        case evr_attr_op_add:
            if(evr_merge_attr_index_attr_add(db, t, ref, a->attr.key, a->attr.value) != evr_ok){
                goto out;
            }
            break;
        case evr_attr_op_rm:
            if(evr_merge_attr_index_attr_rm(db, t, ref, a->attr.key, a->attr.value) != evr_ok){
                goto out;
            }
            break;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_prepare_attr_index_db(struct evr_attr_index_db *db){
    int ret = evr_error;
    if(evr_prepare_stmt(db->db, "select value from state where key = ?", &db->find_state) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "update state set value = ? where key = ?", &db->update_state) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select type from attr_def where key = ?", &db->find_attr_type_for_key) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select rowid, val_str, valid_until, trunc from attr where ref = ? and key = ? and valid_from <= ? order by valid_from desc", &db->find_past_attr_siblings) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select val_str, valid_from, valid_until, trunc from attr where ref = ? and key = ? and valid_from > ? order by valid_from desc", &db->find_future_attr_siblings) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into attr (ref, key, val_str, val_int, valid_from, valid_until, trunc) values (?, ?, ?, ?, ?, ?, ?)", &db->insert_attr) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into claim (ref) values (?)", &db->insert_claim) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into claim_set (ref) values (?)", &db->insert_claim_set) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "update attr set valid_until = ? where rowid = ?", &db->update_attr_valid_until) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select ref, key, val_str from attr where ref = ?1 and valid_from <= ?2 and (valid_until > ?2 or valid_until is null) and val_str not null", &db->find_ref_attrs) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_merge_attr_index_attr_replace(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, char *key, char* value){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(db->find_past_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_past_attr_siblings;
    }
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_past_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_past_attr_siblings;
        }
        int rowid = sqlite3_column_int64(db->find_past_attr_siblings, 0);
        if(evr_attr_index_update_valid_until(db->db, db->update_attr_valid_until, rowid, t) != evr_ok){
            goto out_with_reset_find_past_attr_siblings;
        }
        int trunc = sqlite3_column_int(db->find_past_attr_siblings, 3);
        if(trunc){
            break;
        }
    }
    if(evr_attr_index_bind_find_siblings(db->find_future_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    int is_valid_until = 0;
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_future_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_future_attr_siblings;
        }
        int trunc = sqlite3_column_int(db->find_future_attr_siblings, 3);
        if(trunc){
            is_valid_until = 1;
            break;
        }
    }
    evr_time valid_until = 0;
    if(is_valid_until){
        valid_until = sqlite3_column_int64(db->find_future_attr_siblings, 1);
    }
    if(evr_insert_attr(db, ref, key, value, t, is_valid_until, valid_until, 1) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    ret = evr_ok;
 out_with_reset_find_future_attr_siblings:
    if(sqlite3_reset(db->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find future attr siblings statement");
        ret = evr_error;
    }
 out_with_reset_find_past_attr_siblings:
    if(sqlite3_reset(db->find_past_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find past attr siblings statement");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_merge_attr_index_attr_add(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, char *key, char* value){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(db->find_past_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_past_attr_siblings;
    }
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_past_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_past_attr_siblings;
        }
        const char *row_value = (const char*)sqlite3_column_text(db->find_past_attr_siblings, 1);
        if(!row_value || strcmp(value, row_value) == 0){
            int rowid = sqlite3_column_int64(db->find_past_attr_siblings, 0);
            if(evr_attr_index_update_valid_until(db->db, db->update_attr_valid_until, rowid, t) != evr_ok){
                goto out_with_reset_find_past_attr_siblings;
            }
        }
        int trunc = sqlite3_column_int(db->find_past_attr_siblings, 3);
        if(trunc){
            break;
        }
    }
    if(evr_attr_index_bind_find_siblings(db->find_future_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    int is_valid_until = 0;
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_future_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_future_attr_siblings;
        }
        int trunc = sqlite3_column_int(db->find_future_attr_siblings, 3);
        if(trunc){
            is_valid_until = 1;
            break;
        } else {
            const char *row_value = (const char*)sqlite3_column_text(db->find_past_attr_siblings, 0);
            if(row_value && strcmp(value, row_value) == 0){
                is_valid_until = 1;
                break;
            }
        }
    }
    evr_time valid_until = 0;
    if(is_valid_until){
        valid_until = sqlite3_column_int64(db->find_future_attr_siblings, 1);
    }
    if(evr_insert_attr(db, ref, key, value, t, is_valid_until, valid_until, 0) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    ret = evr_ok;
 out_with_reset_find_future_attr_siblings:
    if(sqlite3_reset(db->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find future attr siblings statement");
        ret = evr_error;
    }
 out_with_reset_find_past_attr_siblings:
    if(sqlite3_reset(db->find_past_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find past attr siblings statement");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, char *key, char* value){
    int ret = evr_error;
    if(evr_attr_index_bind_find_siblings(db->find_past_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_past_attr_siblings;
    }
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_past_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_past_attr_siblings;
        }
        int rowid = sqlite3_column_int64(db->find_past_attr_siblings, 0);
        if(evr_attr_index_update_valid_until(db->db, db->update_attr_valid_until, rowid, t) != evr_ok){
            goto out_with_reset_find_past_attr_siblings;
        }
        int trunc = sqlite3_column_int(db->find_past_attr_siblings, 3);
        if(trunc){
            break;
        }
    }
    if(evr_attr_index_bind_find_siblings(db->find_future_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    int is_valid_until = 0;
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_future_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_future_attr_siblings;
        }
        is_valid_until = 1;
        break;
    }
    evr_time valid_until = 0;
    if(is_valid_until){
        valid_until = sqlite3_column_int64(db->find_future_attr_siblings, 1);
    }
    if(evr_insert_attr(db, ref, key, value, t, is_valid_until, valid_until, 1) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    ret = evr_ok;
 out_with_reset_find_future_attr_siblings:
    if(sqlite3_reset(db->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find future attr siblings statement");
        ret = evr_error;
    }
 out_with_reset_find_past_attr_siblings:
    if(sqlite3_reset(db->find_past_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find past attr siblings statement");
        ret = evr_error;
    }
    return ret;
}

int evr_attr_index_update_valid_until(sqlite3 *db, sqlite3_stmt *update_stmt, int rowid, evr_time valid_until){
    int ret = evr_error;
    if(sqlite3_bind_int64(update_stmt, 1, (sqlite3_int64)valid_until) != SQLITE_OK){
        goto out_with_reset_update_stmt;
    }
    if(sqlite3_bind_int64(update_stmt, 2, (sqlite3_int64)rowid) != SQLITE_OK){
        goto out_with_reset_update_stmt;
    }
    if(evr_step_stmt(db, update_stmt) != SQLITE_DONE){
        goto out_with_reset_update_stmt;
    }
    ret = evr_ok;
 out_with_reset_update_stmt:
    if(sqlite3_reset(update_stmt) != SQLITE_OK){
        evr_panic("Failed to reset update valid until statement");
        ret = evr_error;
    }
    return ret;
}

int evr_attr_index_bind_find_siblings(sqlite3_stmt *find_stmt, evr_claim_ref ref, char *key, evr_time t){
    int ret = evr_error;
    if(sqlite3_bind_blob(find_stmt, 1, ref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out;
    }
    if(sqlite3_bind_text(find_stmt, 2, key, -1, NULL) != SQLITE_OK){
        goto out;
    }
    if(sqlite3_bind_int64(find_stmt, 3, (sqlite3_int64)t) != SQLITE_OK){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_get_attr_type_for_key(struct evr_attr_index_db *db, int *attr_type, char *key
){
    int ret = evr_error;
    if(sqlite3_bind_text(db->find_attr_type_for_key, 1, key, -1, NULL) != SQLITE_OK){
        goto out_with_stmt_reset;
    }
    int step_res = sqlite3_step(db->find_attr_type_for_key);
    int type;
    if(step_res == SQLITE_DONE){
        type = evr_type_str;
    } else if(step_res == SQLITE_ROW) {
        type = sqlite3_column_int(db->find_attr_type_for_key, 0);
    } else {
        goto out_with_stmt_reset;
    }
    *attr_type = type;
    ret = evr_ok;
    log_debug("Detected attr type 0x%02x for key %s", type, key);
 out_with_stmt_reset:
    if(sqlite3_reset(db->find_attr_type_for_key) != SQLITE_OK){
        evr_panic("Failed to reset find attr type for key statement");
        ret = evr_error;
    }
    return ret;
}

int evr_insert_attr(struct evr_attr_index_db *db, evr_claim_ref ref, char *key, char* value, evr_time valid_from, int is_valid_until, evr_time valid_until, int trunc){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    if(sqlite3_bind_blob(db->insert_attr, 1, ref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(sqlite3_bind_text(db->insert_attr, 2, key, -1, NULL) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(value){
        if(sqlite3_bind_text(db->insert_attr, 3, value, -1, NULL) != SQLITE_OK){
            goto out_with_reset_insert;
        }
        if(attr_type == evr_type_int){
            int number;
            if(sscanf(value, "%d", &number) != 1){
                log_debug("Failed to parse '%s' as decimal number", value);
                goto out_with_reset_insert;
            }
            if(sqlite3_bind_int(db->insert_attr, 4, number) != SQLITE_OK){
                goto out_with_reset_insert;
            }
        } else {
            if(sqlite3_bind_null(db->insert_attr, 4) != SQLITE_OK){
                goto out_with_reset_insert;
            }
        }
    } else {
        if(sqlite3_bind_null(db->insert_attr, 3) != SQLITE_OK){
            goto out_with_reset_insert;
        }
        if(sqlite3_bind_null(db->insert_attr, 4) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    }
    if(sqlite3_bind_int64(db->insert_attr, 5, (sqlite3_int64)valid_from) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(is_valid_until){
        if(sqlite3_bind_int64(db->insert_attr, 6, (sqlite3_int64)valid_until) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    } else {
        if(sqlite3_bind_null(db->insert_attr, 6) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    }
    if(sqlite3_bind_int(db->insert_attr, 7, trunc) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(evr_step_stmt(db->db, db->insert_attr) != SQLITE_DONE){
        goto out_with_reset_insert;
    }
    ret = evr_ok;
 out_with_reset_insert:
    if(sqlite3_reset(db->insert_attr) != SQLITE_OK){
        evr_panic("Failed to reset insert attr statement");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_get_ref_attrs(struct evr_attr_index_db *db, evr_time t, const evr_claim_ref ref, evr_attr_visitor visit, void *ctx){
    int ret = evr_error;
    if(sqlite3_bind_blob(db->find_ref_attrs, 1, ref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_find_ref_attrs;
    }
    if(sqlite3_bind_int64(db->find_ref_attrs, 2, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_find_ref_attrs;
    }
    ret = evr_visit_attr_query(db, db->find_ref_attrs, visit, ctx);
 out_with_reset_find_ref_attrs:
    if(sqlite3_reset(db->find_ref_attrs) != SQLITE_OK){
        evr_panic("Failed to reset find_ref_attrs statement");
        ret = evr_error;
    }
    return ret;
}

int evr_visit_attr_query(struct evr_attr_index_db *db, sqlite3_stmt *stmt, evr_attr_visitor visit, void *ctx){
    int ret = evr_error;
    while(1){
        int step_res = evr_step_stmt(db->db, stmt);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out;
        }
        int ref_col_size = sqlite3_column_bytes(stmt, 0);
        if(ref_col_size != evr_claim_ref_size){
            goto out;
        }
        const evr_claim_ref *ref = sqlite3_column_blob(stmt, 0);
        const char *key = (const char*)sqlite3_column_text(stmt, 1);
        const char *value = (const char*)sqlite3_column_text(stmt, 2);
        if(visit(ctx, *ref, key, value) != evr_ok){
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

struct evr_attr_query *evr_attr_parse_query(const char *query);

struct dynamic_array *evr_attr_build_sql_query(struct evr_attr_query_node *root, struct evr_attr_query_ctx *ctx, size_t offset, size_t limit);

#define evr_collect_selected_attrs_attrs_size (2000 * sizeof(struct evr_attr_tuple))
#define evr_collect_selected_attrs_data_size (2000 * 2 * 32)

struct evr_collect_selected_attrs_ctx {
    struct evr_attr_index_db *db;
    struct evr_buf_pos attrs;
    struct evr_buf_pos data;
};

int evr_collect_selected_attrs(struct evr_collect_selected_attrs_ctx *ctx, struct evr_attr_index_db *db, struct evr_attr_selector *selector, evr_time t, const evr_claim_ref ref);

int evr_attr_query_claims(struct evr_attr_index_db *db, const char *query_str, evr_time t, size_t offset, size_t limit, int (*status)(void *ctx, int parse_res), evr_claim_visitor visit, void *visit_ctx){
    int ret = evr_error;
    struct evr_attr_query *query = evr_attr_parse_query(query_str);
    if(!query){
        log_error("Failed to parse attr query: %s", query_str);
        if(status(visit_ctx, evr_error) != evr_ok){
            goto out;
        }
        ret = evr_ok;
        goto out;
    }
    if(status(visit_ctx, evr_ok) != evr_ok){
        goto out_with_free_query;
    }
    struct evr_attr_query_ctx ctx;
    ctx.t = t;
    struct dynamic_array *sql = evr_attr_build_sql_query(query->root, &ctx, offset, limit);
    if(!sql){
        goto out_with_free_query;
    }
    sqlite3_stmt *query_stmt;
    if(evr_prepare_stmt(db->db, sql->data, &query_stmt) != evr_ok){
        goto out_with_free_sql;
    }
    int column = 1;
    if(query->root->bind(&ctx, query->root, query_stmt, &column) != evr_ok){
        goto out_with_finalize_query_stmt;
    }
    struct evr_collect_selected_attrs_ctx attr_ctx;
    attr_ctx.db = NULL;
    attr_ctx.attrs.buf = NULL;
    attr_ctx.data.buf = NULL;
    while(1){
        int step_res = evr_step_stmt(db->db, query_stmt);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_free_attrs;
        }
        int ref_col_size = sqlite3_column_bytes(query_stmt, 0);
        if(ref_col_size != evr_claim_ref_size){
            goto out_with_free_attrs;
        }
        const evr_claim_ref *ref = sqlite3_column_blob(query_stmt, 0);
        evr_reset_buf_pos(&attr_ctx.attrs);
        evr_reset_buf_pos(&attr_ctx.data);
        if(evr_collect_selected_attrs(&attr_ctx, db, query->selector, t, *ref) != evr_ok){
            goto out_with_free_attrs;
        }
        size_t attrs_len = (attr_ctx.attrs.pos - attr_ctx.attrs.buf) / sizeof(struct evr_attr_tuple);
        if(visit(visit_ctx, *ref, (struct evr_attr_tuple*)attr_ctx.attrs.buf, attrs_len) != evr_ok){
            goto out_with_free_attrs;
        }
    }
    ret = evr_ok;
 out_with_free_attrs:
    if(attr_ctx.data.buf){
        free(attr_ctx.data.buf);
    }
    if(attr_ctx.attrs.buf){
        free(attr_ctx.attrs.buf);
    }
    if(attr_ctx.db){
        if(evr_free_attr_index_db(attr_ctx.db) != evr_ok){
            evr_panic("Failed to free attr index db used for fetching attributes");
            ret = evr_error;
        }
    }
 out_with_finalize_query_stmt:
    if(sqlite3_finalize(query_stmt) != SQLITE_OK){
        evr_panic("Failed to finalize claim query statement");
        ret = evr_error;
    }
 out_with_free_sql:
    free(sql);
 out_with_free_query:
    evr_free_attr_query(query);
 out:
    return ret;
}

struct evr_attr_query *evr_attr_parse_query(const char *query){
    struct evr_attr_query *ret = NULL;
    yyscan_t scanner;
    if(yylex_init(&scanner)){
        goto out;
    }
    if(!yy_scan_string(query, scanner)){
        goto out_with_destroy_scanner;
    }
    yypstate *ystate = yypstate_new();
    if(!ystate){
        goto out_with_destroy_scanner;
    }
    int status;
    YYSTYPE pushed_value;
    do {
        status = yypush_parse(ystate, yylex(&pushed_value, scanner), &pushed_value, &ret);
    } while(status == YYPUSH_MORE);
    yypstate_delete(ystate);
 out_with_destroy_scanner:
    yylex_destroy(scanner);
 out:
    return ret;
}

int evr_attr_build_sql_append(struct evr_attr_query_ctx *ctx, const char *cnd){
    int ret = evr_error;
    struct dynamic_array **buf = ctx->more;
    size_t cnd_len = strlen(cnd);
    *buf = write_n_dynamic_array(*buf, cnd, cnd_len);
    if(!*buf){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

struct dynamic_array *evr_attr_build_sql_query(struct evr_attr_query_node *root, struct evr_attr_query_ctx *ctx, size_t offset, size_t limit){
    struct dynamic_array *ret = alloc_dynamic_array(4 * 1024);
    if(!ret){
        goto out;
    }
    ctx->more = &ret;
    const char prefix[] = "select ref from claim where ";
    ret = write_n_dynamic_array(ret, prefix, strlen(prefix));
    if(root->append_cnd(ctx, root, evr_attr_build_sql_append) != evr_ok){
        goto out_with_free_ret;
    }
    // TODO append limit X offset X
    ret = write_n_dynamic_array(ret, "", 1);
 out:
    return ret;
 out_with_free_ret:
    free(ret);
    return NULL;
}

int evr_collect_selected_attrs_visitor(void *context, const evr_claim_ref ref, const char *key, const char *value);

int evr_collect_selected_attrs(struct evr_collect_selected_attrs_ctx *ctx, struct evr_attr_index_db *db, struct evr_attr_selector *selector, evr_time t, const evr_claim_ref ref){
    switch(selector->type){
    default:
        log_error("Unknown selector type %d", selector->type);
        return evr_error;
    case evr_attr_selector_none:
        return evr_ok;
    case evr_attr_selector_all: {
        if(!ctx->db){
            ctx->db = evr_fork_attr_index_db(db);
            if(!ctx->db){
                return evr_error;
            }
            if(evr_prepare_attr_index_db(ctx->db) != evr_ok){
                return evr_error;
            }
        }
        return evr_get_ref_attrs(ctx->db, t, ref, evr_collect_selected_attrs_visitor, ctx);
    }
    }
}

int evr_collect_selected_attrs_visitor(void *context, const evr_claim_ref ref, const char *key, const char *value){
    int ret = evr_error;
    struct evr_collect_selected_attrs_ctx *ctx = context;
    if(!ctx->attrs.buf){
        evr_malloc_buf_pos(&ctx->attrs, evr_collect_selected_attrs_attrs_size);
        evr_malloc_buf_pos(&ctx->data, evr_collect_selected_attrs_data_size);
        if(!ctx->attrs.buf || !ctx->data.buf){
            goto out;
        }
    }
    char *attrs_end = &ctx->attrs.buf[evr_collect_selected_attrs_attrs_size];
    if(ctx->attrs.pos + sizeof(struct evr_attr_tuple) > attrs_end){
        log_error("evr_collect_selected_attrs_ctx attr buffer size exceeded");
        goto out;
    }
    char *data_end = &ctx->data.buf[evr_collect_selected_attrs_data_size];
    size_t key_size = strlen(key) + 1;
    size_t value_size = strlen(value) + 1;
    if(ctx->data.pos + key_size + value_size > data_end){
        log_error("evr_collect_selected_attrs_ctx data buffer size exceeded");
        goto out;
    }
    struct evr_attr_tuple *attr = (struct evr_attr_tuple*)ctx->attrs.pos;
    evr_inc_buf_pos(&ctx->attrs, sizeof(struct evr_attr_tuple));
    attr->key = ctx->data.pos;
    evr_push_n(&ctx->data, key, key_size);
    attr->value = ctx->data.pos;
    evr_push_n(&ctx->data, value, value_size);
    ret = evr_ok;
 out:
    return ret;
}
