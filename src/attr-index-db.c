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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <math.h>

#include "dyn-mem.h"
#include "basics.h"
#include "logger.h"
#include "errors.h"
#include "db.h"
#include "attr-query-sql.h"
#include "attr-query-parser.h"
#include "attr-query-lexer.h"
#include "subprocess.h"
#include "files.h"

void evr_free_attr_index_cfg(struct evr_attr_index_cfg *cfg){
    if(!cfg){
        return;
    }
    char *str_options[] = {
        cfg->state_dir_path,
        cfg->host,
        cfg->port,
        cfg->storage_host,
        cfg->storage_port,
    };
    char **str_options_end = &str_options[sizeof(str_options) / sizeof(char*)];
    for(char **it = str_options; it != str_options_end; ++it){
        if(*it){
            free(*it);
        }
    }
    free(cfg);
}

struct evr_attr_index_db *evr_init_attr_index_db(struct evr_attr_index_db *db);
int evr_attr_index_update_valid_until(sqlite3 *db, sqlite3_stmt *update_stmt, int rowid, evr_time valid_until);
int evr_attr_index_bind_find_siblings(sqlite3_stmt *find_stmt, evr_claim_ref ref, char *key, evr_time t);
int evr_get_attr_type_for_key(struct evr_attr_index_db *db, int *attr_type, char *key);
int evr_insert_attr(struct evr_attr_index_db *db, evr_claim_ref ref, char *key, char* value, evr_time valid_from, int is_valid_until, evr_time valid_until, int trunc);

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_cfg *cfg, char *name, evr_blob_file_writer blob_file_writer, void *blob_file_writer_ctx){
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

void evr_sqlite_pow(sqlite3_context *ctx, int argc, sqlite3_value **argv);

struct evr_attr_index_db *evr_init_attr_index_db(struct evr_attr_index_db *db){
    db->db = NULL;
    db->find_state = NULL;
    db->update_state = NULL;
    db->find_attr_type_for_key = NULL;
    db->find_past_attr_siblings = NULL;
    db->find_future_attr_siblings = NULL;
    db->insert_attr = NULL;
    db->insert_claim = NULL;
    db->update_claim_set_failed = NULL;
    db->reset_claim_set_failed = NULL;
    db->find_reindexable_claim_sets = NULL;
    db->archive_claim = NULL;
    db->insert_claim_set = NULL;
    db->update_attr_valid_until = NULL;
    db->find_seed_attrs = NULL;
    db->find_claims_for_seed = NULL;
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
    db->insert_futile_claim_set = NULL;
#endif
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
    if(sqlite3_exec(db->db, "pragma journal_mode=WAL", NULL, NULL, NULL) != SQLITE_OK){
        goto out_with_close_db;
    }
    if(sqlite3_exec(db->db, "pragma synchronous=off", NULL, NULL, NULL) != SQLITE_OK){
        goto out_with_close_db;
    }
    if(sqlite3_create_function(db->db, "pow", 2, SQLITE_UTF8, NULL, &evr_sqlite_pow, NULL, NULL) != SQLITE_OK){
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

void evr_sqlite_pow(sqlite3_context *ctx, int argc, sqlite3_value **argv){
    double num = sqlite3_value_double(argv[0]);
    double exp = sqlite3_value_double(argv[1]);
    double res = pow(num, exp);
    sqlite3_result_double(ctx, res);
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
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
    evr_finalize_stmt(insert_futile_claim_set);
#endif
    evr_finalize_stmt(find_claims_for_seed);
    evr_finalize_stmt(find_seed_attrs);
    evr_finalize_stmt(update_attr_valid_until);
    evr_finalize_stmt(find_reindexable_claim_sets);
    evr_finalize_stmt(reset_claim_set_failed);
    evr_finalize_stmt(update_claim_set_failed);
    evr_finalize_stmt(insert_claim_set);
    evr_finalize_stmt(archive_claim);
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
        "create table attr (seed blob not null, key text not null, val_str text, val_int integer, valid_from integer not null, valid_until integer, trunc integer not null)",
        "create table claim (ref blob primary key not null, seed blob not null)",
        "create table claim_archive (seed blob primary key not null, valid_until integer not null)",
        "create table state (key integer primary key, value integer not null)",
        "insert into state (key, value) values (" to_string(evr_state_key_last_indexed_claim_ts) ", 0)",
        "insert into state (key, value) values (" to_string(evr_state_key_stage) ", " to_string(evr_attr_index_stage_initial) ")",
        "create table claim_set (ref blob primary key not null, created integer not null, fail_counter integer not null default 0, last_fail_timestamp integer)",
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
        "create table futile_claim_set (ref blob primary key not null)",
#endif
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

int evr_find_reindexable_claim_sets(struct evr_attr_index_db *db, evr_time t, size_t max_claim_sets, evr_blob_ref *claim_sets, size_t *found_claim_sets);

int evr_reindex_failed_claim_sets(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_time t, xmlDocPtr (*get_claim_set)(void *ctx, evr_blob_ref claim_set_ref), void *ctx){
    int ret = evr_error;
    const size_t max_claim_sets = 256;
    evr_blob_ref reindexed_claim_set_refs[max_claim_sets];
    size_t found_claim_sets_len;
    if(evr_find_reindexable_claim_sets(db, t, max_claim_sets, reindexed_claim_set_refs, &found_claim_sets_len) != evr_ok){
        goto out;
    }
    evr_blob_ref *reindexed_claim_set_refs_end = &reindexed_claim_set_refs[found_claim_sets_len];
    for(evr_blob_ref *cs_ref = reindexed_claim_set_refs; cs_ref != reindexed_claim_set_refs_end; ++cs_ref){
        xmlDocPtr cs_doc = get_claim_set(ctx, *cs_ref);
        if(!cs_doc){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, *cs_ref);
            log_error("Claim set not fetchable for blob key %s", ref_str);
            goto out;
        }
        if(evr_merge_attr_index_claim_set(db, spec, style, t, *cs_ref, cs_doc, 1) != evr_ok){
            xmlFreeDoc(cs_doc);
            goto out;
        }
        xmlFreeDoc(cs_doc);
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_find_reindexable_claim_sets(struct evr_attr_index_db *db, evr_time t, size_t max_claim_sets, evr_blob_ref *claim_sets, size_t *found_claim_sets){
    int ret = evr_error;
    if(sqlite3_bind_int64(db->find_reindexable_claim_sets, 1, t) != SQLITE_OK){
        goto out_with_reset_find_reindexable_claim_sets;
    }
    evr_blob_ref *claim_sets_end = &claim_sets[max_claim_sets];
    for(evr_blob_ref *cs_ref = claim_sets; cs_ref != claim_sets_end; ++cs_ref){
        int step_res = evr_step_stmt(db->db, db->find_reindexable_claim_sets);
        if(step_res == SQLITE_DONE){
            *found_claim_sets = cs_ref - claim_sets;
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_reindexable_claim_sets;
        }
        int ref_col_size = sqlite3_column_bytes(db->find_reindexable_claim_sets, 0);
        if(ref_col_size != evr_blob_ref_size){
            log_error("claim-set ref of illegal size %d in claim-set table", ref_col_size);
            goto out_with_reset_find_reindexable_claim_sets;
        }
        const evr_claim_ref *sqlite_cs_ref = sqlite3_column_blob(db->find_reindexable_claim_sets, 0);
        memcpy(*cs_ref, *sqlite_cs_ref, evr_blob_ref_size);
    }
    ret = evr_ok;
 out_with_reset_find_reindexable_claim_sets:
    if(sqlite3_reset(db->find_reindexable_claim_sets) != SQLITE_OK){
        evr_panic("Failed to reset find_reindexable_claim_sets");
        ret = evr_error;
    }
    return ret;
}

int evr_append_attr_factory_claims(struct evr_attr_index_db *db, xmlDocPtr raw_claim_set_doc, struct evr_attr_spec_claim *spec, evr_blob_ref claim_set_ref);

void evr_log_failed_claim_set_doc(struct evr_attr_index_db *db, evr_blob_ref claim_set_ref, xmlDocPtr claim_set_doc, char *fail_reason);

void evr_log_failed_claim_set_buf(struct evr_attr_index_db *db, evr_blob_ref claim_set_ref, char *claim_set_buf, int claim_set_buf_size, char *fail_reason);

int evr_merge_attr_index_claim_set(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_time t, evr_blob_ref claim_set_ref, xmlDocPtr raw_claim_set_doc, int reindex){
    int ret = evr_error;
    xmlNode *cs_node = evr_get_root_claim_set(raw_claim_set_doc);
    if(!cs_node){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("No claim-set found in blob with ref %s", ref_str);
        goto out;
    }
    evr_time created;
    if(evr_parse_created(&created, cs_node) != evr_ok){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_error("Failed to parse created date from claim-set within blob ref %s", ref_str);
        goto out;
    }
    if(sqlite3_bind_blob(db->insert_claim_set, 1, claim_set_ref, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert_claim_set;
    }
    if(sqlite3_bind_int64(db->insert_claim_set, 2, (sqlite3_int64)created) != SQLITE_OK){
        goto out_with_reset_insert_claim_set;
    }
    if(reindex){
#ifdef EVR_LOG_DEBUG
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, claim_set_ref);
        log_debug("Reindexing claim set %s", ref_str);
#endif
    } else {
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
    }
    if(evr_add_claim_seed_attrs(raw_claim_set_doc, claim_set_ref) != evr_ok){
        evr_log_failed_claim_set_doc(db, claim_set_ref, raw_claim_set_doc, "Unable to add seeds attributes to claim-set before attr factories.");
        goto out_with_reset_insert_claim_set;
    }
    if(evr_append_attr_factory_claims(db, raw_claim_set_doc, spec, claim_set_ref) != evr_ok){
        // evr_append_attr_factory_claims is not called here because
        // we call it from within evr_append_attr_factory_claims
        if(sqlite3_bind_int64(db->update_claim_set_failed, 1, t) != SQLITE_OK){
            goto out_with_reset_update_claim_set_failed;
        }
        if(sqlite3_bind_blob(db->update_claim_set_failed, 2, claim_set_ref, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
            goto out_with_reset_update_claim_set_failed;
        }
        if(evr_step_stmt(db->db, db->update_claim_set_failed) != SQLITE_DONE){
            goto out_with_reset_update_claim_set_failed;
        }
        ret = evr_ok;
    out_with_reset_update_claim_set_failed:
        if(sqlite3_reset(db->update_claim_set_failed) != SQLITE_OK){
            evr_panic("Failed to reset update_claim_set_failed statement");
            ret = evr_error;
        }
        goto out_with_reset_insert_claim_set;
    }
    if(evr_add_claim_seed_attrs(raw_claim_set_doc, claim_set_ref) != evr_ok){
        evr_log_failed_claim_set_doc(db, claim_set_ref, raw_claim_set_doc, "Unable to add seeds attributes to claim-set after attr factories.");
        goto out_with_reset_insert_claim_set;
    }
    const char *xslt_params[] = {
        NULL
    };
    xmlDocPtr claim_set_doc = xsltApplyStylesheet(style, raw_claim_set_doc, xslt_params);
    if(!claim_set_doc){
        evr_log_failed_claim_set_doc(db, claim_set_ref, raw_claim_set_doc, "Unable to transform claim-set using XSLT stylesheet.");
        goto out_with_reset_insert_claim_set;
    }
    cs_node = evr_get_root_claim_set(claim_set_doc);
    if(!cs_node){
#ifdef EVR_LOG_INFO
        {
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_info("Transformed claim set blob %s does not contain claim-set element", ref_str);
        }
#endif
        evr_log_failed_claim_set_doc(db, claim_set_ref, claim_set_doc, "No claim-set element found in transformed claim-set.");
        ret = evr_ok;
        goto out_with_free_claim_set_doc;
    }
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
    int claim_set_futile = 1;
#endif
    xmlNode *c_node = evr_first_claim(cs_node);
    struct evr_attr_claim *attr;
    while(c_node){
        c_node = evr_find_next_element(c_node, "attr");
        if(!c_node){
            break;
        }
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
        claim_set_futile = 0;
#endif
        attr = evr_parse_attr_claim(c_node);
        if(!attr){
            evr_log_failed_claim_set_doc(db, claim_set_ref, claim_set_doc, "Failed to parse attr claim from transformed claim-set.");
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_error("Failed to parse attr claim from transformed claim-set for blob with ref %s", ref_str);
            goto out_with_free_claim_set_doc;
        }
        if(attr->seed_type == evr_seed_type_self){
            evr_build_claim_ref(attr->seed, claim_set_ref, attr->index_seed);
            attr->seed_type = evr_seed_type_claim;
        }
        evr_claim_ref cref;
        evr_build_claim_ref(cref, claim_set_ref, attr->index_seed);
        int merge_res = evr_merge_attr_index_claim(db, created, cref, attr);
        free(attr);
        if(merge_res != evr_ok){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_error("Failed to merge attr claim from transformed claim-set for blob with ref %s into attr index", ref_str);
            goto out_with_free_claim_set_doc;
        }
        c_node = c_node->next;
    }
    c_node = evr_first_claim(cs_node);
    struct evr_archive_claim *arch;
    while(c_node){
        c_node = evr_find_next_element(c_node, "archive");
        if(!c_node){
            break;
        }
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
        claim_set_futile = 0;
#endif
        arch = evr_parse_archive_claim(c_node);
        if(!arch){
            evr_log_failed_claim_set_doc(db, claim_set_ref, claim_set_doc, "Failed to parse archive claim from transformed claim-set.");
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            log_error("Failed to parse archive claim from transformed claim-set for blob with ref %s", ref_str);
            goto out_with_free_claim_set_doc;
        }
#ifdef EVR_LOG_DEBUG
        {
            evr_claim_ref_str seed_str;
            evr_fmt_claim_ref(seed_str, arch->seed);
            log_debug("Merging archive seed %s", seed_str);
        }
#endif
        if(sqlite3_bind_blob(db->archive_claim, 1, arch->seed, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
            goto out_with_reset_archive_claim;
        }
        if(sqlite3_bind_int64(db->archive_claim, 2, (sqlite3_int64)created) != SQLITE_OK){
            goto out_with_reset_archive_claim;
        }
        if(evr_step_stmt(db->db, db->archive_claim) != SQLITE_DONE){
            goto out_with_reset_archive_claim;
        }
        free(arch);
        c_node = c_node->next;
        continue;
    out_with_reset_archive_claim:
        if(sqlite3_reset(db->archive_claim) != SQLITE_OK){
            evr_panic("Failed to reset archive_claim statement");
        }
        free(arch);
        goto out_with_free_claim_set_doc;
    }
    if(reindex){
        if(sqlite3_bind_blob(db->reset_claim_set_failed, 1, claim_set_ref, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            evr_panic("Unable to reset failed counter on claim-set %s", ref_str);
            // TODO the following goto is not perfect because it does not reset the db->reset_claim_set_failed statement, otherwise we have an evr_panic before it
            goto out_with_free_claim_set_doc;
        }
        if(evr_step_stmt(db->db, db->reset_claim_set_failed) != SQLITE_DONE){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, claim_set_ref);
            evr_panic("Unable to reset failed counter on claim-set %s", ref_str);
            // TODO the following goto is not perfect because it does not reset the db->reset_claim_set_failed statement, otherwise we have an evr_panic before it
            goto out_with_free_claim_set_doc;
        }
        if(sqlite3_reset(db->reset_claim_set_failed) != SQLITE_OK){
            evr_panic("Unable to reset reset_claim_set_failed statement");
            goto out_with_free_claim_set_doc;
        }
    }
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
    if(claim_set_futile){
        if(sqlite3_bind_blob(db->insert_futile_claim_set, 1, claim_set_ref, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
            goto out_with_reset_insert_futile_claim_set;
        }
        if(evr_step_stmt(db->db, db->insert_futile_claim_set) != SQLITE_DONE){
            goto out_with_reset_insert_futile_claim_set;
        }
    }
#endif
    ret = evr_ok;
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
 out_with_reset_insert_futile_claim_set:
    if(claim_set_futile && sqlite3_reset(db->insert_futile_claim_set) != SQLITE_OK){
        evr_panic("Failed to reset insert_futile_claim_set statement");
        ret = evr_error;
    }
#endif
 out_with_free_claim_set_doc:
    xmlFreeDoc(claim_set_doc);
    int reset_res;
 out_with_reset_insert_claim_set:
    reset_res = sqlite3_reset(db->insert_claim_set);
    if(reset_res != SQLITE_OK && reset_res != SQLITE_CONSTRAINT){
        evr_panic("Failed to reset insert_claim_set statement");
        ret = evr_error;
    }
 out:
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
        c->built_doc = NULL;
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
                ret = evr_error;
                continue;
            }
            if(evr_merge_claim_set_docs(raw_claim_set_doc, c->built_doc, "original", "dynamic") != evr_ok){
                evr_blob_ref_str claim_set_ref_str;
                evr_fmt_blob_ref(claim_set_ref_str, c->claim_set_ref);
                evr_blob_ref_str attr_factory_str;
                evr_fmt_blob_ref(attr_factory_str, c->attr_factory);
                log_error("Failed to merged attr-factory %s's dynamic claim-set for original claim-set %s", attr_factory_str, claim_set_ref_str);
                ret = evr_error;
                evr_log_failed_claim_set_doc(db, claim_set_ref, c->built_doc, "Unable to merge attr-factory built document into claim-set document.");
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
    evr_blob_ref_str attr_factory_str;
    evr_fmt_blob_ref(attr_factory_str, ctx->attr_factory);
    log_debug("Spawn attr-factory %s for claim-set %s", attr_factory_str, claim_set_ref_str);
    struct evr_subprocess sp;
    if(evr_spawn(&sp, argv) != evr_ok){
        goto out;
    }
    int write_res = write_n(sp.stdin, ctx->claim_set, ctx->claim_set_len);
    if(write_res != evr_ok && write_res != evr_end){
        goto out_with_close_sp;
    }
    if(close(sp.stdin)){
        goto out_with_close_sp;
    }
    const int closed_fd = -1;
    sp.stdin = closed_fd;
    struct dynamic_array *buf = alloc_dynamic_array(32 * 1024);
    if(!buf){
        goto out_with_close_sp;
    }
    int read_res = read_fd(&buf, sp.stdout, evr_max_blob_data_size);
    if(read_res != evr_ok && read_res != evr_end){
        if(buf){
            free(buf);
        }
        goto out_with_close_sp;
    }
    if(!buf){
        goto out_with_close_sp;
    }
    if(waitpid(sp.pid, &ctx->res, WUNTRACED) < 0){
        evr_panic("Failed to wait for attr-factory %s subprocess", attr_factory_str);
        goto out_with_close_sp;
    }
    char *fail_reason;
    if(ctx->res != 0){
        log_error("attr-factory %s for claim-set %s ended with exit code %d", attr_factory_str, claim_set_ref_str, ctx->res);
        fail_reason = "attr-factory failed with exit code unequal 0.";
        goto out_with_log_buf_and_stderr;
    }
    ctx->built_doc = evr_parse_claim_set(buf->data, buf->size_used);
    if(!ctx->built_doc){
        log_error("Output from attr-factory %s for claim-set %s not parseable as XML.", attr_factory_str, claim_set_ref_str);
        fail_reason = "attr-factory output not parseable as claim-set XML.";
        goto out_with_log_buf_and_stderr;
    }
 out_with_free_buf:
    free(buf);
 out_with_close_sp:
    if(sp.stdin != closed_fd){
        close(sp.stdin);
    }
    close(sp.stdout);
    close(sp.stderr);
    log_debug("Joined attr-factory %s for claim-set %s with exit code %d", attr_factory_str, claim_set_ref_str, ctx->res);
 out:
    return evr_ok;
 out_with_log_buf_and_stderr:
    if(!buf){
        buf = alloc_dynamic_array(32 * 1024);
        if(!buf){
            evr_panic("Unable to log failed attr-factory %s call.", attr_factory_str);
            goto out_with_close_sp;
        }
    }
    char stderr_msg[] = "\n\n-------- stderr follows --------\n";
    buf = write_n_dynamic_array(buf, stderr_msg, strlen(stderr_msg));
    if(!buf){
        evr_panic("Unable to log failed attr-factory %s call.", attr_factory_str);
        goto out_with_close_sp;
    }
    int err_read_res = read_fd(&buf, sp.stderr, evr_max_blob_data_size);
    if(err_read_res != evr_ok && err_read_res != evr_end){
        goto out_with_free_buf;
    }
    evr_log_failed_claim_set_buf(ctx->db, ctx->claim_set_ref, buf->data, buf->size_used, fail_reason);
    goto out_with_free_buf;
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

void evr_log_failed_claim_set_doc(struct evr_attr_index_db *db, evr_blob_ref claim_set_ref, xmlDocPtr claim_set_doc, char *fail_reason){
    char *claim_set_str = NULL;
    int claim_set_str_size;
    xmlDocDumpMemoryEnc(claim_set_doc, (xmlChar**)&claim_set_str, &claim_set_str_size, "UTF-8");
    if(!claim_set_str){
        return;
    }
    evr_log_failed_claim_set_buf(db, claim_set_ref, claim_set_str, claim_set_str_size, fail_reason);
    xmlFree(claim_set_str);
}

void evr_log_failed_claim_set_buf(struct evr_attr_index_db *db, evr_blob_ref claim_set_ref, char *claim_set_buf, int claim_set_buf_size, char *fail_reason){
#define log_scope "Failed to log failed claim-set operation."
    const char suffix[] = ".log";
    const size_t dir_len = strlen(db->dir);
    char log_path[dir_len + evr_blob_ref_str_size - 1 + sizeof(suffix)];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, log_path);
    evr_push_n(&bp, db->dir, dir_len);
    evr_fmt_blob_ref(bp.pos, claim_set_ref);
    evr_inc_buf_pos(&bp, evr_blob_ref_str_size - 1);
    evr_push_n(&bp, suffix, sizeof(suffix));
    log_debug("Logging failed claim-set operation to %s: %s", log_path, fail_reason);
    int f = open(log_path, O_WRONLY | O_APPEND | O_CREAT);
    if(f < 0){
        log_error(log_scope " Can't open claim-set log file.");
        return;
    }
    if(write_n(f, fail_reason, strlen(fail_reason)) != evr_ok){
        log_error(log_scope " Can't write fail reason to log file.");
        goto out_with_close_f;
    }
    const char sep[] = "\n\n";
    if(write_n(f, sep, strlen(sep)) != evr_ok){
        log_error(log_scope " Can't write separator to log file.");
        goto out_with_close_f;
    }
    if(write_n(f, claim_set_buf, claim_set_buf_size) != evr_ok){
        log_error(log_scope " Can't write claim-set string to log file.");
        goto out_with_close_f;
    }
 out_with_close_f:
    if(close(f) != 0){
        log_error(log_scope " Can't close claim-set log file.");
    }
}

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, evr_claim_ref ref, struct evr_attr *attr, size_t attr_len);

int evr_merge_attr_index_claim(struct evr_attr_index_db *db, evr_time t, evr_claim_ref cref, struct evr_attr_claim *claim){
    int ret = evr_error;
    if(claim->seed_type != evr_seed_type_claim){
        log_error("Only attr claims with claim seed can be merged into attr-index");
        goto out;
    }
    if(evr_merge_attr_index_attr(db, t, claim->seed, cref, claim->attr, claim->attr_len) != evr_ok){
        goto out;
    }
    if(sqlite3_bind_blob(db->insert_claim, 1, cref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert_claim;
    }
    if(sqlite3_bind_blob(db->insert_claim, 2, claim->seed, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
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

int evr_merge_attr_index_attr_replace(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, char *key, char* value);

int evr_merge_attr_index_attr_add(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, char *key, char* value);

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, char *key, char* value);

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, evr_claim_ref ref, struct evr_attr *attr, size_t attr_len){
    int ret = evr_error;
    struct evr_attr *end = &attr[attr_len];
    int ref_str_built = 0;
    evr_claim_ref_str ref_str;
    for(struct evr_attr *a = attr; a != end; ++a){
        char *value;
        switch(a->value_type){
        default:
            log_error("Unknown attr value type 0x%02x detected.", a->value_type);
            continue;
        case evr_attr_value_type_static:
            value = a->value;
            break;
        case evr_attr_value_type_self_claim_ref:
            if(!ref_str_built){
                evr_fmt_claim_ref(ref_str, ref);
                ref_str_built = 1;
            }
            value = ref_str;
            break;
        }
#ifdef EVR_LOG_DEBUG
        do {
            char *value_str = value ? value : "null";
            log_debug("Merging attr op=0x%02x, k=%s, v=%s", a->op, a->key, value_str);
        } while(0);
#endif
        switch(a->op){
        default:
            log_error("Requested to merge attr with unknown op 0x%02x", a->op);
            goto out;
        case evr_attr_op_replace:
            if(evr_merge_attr_index_attr_replace(db, t, seed, a->key, value) != evr_ok){
                goto out;
            }
            break;
        case evr_attr_op_add:
            if(evr_merge_attr_index_attr_add(db, t, seed, a->key, value) != evr_ok){
                goto out;
            }
            break;
        case evr_attr_op_rm:
            if(evr_merge_attr_index_attr_rm(db, t, seed, a->key, value) != evr_ok){
                goto out;
            }
            break;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

// TODO using a substr to extract the claim ref's blob ref part is
// error prone. we should split up the c.ref column into a c.ref and
// c.index column. then we can get rid of the substr call which makes
// assumptions about the formatting of a claim ref.
#define evr_sql_extract_blob_ref(column) \
    "substr(" column ", 0, " to_string(evr_blob_ref_size + 1)  ")"

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
    if(evr_prepare_stmt(db->db, "select rowid, val_str, valid_until, trunc from attr where seed = ? and key = ? and valid_from <= ? order by valid_from desc", &db->find_past_attr_siblings) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select val_str, valid_from, valid_until, trunc from attr where seed = ? and key = ? and valid_from > ? order by valid_from desc", &db->find_future_attr_siblings) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into attr (seed, key, val_str, val_int, valid_from, valid_until, trunc) values (?, ?, ?, ?, ?, ?, ?)", &db->insert_attr) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into claim (ref, seed) values (?, ?)", &db->insert_claim) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into claim_archive (seed, valid_until) values (?, ?)", &db->archive_claim) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "insert into claim_set (ref, created) values (?, ?)", &db->insert_claim_set) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "update claim_set set fail_counter = fail_counter + 1, last_fail_timestamp = ? where ref = ?", &db->update_claim_set_failed) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "update claim_set set fail_counter = 0 where ref = ?", &db->reset_claim_set_failed) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select ref from claim_set where fail_counter > 0 and last_fail_timestamp + pow(1.5, fail_counter) * " to_string(evr_reindex_interval) " <= ?", &db->find_reindexable_claim_sets) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "update attr set valid_until = ? where rowid = ?", &db->update_attr_valid_until) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select key, val_str from attr where seed = ?1 and valid_from <= ?2 and (valid_until > ?2 or valid_until is null) and val_str not null", &db->find_seed_attrs) != evr_ok){
        goto out;
    }
    if(evr_prepare_stmt(db->db, "select c.ref from claim c inner join claim_set cs where c.seed = ? and cs.fail_counter = 0 and cs.ref = " evr_sql_extract_blob_ref("c.ref") " order by cs.created", &db->find_claims_for_seed) != evr_ok){
        goto out;
    }
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
    if(evr_prepare_stmt(db->db, "insert into futile_claim_set (ref) values (?)", &db->insert_futile_claim_set) != evr_ok){
        goto out;
    }
#endif
    ret = evr_ok;
 out:
    return ret;
}

int evr_merge_attr_index_attr_replace(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, char *key, char* value){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(db->find_past_attr_siblings, seed, key, t) != evr_ok){
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
    if(evr_attr_index_bind_find_siblings(db->find_future_attr_siblings, seed, key, t) != evr_ok){
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
    if(evr_insert_attr(db, seed, key, value, t, is_valid_until, valid_until, 1) != evr_ok){
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

int evr_merge_attr_index_attr_add(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, char *key, char* value){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(db->find_past_attr_siblings, seed, key, t) != evr_ok){
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
    if(evr_attr_index_bind_find_siblings(db->find_future_attr_siblings, seed, key, t) != evr_ok){
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
    if(evr_insert_attr(db, seed, key, value, t, is_valid_until, valid_until, 0) != evr_ok){
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

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, evr_time t, evr_claim_ref seed, char *key, char* value){
    int ret = evr_error;
    if(evr_attr_index_bind_find_siblings(db->find_past_attr_siblings, seed, key, t) != evr_ok){
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
    if(evr_attr_index_bind_find_siblings(db->find_future_attr_siblings, seed, key, t) != evr_ok){
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
    if(evr_insert_attr(db, seed, key, value, t, is_valid_until, valid_until, 1) != evr_ok){
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

int evr_get_seed_attrs(struct evr_attr_index_db *db, evr_time t, const evr_claim_ref seed, evr_attr_visitor visit, void *ctx){
    int ret = evr_error;
    if(sqlite3_bind_blob(db->find_seed_attrs, 1, seed, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_find_seed_attrs;
    }
    if(sqlite3_bind_int64(db->find_seed_attrs, 2, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_find_seed_attrs;
    }
    ret = evr_visit_attr_query(db, db->find_seed_attrs, visit, ctx);
 out_with_reset_find_seed_attrs:
    if(sqlite3_reset(db->find_seed_attrs) != SQLITE_OK){
        evr_panic("Failed to reset find_seed_attrs statement");
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
        const char *key = (const char*)sqlite3_column_text(stmt, 0);
        const char *value = (const char*)sqlite3_column_text(stmt, 1);
        if(visit(ctx, key, value) != evr_ok){
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

struct evr_attr_query *evr_attr_parse_query(const char *query, char **query_error);

struct dynamic_array *evr_attr_build_sql_query(struct evr_attr_query_node *root, struct evr_attr_query_ctx *ctx);

#define evr_collect_selected_attrs_attrs_size (2000 * sizeof(struct evr_attr_tuple))
#define evr_collect_selected_attrs_data_size (2000 * 2 * 32)

struct evr_collect_selected_attrs_ctx {
    struct evr_attr_index_db *db;
    struct evr_buf_pos attrs;
    struct evr_buf_pos data;
};

int evr_collect_selected_attrs(struct evr_collect_selected_attrs_ctx *ctx, struct evr_attr_index_db *db, struct evr_attr_selector *selector, evr_time t, const evr_claim_ref seed);

int evr_attr_query_claims(struct evr_attr_index_db *db, const char *query_str, int (*status)(void *ctx, int parse_res, char *parse_error), evr_claim_visitor visit, void *visit_ctx){
    int ret = evr_error;
    char *query_error = NULL;
    struct evr_attr_query *query = evr_attr_parse_query(query_str, &query_error);
    if(!query){
        log_debug("Failed to parse attr query '%s' because of: %s", query_str, query_error);
        int status_res = status(visit_ctx, evr_error, query_error);
        if(query_error){
            free(query_error);
        }
        if(status_res != evr_ok){
            goto out;
        }
        ret = evr_ok;
        goto out;
    }
    if(query_error){
        free(query_error);
    }
    if(status(visit_ctx, evr_ok, NULL) != evr_ok){
        goto out_with_free_query;
    }
    struct evr_attr_query_ctx ctx;
    ctx.effective_time = query->effective_time;
    struct dynamic_array *sql = evr_attr_build_sql_query(query->root, &ctx);
    if(!sql){
        goto out_with_free_query;
    }
    sqlite3_stmt *query_stmt;
    if(evr_prepare_stmt(db->db, sql->data, &query_stmt) != evr_ok){
        goto out_with_free_sql;
    }
    int column = 1;
    if(sqlite3_bind_int64(query_stmt, column++, (sqlite3_int64)query->effective_time) != SQLITE_OK){
        goto out_with_finalize_query_stmt;
    }
    if(sqlite3_bind_int64(query_stmt, column++, (sqlite3_int64)query->effective_time) != SQLITE_OK){
        goto out_with_finalize_query_stmt;
    }
    if(query->root && query->root->bind(&ctx, query->root, query_stmt, &column) != evr_ok){
        goto out_with_finalize_query_stmt;
    }
    if(sqlite3_bind_int(query_stmt, column++, query->limit) != SQLITE_OK){
        goto out_with_finalize_query_stmt;
    }
    if(sqlite3_bind_int(query_stmt, column++, query->offset) != SQLITE_OK){
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
        const evr_claim_ref *seed = sqlite3_column_blob(query_stmt, 0);
        evr_reset_buf_pos(&attr_ctx.attrs);
        evr_reset_buf_pos(&attr_ctx.data);
        if(evr_collect_selected_attrs(&attr_ctx, db, query->selector, query->effective_time, *seed) != evr_ok){
            goto out_with_free_attrs;
        }
        size_t attrs_len = (attr_ctx.attrs.pos - attr_ctx.attrs.buf) / sizeof(struct evr_attr_tuple);
        if(visit(visit_ctx, *seed, (struct evr_attr_tuple*)attr_ctx.attrs.buf, attrs_len) != evr_ok){
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

struct evr_attr_query *evr_attr_parse_query(const char *query, char **query_error){
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
    struct evr_attr_query_result result;
    result.query = NULL;
    result.error = NULL;
    int status;
    YYSTYPE pushed_value;
    do {
        status = yypush_parse(ystate, yylex(&pushed_value, scanner), &pushed_value, &result);
    } while(status == YYPUSH_MORE);
    yypstate_delete(ystate);
    if(result.error){
        if(query_error){
            *query_error = result.error;
        } else {
            free(result.error);
        }
    }
    ret = result.query;
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

struct dynamic_array *evr_attr_build_sql_query(struct evr_attr_query_node *root, struct evr_attr_query_ctx *ctx){
    struct dynamic_array *ret = alloc_dynamic_array(4 * 1024);
    if(!ret){
        goto out;
    }
    ctx->more = &ret;
    const char prefix[] =
        "select distinct seed from claim c "
        "inner join claim_set cs "
        "where cs.ref = " evr_sql_extract_blob_ref("c.ref")
        " and cs.created <= ?"
        " and c.seed not in (select ca.seed from claim_archive ca where ca.seed = c.seed and ca.valid_until <= ?)";
    ret = write_n_dynamic_array(ret, prefix, strlen(prefix));
    if(!ret){
        goto out;
    }
    if(root){
        const char sep[] = " and ";
        ret = write_n_dynamic_array(ret, sep, strlen(sep));
        if(!ret){
            goto out;
        }
        if(root->append_cnd(ctx, root, evr_attr_build_sql_append) != evr_ok){
            goto out_with_free_ret;
        }
    }
    const char suffix[] = " order by cs.created desc limit ? offset ?";
    // sizeof(suffix) because we also want to copy the \0
    ret = write_n_dynamic_array(ret, suffix, sizeof(suffix));
 out:
    return ret;
 out_with_free_ret:
    free(ret);
    return NULL;
}

int evr_collect_selected_attrs_visitor(void *context, const char *key, const char *value);

int evr_collect_selected_attrs(struct evr_collect_selected_attrs_ctx *ctx, struct evr_attr_index_db *db, struct evr_attr_selector *selector, evr_time t, const evr_claim_ref seed){
    if(!selector){
        // no selector is like evr_attr_selector_none
        return evr_ok;
    }
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
        return evr_get_seed_attrs(ctx->db, t, seed, evr_collect_selected_attrs_visitor, ctx);
    }
    }
}

int evr_collect_selected_attrs_visitor(void *context, const char *key, const char *value){
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

int evr_attr_visit_claims_for_seed(struct evr_attr_index_db *db, evr_claim_ref seed_ref, int (*visit)(void *ctx, const evr_claim_ref claim), void *ctx){
    int ret = evr_error;
    if(sqlite3_bind_blob(db->find_claims_for_seed, 1, seed_ref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_stmt;
    }
    while(1){
        int step_res = evr_step_stmt(db->db, db->find_claims_for_seed);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_stmt;
        }
        int ref_col_size = sqlite3_column_bytes(db->find_claims_for_seed, 0);
        if(ref_col_size != evr_claim_ref_size){
            log_error("Claim ref of illegal size %d in claim table", ref_col_size);
            goto out_with_reset_stmt;
        }
        const evr_claim_ref *ref = sqlite3_column_blob(db->find_claims_for_seed, 0);
        if(visit(ctx, *ref) != evr_ok){
            goto out_with_reset_stmt;
        }
    }
    ret = evr_ok;
 out_with_reset_stmt:
    if(sqlite3_reset(db->find_claims_for_seed) != SQLITE_OK){
        evr_panic("Failed to reset find_claims_for_seed statement");
        ret = evr_error;
    }
    return ret;
}
