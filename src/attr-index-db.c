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

#include "basics.h"
#include "logger.h"
#include "errors.h"
#include "db.h"

int evr_attr_index_update_valid_until(sqlite3 *db, sqlite3_stmt *update_stmt, int rowid, time_t valid_until);
int evr_attr_index_bind_find_siblings(sqlite3_stmt *find_stmt, evr_blob_key_t ref, char *key, time_t t);
int evr_get_attr_type_for_key(struct evr_attr_index_db *db, int *attr_type, char *key);
int evr_insert_attr(struct evr_attr_index_db *db, evr_blob_key_t ref, char *key, char* value, time_t valid_from, int is_valid_until, time_t valid_until, int trunc);

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name){
    struct evr_attr_index_db *db = malloc(sizeof(struct evr_attr_index_db));
    if(!db){
        return NULL;
    }
    db->db = NULL;
    db->find_attr_type_for_key = NULL;
    db->find_past_attr_siblings = NULL;
    db->find_future_attr_siblings = NULL;
    db->insert_attr = NULL;
    db->update_attr_valid_until = NULL;
    db->find_ref_attrs = NULL;
    const char ext[] = ".db"; 
    size_t state_dir_path_len = strlen(cfg->state_dir_path);
    size_t name_len = strlen(name);
    size_t ext_len = strlen(ext);
    char db_path[state_dir_path_len + 1 + name_len + ext_len + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, db_path);
    evr_push_n(&bp, cfg->state_dir_path, state_dir_path_len);
    const char slash = '/';
    if(state_dir_path_len > 0 && cfg->state_dir_path[state_dir_path_len - 1] != slash){
        evr_push_as(&bp, &slash, char);
    }
    evr_push_n(&bp, name, name_len);
    evr_push_n(&bp, ext, ext_len);
    evr_push_eos(&bp);
    int db_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
    if(sqlite3_open_v2(db_path, &db->db, db_flags, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db->db);
        log_error("Could not open %s sqlite database for attr-index: %s", db_path, sqlite_error_msg);
        goto out_with_free_db;
    }
    return db;
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

int evr_free_glacier_index_db(struct evr_attr_index_db *db){
    int ret = evr_error;
    evr_finalize_stmt(find_ref_attrs);
    evr_finalize_stmt(update_attr_valid_until);
    evr_finalize_stmt(insert_attr);
    evr_finalize_stmt(find_future_attr_siblings);
    evr_finalize_stmt(find_past_attr_siblings);
    evr_finalize_stmt(find_attr_type_for_key);
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

int evr_setup_attr_index_db(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec){
    int ret = evr_error;
    const char *sql[] = {
        "create table attr_def (key text primary key not null, type integer not null)",
        "create table attr (ref blob not null, key text not null, val_str text, val_int integer, valid_from integer not null, valid_until integer, trunc integer not null)",
        NULL
    };
    char *error;
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
    if(sqlite3_prepare_v2(db->db, "insert into attr_def (key, type) values (?, ?)", -1, &insert_attr_def, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db->db);
        log_error("Failed to prepare insert attr_def statement: %s", sqlite_error_msg);
        goto out;
    }
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
    ret = evr_ok;
 out_with_free_insert_attr_def:
    if(sqlite3_finalize(insert_attr_def) != SQLITE_OK){
        ret = evr_error;
    }
 out:
    return ret;
 out_with_free_error:
    sqlite3_free(error);
    return ret;
}

int evr_merge_attr_index_attr_replace(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value);

int evr_merge_attr_index_attr_add(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value);

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value);

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, struct evr_attr *attr, size_t attr_len){
    int ret = evr_error;
    struct evr_attr *end = &attr[attr_len];
    for(struct evr_attr *a = attr; a != end; ++a){
#ifdef EVR_LOG_DEBUG
        do {
            char *value = a->value ? a->value : "null";
            log_debug("Merging attr op=0x%02x, k=%s, v=%s", a->op, a->key, value);
        } while(0);
#endif
        switch(a->op){
        default:
            log_error("Requested to merge attr with unknown op 0x%02x", a->op);
            goto out;
        case evr_attr_op_replace:
            if(evr_merge_attr_index_attr_replace(db, t, ref, a->key, a->value) != evr_ok){
                goto out;
            }
            break;
        case evr_attr_op_add:
            if(evr_merge_attr_index_attr_add(db, t, ref, a->key, a->value) != evr_ok){
                goto out;
            }
            break;
        case evr_attr_op_rm:
            if(evr_merge_attr_index_attr_rm(db, t, ref, a->key, a->value) != evr_ok){
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

int evr_merge_attr_index_attr_replace(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value){
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
    time_t valid_until = 0;
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

int evr_merge_attr_index_attr_add(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value){
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
    time_t valid_until = 0;
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

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value){
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
    time_t valid_until = 0;
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

int evr_attr_index_update_valid_until(sqlite3 *db, sqlite3_stmt *update_stmt, int rowid, time_t valid_until){
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

int evr_attr_index_bind_find_siblings(sqlite3_stmt *find_stmt, evr_blob_key_t ref, char *key, time_t t){
    int ret = evr_error;
    if(sqlite3_bind_blob(find_stmt, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
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

int evr_insert_attr(struct evr_attr_index_db *db, evr_blob_key_t ref, char *key, char* value, time_t valid_from, int is_valid_until, time_t valid_until, int trunc){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    if(sqlite3_bind_blob(db->insert_attr, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
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

int evr_get_ref_attrs(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, evr_attr_visitor visit){
    int ret = evr_error;
    if(sqlite3_bind_blob(db->find_ref_attrs, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_find_ref_attrs;
    }
    if(sqlite3_bind_int64(db->find_ref_attrs, 2, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_find_ref_attrs;
    }
    ret = evr_visit_attr_query(db, db->find_ref_attrs, visit);
 out_with_reset_find_ref_attrs:
    if(sqlite3_reset(db->find_ref_attrs) != SQLITE_OK){
        evr_panic("Failed to reset find_ref_attrs statement");
        ret = evr_error;
    }
    return ret;
}

int evr_visit_attr_query(struct evr_attr_index_db *db, sqlite3_stmt *stmt, evr_attr_visitor visit){
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
        if(ref_col_size != evr_blob_key_size){
            goto out;
        }
        const evr_blob_key_t *ref = sqlite3_column_blob(stmt, 0);
        const char *key = (const char*)sqlite3_column_text(stmt, 1);
        const char *value = (const char*)sqlite3_column_text(stmt, 2);
        if(visit(*ref, key, value) != evr_ok){
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}
