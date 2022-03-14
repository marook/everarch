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

void evr_reset_attr_ops(struct evr_attr_ops *ops);
int evr_init_attr_ops(struct evr_attr_index_db *db, struct evr_attr_ops *ops, const char *type_name);
int evr_free_attr_ops(struct evr_attr_ops *ops);
int evr_create_attr_table(struct evr_attr_index_db *db, const char *type_name, const char *sqlite_type_name);
int evr_attr_index_update_valid_until(sqlite3 *db, sqlite3_stmt *update_stmt, int rowid, time_t valid_until);
int evr_attr_index_bind_find_siblings(sqlite3_stmt *find_stmt, evr_blob_key_t ref, char *key, time_t t);
int evr_get_attr_type_for_key(struct evr_attr_index_db *db, int *attr_type, char *key);
int evr_get_attr_ops_for_type(struct evr_attr_index_db *db, int attr_type, struct evr_attr_ops **ops);

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name){
    struct evr_attr_index_db *db = malloc(sizeof(struct evr_attr_index_db));
    if(!db){
        return NULL;
    }
    db->db = NULL;
    db->find_attr_type_for_key = NULL;
    evr_reset_attr_ops(&db->str_ops);
    evr_reset_attr_ops(&db->int_ops);
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

void evr_reset_attr_ops(struct evr_attr_ops *ops){
    ops->find_past_attr_siblings = NULL;
    ops->find_future_attr_siblings = NULL;
    ops->insert = NULL;
    ops->update_valid_until = NULL;
    ops->find_ref_attrs = NULL;
}

int evr_free_glacier_index_db(struct evr_attr_index_db *db){
    int ret = evr_error;
    if(evr_free_attr_ops(&db->int_ops) != evr_ok){
        evr_panic("Failed to finalize int_ops");
        goto out;
    }
    if(evr_free_attr_ops(&db->str_ops) != evr_ok){
        evr_panic("Failed to finalize str_ops");
        goto out;
    }
    if(sqlite3_finalize(db->find_attr_type_for_key) != SQLITE_OK){
        evr_panic("Could not finalize find_attr_type_for_key");
        goto out;
    }
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
    if(evr_create_attr_table(db, "str", "text") != evr_ok){
        goto out;
    }
    if(evr_create_attr_table(db, "int", "integer") != evr_ok){
        goto out;
    }
    const char *sql[] = {
        "create table attr_def (key text primary key not null, type integer not null)",
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

int evr_create_attr_table(struct evr_attr_index_db *db, const char *type_name, const char *sqlite_type_name){
    int ret = evr_error;
    char sql[256];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, sql);
    evr_push_concat(&bp, "create table attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " (ref blob not null, key text not null, value ");
    evr_push_concat(&bp, sqlite_type_name);
    evr_push_concat(&bp, ", valid_from integer not null, valid_until integer, trunc integer not null)");
    evr_push_eos(&bp);
    char *error;
    if(sqlite3_exec(db->db, sql, NULL, NULL, &error) != SQLITE_OK){
        log_error("Failed to create attr_def table: %s", error);
        goto out_with_free_error;
    }
    evr_reset_buf_pos(&bp);
    evr_push_concat(&bp, "create index attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, "_key on attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " (key)");
    evr_push_eos(&bp);
    if(sqlite3_exec(db->db, sql, NULL, NULL, &error) != SQLITE_OK){
        log_error("Failed to create attr_def key index: %s", error);
        goto out_with_free_error;
    }
    ret = evr_ok;
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

int evr_bind_str_value(sqlite3_stmt *stmt, int pos, const char *value);
int evr_bind_int_value(sqlite3_stmt *stmt, int pos, const char *value);
const char *evr_column_str_value(sqlite3_stmt *stmt, int pos, char *buf, size_t buf_size);
const char *evr_column_int_value(sqlite3_stmt *stmt, int pos, char *buf, size_t buf_size);

int evr_prepare_attr_index_db(struct evr_attr_index_db *db){
    int ret = evr_error;
    char sql[256];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, sql);
    if(evr_prepare_stmt(db->db, "select type from attr_def where key = ?", &db->find_attr_type_for_key) != evr_ok){
        goto out;
    }
    if(evr_init_attr_ops(db, &db->str_ops, "str") != evr_ok){
        goto out;
    }
    db->str_ops.bind = evr_bind_str_value;
    db->str_ops.column = evr_column_str_value;
    if(evr_init_attr_ops(db, &db->int_ops, "int") != evr_ok){
        goto out;
    }
    db->int_ops.bind = evr_bind_int_value;
    db->int_ops.column = evr_column_int_value;
    ret = evr_ok;
 out:
    return ret;
}

int evr_bind_str_value(sqlite3_stmt *stmt, int pos, const char *value){
    if(!value){
        return SQLITE_OK;
    }
    return sqlite3_bind_text(stmt, pos, value, -1, NULL);
}

int evr_bind_int_value(sqlite3_stmt *stmt, int pos, const char *value){
    if(!value){
        return SQLITE_OK;
    }
    int number;
    if(sscanf(value, "%d", &number) != 1){
        return SQLITE_ERROR;
    }
    return sqlite3_bind_int(stmt, pos, number);
}

const char *evr_column_str_value(sqlite3_stmt *stmt, int pos, char *buf, size_t buf_size){
    return (const char*)sqlite3_column_text(stmt, pos);
}

const char *evr_column_int_value(sqlite3_stmt *stmt, int pos, char *buf, size_t buf_size){
    int value = sqlite3_column_int(stmt, pos);
    int written = snprintf(buf, buf_size, "%d", value);
    if(written >= buf_size){
        evr_panic("Failed to format integer value %d", value);
        return NULL;
    }
    return buf;
}

int evr_init_attr_ops(struct evr_attr_index_db *db, struct evr_attr_ops *ops, const char *type_name){
    int ret = evr_error;
    char sql[256];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, sql);
    evr_push_concat(&bp, "select rowid, value, valid_until, trunc from attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " where ref = ? and key = ? and valid_from <= ? order by valid_from desc");
    evr_push_eos(&bp);
    if(evr_prepare_stmt(db->db, sql, &ops->find_past_attr_siblings) != evr_ok){
        goto out;
    }
    evr_reset_buf_pos(&bp);
    evr_push_concat(&bp, "select value, valid_from, valid_until, trunc from attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " where ref = ? and key = ? and valid_from > ? order by valid_from desc");
    evr_push_eos(&bp);
    if(evr_prepare_stmt(db->db, sql, &ops->find_future_attr_siblings) != evr_ok){
        goto out;
    }
    evr_reset_buf_pos(&bp);
    evr_push_concat(&bp, "insert into attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " (ref, key, value, valid_from, valid_until, trunc) values (?, ?, ?, ?, ?, ?)");
    evr_push_eos(&bp);
    if(evr_prepare_stmt(db->db, sql, &ops->insert) != evr_ok){
        goto out;
    }
    evr_reset_buf_pos(&bp);
    evr_push_concat(&bp, "update attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " set valid_until = ? where rowid = ?");
    evr_push_eos(&bp);
    if(evr_prepare_stmt(db->db, sql, &ops->update_valid_until) != evr_ok){
        goto out;
    }
    evr_reset_buf_pos(&bp);
    evr_push_concat(&bp, "select ref, key, value from attr_");
    evr_push_concat(&bp, type_name);
    evr_push_concat(&bp, " where ref = ?1 and valid_from <= ?2 and (valid_until > ?2 or valid_until is null) and value not null");
    evr_push_eos(&bp);
    if(evr_prepare_stmt(db->db, sql, &ops->find_ref_attrs) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_free_attr_ops(struct evr_attr_ops *ops){
    int ret = evr_error;
    if(sqlite3_finalize(ops->find_ref_attrs) != SQLITE_OK){
        evr_panic("Failed to finalize find_ref_attrs");
        goto out;
    }
    if(sqlite3_finalize(ops->update_valid_until) != SQLITE_OK){
        evr_panic("Failed to finalize update_valid_until");
        goto out;
    }
    if(sqlite3_finalize(ops->insert) != SQLITE_OK){
        evr_panic("Failed to finalize insert");
        goto out;
    }
    if(sqlite3_finalize(ops->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to finalize find_future_attr_siblings");
        goto out;
    }
    if(sqlite3_finalize(ops->find_past_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to finalize find_past_attr_siblings");
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
    struct evr_attr_ops *ops;
    if(evr_get_attr_ops_for_type(db, attr_type, &ops) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(ops->find_past_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_past_attr_siblings;
    }
    while(1){
        int step_res = evr_step_stmt(db->db, ops->find_past_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_past_attr_siblings;
        }
        int rowid = sqlite3_column_int64(ops->find_past_attr_siblings, 0);
        if(evr_attr_index_update_valid_until(db->db, ops->update_valid_until, rowid, t) != evr_ok){
            goto out_with_reset_find_past_attr_siblings;
        }
        int trunc = sqlite3_column_int(ops->find_past_attr_siblings, 3);
        if(trunc){
            break;
        }
    }
    if(evr_attr_index_bind_find_siblings(ops->find_future_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    int is_valid_until = 0;
    while(1){
        int step_res = evr_step_stmt(db->db, ops->find_future_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_future_attr_siblings;
        }
        int trunc = sqlite3_column_int(ops->find_future_attr_siblings, 3);
        if(trunc){
            is_valid_until = 1;
            break;
        }
    }
    time_t valid_until;
    if(is_valid_until){
        valid_until = sqlite3_column_int64(ops->find_future_attr_siblings, 1);
    }
    if(sqlite3_bind_blob(ops->insert, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(sqlite3_bind_text(ops->insert, 2, key, -1, NULL) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(ops->bind(ops->insert, 3, value) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(sqlite3_bind_int64(ops->insert, 4, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(is_valid_until){
        if(sqlite3_bind_int64(ops->insert, 5, (sqlite3_int64)valid_until) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    } else {
        if(sqlite3_bind_null(ops->insert, 5) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    }
    if(sqlite3_bind_int(ops->insert, 6, 1) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(evr_step_stmt(db->db, ops->insert) != SQLITE_DONE){
        goto out_with_reset_insert;
    }
    ret = evr_ok;
 out_with_reset_insert:
    if(sqlite3_reset(ops->insert) != SQLITE_OK){
        evr_panic("Failed to reset insert attr statement");
        ret = evr_error;
    }
 out_with_reset_find_future_attr_siblings:
    if(sqlite3_reset(ops->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find future attr siblings statement");
        ret = evr_error;
    }
 out_with_reset_find_past_attr_siblings:
    if(sqlite3_reset(ops->find_past_attr_siblings) != SQLITE_OK){
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
    struct evr_attr_ops *ops;
    if(evr_get_attr_ops_for_type(db, attr_type, &ops) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(ops->find_past_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_past_attr_siblings;
    }
    char row_value_buf[24];
    while(1){
        int step_res = evr_step_stmt(db->db, ops->find_past_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_past_attr_siblings;
        }
        const char *row_value = ops->column(ops->find_past_attr_siblings, 1, row_value_buf, sizeof(row_value_buf));
        if(!row_value || strcmp(value, row_value) == 0){
            int rowid = sqlite3_column_int64(ops->find_past_attr_siblings, 0);
            if(evr_attr_index_update_valid_until(db->db, ops->update_valid_until, rowid, t) != evr_ok){
                goto out_with_reset_find_past_attr_siblings;
            }
        }
        int trunc = sqlite3_column_int(ops->find_past_attr_siblings, 3);
        if(trunc){
            break;
        }
    }
    if(evr_attr_index_bind_find_siblings(ops->find_future_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    int is_valid_until = 0;
    while(1){
        int step_res = evr_step_stmt(db->db, ops->find_future_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_future_attr_siblings;
        }
        int trunc = sqlite3_column_int(ops->find_future_attr_siblings, 3);
        if(trunc){
            is_valid_until = 1;
            break;
        } else {
            const char *row_value = ops->column(ops->find_future_attr_siblings, 0, row_value_buf, sizeof(row_value_buf));
            if(row_value && strcmp(value, row_value) == 0){
                is_valid_until = 1;
                break;
            }
        }
    }
    time_t valid_until;
    if(is_valid_until){
        valid_until = sqlite3_column_int64(ops->find_future_attr_siblings, 1);
    }
    if(sqlite3_bind_blob(ops->insert, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(sqlite3_bind_text(ops->insert, 2, key, -1, NULL) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(ops->bind(ops->insert, 3, value) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(sqlite3_bind_int64(ops->insert, 4, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(is_valid_until){
        if(sqlite3_bind_int64(ops->insert, 5, (sqlite3_int64)valid_until) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    } else {
        if(sqlite3_bind_null(ops->insert, 5) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    }
    if(sqlite3_bind_int(ops->insert, 6, 0) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(evr_step_stmt(db->db, ops->insert) != SQLITE_DONE){
        goto out_with_reset_insert;
    }
    ret = evr_ok;
 out_with_reset_insert:
    if(sqlite3_reset(ops->insert) != SQLITE_OK){
        evr_panic("Failed to reset insert attr statement");
        ret = evr_error;
    }
 out_with_reset_find_future_attr_siblings:
    if(sqlite3_reset(ops->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find future attr siblings statement");
        ret = evr_error;
    }
 out_with_reset_find_past_attr_siblings:
    if(sqlite3_reset(ops->find_past_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find past attr siblings statement");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_merge_attr_index_attr_rm(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, char *key, char* value){
    int ret = evr_error;
    int attr_type;
    if(evr_get_attr_type_for_key(db, &attr_type, key) != evr_ok){
        goto out;
    }
    struct evr_attr_ops *ops;
    if(evr_get_attr_ops_for_type(db, attr_type, &ops) != evr_ok){
        goto out;
    }
    if(evr_attr_index_bind_find_siblings(ops->find_past_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_past_attr_siblings;
    }
    while(1){
        int step_res = evr_step_stmt(db->db, ops->find_past_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_past_attr_siblings;
        }
        int rowid = sqlite3_column_int64(ops->find_past_attr_siblings, 0);
        if(evr_attr_index_update_valid_until(db->db, ops->update_valid_until, rowid, t) != evr_ok){
            goto out_with_reset_find_past_attr_siblings;
        }
        int trunc = sqlite3_column_int(ops->find_past_attr_siblings, 3);
        if(trunc){
            break;
        }
    }
    if(evr_attr_index_bind_find_siblings(ops->find_future_attr_siblings, ref, key, t) != evr_ok){
        goto out_with_reset_find_future_attr_siblings;
    }
    int is_valid_until = 0;
    while(1){
        int step_res = evr_step_stmt(db->db, ops->find_future_attr_siblings);
        if(step_res == SQLITE_DONE){
            break;
        }
        if(step_res != SQLITE_ROW){
            goto out_with_reset_find_future_attr_siblings;
        }
        is_valid_until = 1;
        break;
    }
    time_t valid_until;
    if(is_valid_until){
        valid_until = sqlite3_column_int64(ops->find_future_attr_siblings, 1);
    }
    if(sqlite3_bind_blob(ops->insert, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(sqlite3_bind_text(ops->insert, 2, key, -1, NULL) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(value){
        if(ops->bind(ops->insert, 3, value) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    } else {
        if(sqlite3_bind_null(ops->insert, 3) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    }
    if(sqlite3_bind_int64(ops->insert, 4, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(is_valid_until){
        if(sqlite3_bind_int64(ops->insert, 5, (sqlite3_int64)valid_until) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    } else {
        if(sqlite3_bind_null(ops->insert, 5) != SQLITE_OK){
            goto out_with_reset_insert;
        }
    }
    if(sqlite3_bind_int(ops->insert, 6, 1) != SQLITE_OK){
        goto out_with_reset_insert;
    }
    if(evr_step_stmt(db->db, ops->insert) != SQLITE_DONE){
        goto out_with_reset_insert;
    }
    ret = evr_ok;
 out_with_reset_insert:
    if(sqlite3_reset(ops->insert) != SQLITE_OK){
        evr_panic("Failed to reset insert attr statement");
        ret = evr_error;
    }
 out_with_reset_find_future_attr_siblings:
    if(sqlite3_reset(ops->find_future_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find future attr siblings statement");
        ret = evr_error;
    }
 out_with_reset_find_past_attr_siblings:
    if(sqlite3_reset(ops->find_past_attr_siblings) != SQLITE_OK){
        evr_panic("Failed to reset find past attr siblings statement");
        ret = evr_error;
    }
 out:
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

int evr_get_attr_ops_for_type(struct evr_attr_index_db *db, int attr_type, struct evr_attr_ops **ops){
    int ret = evr_error;
    switch(attr_type){
    default:
        goto out;
    case evr_type_str:
        *ops = &db->str_ops;
        break;
    case evr_type_int:
        *ops = &db->int_ops;
        break;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_get_ref_attrs(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, struct evr_attr_ops *ops, evr_attr_visitor visit){
    int ret = evr_error;
    if(sqlite3_bind_blob(ops->find_ref_attrs, 1, ref, evr_blob_key_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset_find_ref_attrs;
    }
    if(sqlite3_bind_int64(ops->find_ref_attrs, 2, (sqlite3_int64)t) != SQLITE_OK){
        goto out_with_reset_find_ref_attrs;
    }
    ret = evr_visit_attr_query(db, ops->find_ref_attrs, visit);
 out_with_reset_find_ref_attrs:
    if(sqlite3_reset(ops->find_ref_attrs) != SQLITE_OK){
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
