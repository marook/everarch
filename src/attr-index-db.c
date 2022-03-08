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

void evr_reset_attr_ops(struct evr_attr_ops *ops);
int evr_create_attr_table(struct evr_attr_index_db *db, const char *type_name, const char *sqlite_type_name);

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name){
    struct evr_attr_index_db *db = malloc(sizeof(struct evr_attr_index_db));
    if(!db){
        return NULL;
    }
    db->db = NULL;
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
    ops->insert_attr = NULL;
}

int evr_free_glacier_index_db(struct evr_attr_index_db *db){
    int ret = evr_error;
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
    evr_push_concat(&bp, " not null, valid_from integer not null, valid_until integer not null)");
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
