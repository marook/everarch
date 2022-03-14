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

#ifndef __attr_index_db_h__
#define __attr_index_db_h__

#include "config.h"

#include <sqlite3.h>

#include "attr-index-db-configuration.h"
#include "claims.h"

struct evr_attr_ops {
    int (*bind)(sqlite3_stmt *stmt, int pos, const char *value);
    const char *(*column)(sqlite3_stmt *stmt, int pos, char *buf, size_t buf_size);
    sqlite3_stmt *find_past_attr_siblings;
    sqlite3_stmt *find_future_attr_siblings;
    sqlite3_stmt *insert;
    sqlite3_stmt *update_valid_until;
    sqlite3_stmt *find_ref_attrs;
};

struct evr_attr_index_db {
    sqlite3 *db;
    sqlite3_stmt *find_attr_type_for_key;
    struct evr_attr_ops str_ops;
    struct evr_attr_ops int_ops;
};

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name);

int evr_free_glacier_index_db(struct evr_attr_index_db *db);

/**
 * evr_setup_attr_index_db sets up an opened but empty attr-index db.
 */
int evr_setup_attr_index_db(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec);

/**
 * evr_prepare_attr_index_db prepares a formerly setup
 * evr_attr_index_db for merge calls.
 */
int evr_prepare_attr_index_db(struct evr_attr_index_db *db);

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, struct evr_attr *attr, size_t attr_len);

typedef int (*evr_attr_visitor)(const evr_blob_key_t ref, const char *key, const char *value);

int evr_get_ref_attrs(struct evr_attr_index_db *db, time_t t, evr_blob_key_t ref, struct evr_attr_ops *ops, evr_attr_visitor visit);

/**
 * evr_visit_attr_query visits statements which select attribute ref,
 * key and value.
 */
int evr_visit_attr_query(struct evr_attr_index_db *db, sqlite3_stmt *stmt, evr_attr_visitor visit);

#endif
