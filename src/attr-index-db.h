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

/*
 * attr-index-db.h provides functions for creating, filling and
 * querrying the attributes index.
 *
 * The implementation relies upon the fact that the sqlite3 db is
 * configured to use multi threading BEFORE calling any function from
 * attr-index-db.h:
 *
 * if(sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK){
 *   // handle error
 * }
 */

#ifndef __attr_index_db_h__
#define __attr_index_db_h__

#include "config.h"

#include <sqlite3.h>
#include <libxslt/documents.h>

#include "attr-index-db-configuration.h"
#include "claims.h"

typedef int (*evr_blob_file_writer)(void *ctx, char *path, mode_t mode, evr_blob_ref ref);

struct evr_attr_index_db {
    /**
     * dir is the path to the index's root directory. Always ends with
     * a slash.
     */
    char *dir;
    sqlite3 *db;
    sqlite3_stmt *find_state;
    sqlite3_stmt *update_state;
    sqlite3_stmt *find_attr_type_for_key;
    sqlite3_stmt *find_past_attr_siblings;
    sqlite3_stmt *find_future_attr_siblings;
    sqlite3_stmt *insert_attr;
    sqlite3_stmt *insert_claim;
    sqlite3_stmt *insert_claim_set;
    sqlite3_stmt *update_attr_valid_until;
    sqlite3_stmt *find_ref_attrs;
    evr_blob_file_writer blob_file_writer;
    void *blob_file_writer_ctx;
};

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name, evr_blob_file_writer blob_file_writer, void *blob_file_writer_ctx);

struct evr_attr_index_db *evr_fork_attr_index_db(struct evr_attr_index_db *db);

int evr_free_attr_index_db(struct evr_attr_index_db *db);

/**
 * evr_state_key_last_indexed_claim_ts is the last modified timestamp
 * of the last merged claim set's blob.
 */
#define evr_state_key_last_indexed_claim_ts 1

/**
 * evr_state_key_stage indicates at which readiness phase the db is.
 */
#define evr_state_key_stage 2

#define evr_attr_index_stage_initial 0
#define evr_attr_index_stage_built   1

int evr_attr_index_get_state(struct evr_attr_index_db *db, int key, sqlite3_int64 *value);

int evr_attr_index_set_state(struct evr_attr_index_db *db, int key, sqlite3_int64 value);

/**
 * evr_setup_attr_index_db sets up an opened but empty attr-index db.
 */
int evr_setup_attr_index_db(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec);

/**
 * evr_prepare_attr_index_db prepares a formerly setup
 * evr_attr_index_db for merge calls.
 */
int evr_prepare_attr_index_db(struct evr_attr_index_db *db);

int evr_merge_attr_index_claim_set(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_blob_ref claim_set_ref, evr_time claim_set_last_modified, xmlDocPtr raw_claim_set_doc);

int evr_merge_attr_index_claim(struct evr_attr_index_db *db, evr_time t, struct evr_attr_claim *claim);

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, evr_time t, evr_claim_ref ref, struct evr_attr *attr, size_t attr_len);

typedef int (*evr_attr_visitor)(void *ctx, const evr_claim_ref ref, const char *key, const char *value);

/**
 * evr_claim_visitor is a callback for visiting claims.
 *
 * attrs may be NULL in the case that no attributes are provided at
 * all. Otherwise attrs_len specifies how many attributes are
 * provided.
 */
typedef int (*evr_claim_visitor)(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);

int evr_get_ref_attrs(struct evr_attr_index_db *db, evr_time t, const evr_claim_ref ref, evr_attr_visitor visit, void *ctx);

/**
 * evr_visit_attr_query visits statements which select attribute ref,
 * key and value.
 */
int evr_visit_attr_query(struct evr_attr_index_db *db, sqlite3_stmt *stmt, evr_attr_visitor visit, void *ctx);

int evr_attr_query_claims(struct evr_attr_index_db *db, const char *query, evr_time t, size_t offset, size_t limit, int (*status)(void *ctx, int parse_res), evr_claim_visitor visit, void *ctx);

#endif
