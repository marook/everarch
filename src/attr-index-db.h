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
#include <netinet/in.h>

#include "claims.h"
#include "auth.h"

/**
 * evr_reindex_interval is the baseline for the interval in evr_time
 * at which the failed claim-sets should be checked for reindexing.
 */
#define evr_reindex_interval (30*1000)

struct evr_attr_index_cfg {
    char *state_dir_path;
    char *host;
    char *port;
#ifdef EVR_HAS_HTTPD
    char *http_port;
#endif
    char *ssl_cert_path;
    char *ssl_key_path;
    int auth_token_set;
    evr_auth_token auth_token;
    struct evr_cert_cfg *ssl_certs;
    char *storage_host;
    char *storage_port;
    int storage_auth_token_set;
    evr_auth_token storage_auth_token;

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

    /**
     * foreground's indicates if the process should stay in the
     * started process or fork into a daemon.
     */
    int foreground;

    char *log_path;
    char *pid_path;
};

void evr_free_attr_index_cfg(struct evr_attr_index_cfg *cfg);

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
    sqlite3_stmt *find_claim_archived;
    sqlite3_stmt *archive_claim;
    sqlite3_stmt *insert_claim_set;
    sqlite3_stmt *update_claim_set_failed;
    sqlite3_stmt *reset_claim_set_failed;
    sqlite3_stmt *find_reindexable_claim_sets;
    sqlite3_stmt *update_attr_valid_until;
    sqlite3_stmt *find_seed_attrs;
    sqlite3_stmt *find_claims_for_seed;
#ifdef EVR_FUTILE_CLAIM_SET_TRACKING
    sqlite3_stmt *insert_futile_claim_set;
#endif
    evr_blob_file_writer blob_file_writer;
    void *blob_file_writer_ctx;
    /**
     * claim_log_dir is the path to the root directory of per claim
     * logs. Always ends with a slash.
     */
    char *claim_log_dir;
};

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_cfg *cfg, char *name, evr_blob_file_writer blob_file_writer, void *blob_file_writer_ctx);

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

/**
 * evr_max_claim_sets_per_reindex defines how many failed claim-sets
 * are reindexed in one reindex batch at once.
 */
#define evr_max_claim_sets_per_reindex 256

int evr_reindex_failed_claim_sets(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_time t, xmlDocPtr (*get_claim_set)(void *ctx, evr_blob_ref claim_set_ref), void *ctx, struct evr_claim_ref_tiny_set *visited_seed_set);

int evr_merge_attr_index_claim_set(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec, xsltStylesheetPtr style, evr_time t, evr_blob_ref claim_set_ref, xmlDocPtr raw_claim_set_doc, int reindex, struct evr_claim_ref_tiny_set *visited_seed_set);

int evr_merge_attr_index_claim(struct evr_attr_index_db *db, evr_time t, evr_claim_ref cref, struct evr_attr_claim *claim);

typedef int (*evr_attr_visitor)(void *ctx, const char *key, const char *value);

struct evr_attr_tuple {
    char *key;
    char *value;
};

int evr_get_seed_attrs(struct evr_attr_index_db *db, evr_time t, const evr_claim_ref ref, evr_attr_visitor visit, void *ctx);

/**
 * evr_visit_attr_query visits statements which select attribute ref,
 * key and value.
 */
int evr_visit_attr_query(struct evr_attr_index_db *db, sqlite3_stmt *stmt, evr_attr_visitor visit, void *ctx);

/**
 * evr_claim_visitor is a callback for visiting claims.
 *
 * attrs may be NULL in the case that no attributes are provided at
 * all. Otherwise attrs_len specifies how many attributes are
 * provided.
 */
typedef int (*evr_claim_visitor)(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);

int evr_attr_query_claims(struct evr_attr_index_db *db, const char *query, int (*status)(void *ctx, int parse_res, char *parse_error), evr_claim_visitor visit, void *ctx);

int evr_attr_visit_claims_for_seed(struct evr_attr_index_db *db, evr_claim_ref seed_ref, int (*visit)(void *ctx, const evr_claim_ref claim), void *ctx);

#endif
