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
#include <libxslt/documents.h>

#include "attr-index-db-configuration.h"
#include "claims.h"

struct evr_attr_index_db {
    sqlite3 *db;
    sqlite3_stmt *find_attr_type_for_key;
    sqlite3_stmt *find_past_attr_siblings;
    sqlite3_stmt *find_future_attr_siblings;
    sqlite3_stmt *insert_attr;
    sqlite3_stmt *insert_claim;
    sqlite3_stmt *update_attr_valid_until;
    sqlite3_stmt *find_ref_attrs;
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

int evr_merge_attr_index_claim_set(struct evr_attr_index_db *db, xsltStylesheetPtr style, evr_blob_ref claim_set_ref, xmlDocPtr raw_claim_set_doc);

int evr_merge_attr_index_claim(struct evr_attr_index_db *db, time_t t, struct evr_attr_claim *claim);

int evr_merge_attr_index_attr(struct evr_attr_index_db *db, time_t t, evr_claim_ref ref, struct evr_attr *attr, size_t attr_len);

typedef int (*evr_attr_visitor)(const evr_claim_ref ref, const char *key, const char *value);

typedef int (*evr_claim_visitor)(const evr_claim_ref ref);

int evr_get_ref_attrs(struct evr_attr_index_db *db, time_t t, evr_claim_ref ref, evr_attr_visitor visit);

/**
 * evr_visit_attr_query visits statements which select attribute ref,
 * key and value.
 */
int evr_visit_attr_query(struct evr_attr_index_db *db, sqlite3_stmt *stmt, evr_attr_visitor visit);

int evr_attr_query_claims(struct evr_attr_index_db *db, const char *query, time_t t, size_t offset, size_t limit, evr_claim_visitor visit);

#endif
