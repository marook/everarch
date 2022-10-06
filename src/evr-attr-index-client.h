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

#ifndef evr_attr_index_client_h
#define evr_attr_index_client_h

#include "config.h"

#include "files.h"
#include "auth.h"
#include "keys.h"

int evr_attri_write_auth_token(struct evr_file *f, evr_auth_token t);

int evr_attri_write_list_claims_for_seed(struct evr_file *f, evr_claim_ref seed);

/**
 * evr_attri_search writes search commands to r and visits the
 * results.
 *
 * Query must not contain the limit or offset evr query language
 * keywords. limit and offset are added by evr_attri_search in order
 * to read the matching seeds page by page. The caller should add an
 * 'at' timestamp to the query so the pages are somehow stable.
 */
int evr_attri_search(struct evr_buf_read *r, char *query, int (*visit_seed)(void *ctx, evr_claim_ref seed), int (*visit_attr)(void *ctx, evr_claim_ref seed, char *key, char *val), void *ctx);

int evr_attri_write_search(struct evr_file *f, char *query);

int evr_attri_read_search(struct evr_buf_read *r, int (*visit_seed)(void *ctx, evr_claim_ref seed), int (*visit_attr)(void *ctx, evr_claim_ref seed, char *key, char *val), void *ctx);

#endif
