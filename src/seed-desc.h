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

#ifndef seed_desc_h
#define seed_desc_h

#include "config.h"

#include <libxml/tree.h>

#include "keys.h"
#include "files.h"
#include "signatures.h"

int evr_seed_desc_create_doc(xmlDoc **doc, xmlNode **set_node, evr_claim_ref entry_seed);

/**
 * evr_seed_desc_append_desc creates a seed-description element
 */
int evr_seed_desc_append_desc(xmlDoc *doc, xmlNode *set_node, xmlNode **desc_node, evr_claim_ref seed);

/**
 * evr_seed_desc_append_claims inserts a child node with the tag name
 * claims to the seed description node. The claims node will contain
 * every claim referenced by the claims argument.
 *
 * c is a connection to the evr-glacier-storage.
 */
int evr_seed_desc_append_claims(xmlDoc *doc, xmlNode *decs_node, struct evr_verify_ctx *vctx, struct evr_file *c, evr_claim_ref *claims, size_t claims_len);

/**
 * evr_seed_desc_append_attrs inserts a child node with the tag name
 * attrs to the seed description node. The attrs node will contain every
 * attribute currently applied to the seed.
 *
 * r is a connection to the evr-attr-index.
 */
int evr_seed_desc_append_attrs(xmlDoc *doc, xmlNode *desc_node, struct evr_buf_read *r, evr_claim_ref seed, int (*visit_attr)(void *ctx, char *key, char *val), void *ctx);

#endif
