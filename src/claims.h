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
 * claims.h provides functions to produce a claim set document from
 * claim structs.
 *
 * The general approach is to evr_init_claim_set(…) a claim set. Then
 * append claims to the claim set. evr_finalize_claim_set(…) the claim
 * set so the claim set document can be extracted via
 * evr_claim_set.out->content. evr_free_claim_set(…) after the claim
 * document content has been consumed.
 */

#ifndef __evr_claims_h__
#define __evr_claims_h__

#include "config.h"

#include <time.h>
#include <libxml/xmlwriter.h>

#include "basics.h"
#include "keys.h"

struct evr_claim_set {
    /**
     * out contains the serialized claim set after
     * evr_finalize_claim_set has been called. Read it via out->content.
     */
    xmlBufferPtr out;

    xmlTextWriterPtr writer;
};

struct evr_file_slice {
    evr_blob_ref ref;
    size_t size;
};

struct evr_file_claim {
    /**
     * title could be the file name. May also be null if the file has
     * no name.
     */
    char *title;

    size_t slices_len;
    
    struct evr_file_slice *slices;
};

#define evr_type_str 0x01
#define evr_type_int 0x02

struct evr_attr_def {
    char *key;
    int type;
};

struct evr_attr_spec_claim {
    size_t attr_def_len;
    struct evr_attr_def *attr_def;
    evr_blob_ref transformation_blob_ref;
    size_t attr_factories_len;
    evr_blob_ref *attr_factories;
};

#define evr_attr_op_replace 0x01
#define evr_attr_op_add 0x02
#define evr_attr_op_rm 0x03

#define evr_attr_value_type_static         0x01
#define evr_attr_value_type_self_claim_ref 0x02

struct evr_attr {
    int op;
    char *key;
    int value_type;
    char *value;
};

#define evr_ref_type_self  0x01
#define evr_ref_type_claim 0x02

struct evr_attr_claim {
    int ref_type;

    /**
     * ref is only filled if ref_type is evr_ref_type_claim.
     */
    evr_claim_ref ref;

    size_t index_ref;
    size_t attr_len;
    struct evr_attr *attr;
};

int evr_init_claim_set(struct evr_claim_set *cs, const evr_time *created);

int evr_append_file_claim(struct evr_claim_set *cs, const struct evr_file_claim *claim);

int evr_finalize_claim_set(struct evr_claim_set *cs);

int evr_free_claim_set(struct evr_claim_set *cs);

/**
 * evr_parse_claim_set parses a claim set document from the given
 * buffer.
 *
 * Usually you want to do the following (except you add error handling
 * of course):
 *
 * xmlInitParser(); // just once at startup
 * …
 * doc = evr_parse_claim_set(…)
 * evr_time created;
 * evr_parse_created(&created, xmlDocGetRootElement(doc));
 * for(cn = evr_first_claim(); cn; cn = evr_next_claim(cn)){
 *   …
 *   if(evr_is_evr_element(cn, "file"){
 *     struct evr_file_claim c;
 *     evr_parse_file_claim(&c, cn);
 *     …
 *   }
 *   …
 * }
 * xmlFreeDoc(doc);
 * …
 * xmlCleanupParser(); // just before exit once
 */
xmlDocPtr evr_parse_claim_set(const char *buf, size_t buf_size);

xmlNode *evr_get_root_claim_set(xmlDocPtr doc);

int evr_parse_created(evr_time *t, xmlNode *node);

xmlNode *evr_first_claim(xmlNode *claim_set);

xmlNode *evr_next_claim(xmlNode *claim_node);

xmlNode *evr_nth_claim(xmlNode *claim_set, int n);

int evr_is_evr_element(xmlNode *n, char *name);

/**
 * evr_add_claim_ref_attrs makes sure every claim within the doc has a
 * ref attribute. Existing ref attributes are kept as they are.
 */
int evr_add_claim_ref_attrs(xmlDocPtr doc, evr_blob_ref doc_ref);

struct evr_attr_spec_claim *evr_parse_attr_spec_claim(xmlNode *claim_node);

/**
 * evr_parse_file_claim parses a claim node into a struct
 * evr_file_claim.
 *
 * Returns NULL on errors. Otherwise a evr_file_claim. The caller must
 * free the returned evr_file_claim.
 */
struct evr_file_claim *evr_parse_file_claim(xmlNode *claim_node);

struct evr_attr_claim *evr_parse_attr_claim(xmlNode *claim_node);

/**
 * evr_find_next_element searches for a node with name
 * name_filter. Starting with n and following with every following
 * sibling of n.
 *
 * name_filter can only match names in the everarch claims
 * namespace. name_filter may be NULL if the element name filter
 * should be ignored.
 */
xmlNode *evr_find_next_element(xmlNode *n, char *name_filter);

#endif
