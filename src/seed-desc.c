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

#include "seed-desc.h"

#include "evr-glacier-client.h"
#include "evr-attr-index-client.h"

#define evr_seed_desc_ns "https://evr.ma300k.de/seed-description/"

int evr_seed_desc_create_doc(xmlDoc **_doc, xmlNode **_desc_node, evr_claim_ref seed){
    xmlDoc *doc = xmlNewDoc(BAD_CAST "1.0");
    if(!doc){
        goto fail;
    }
    xmlNode *desc_node = xmlNewNode(NULL, BAD_CAST "seed-description");
    if(!desc_node){
        goto fail_with_free_doc;
    }
    xmlDocSetRootElement(doc, desc_node);
    if(xmlNewNs(desc_node, BAD_CAST evr_seed_desc_ns, NULL) == NULL){
        goto fail_with_free_doc;
    }
    evr_claim_ref_str seed_str;
    evr_fmt_claim_ref(seed_str, seed);
    if(xmlSetProp(desc_node, BAD_CAST "seed", BAD_CAST seed_str) == NULL){
        goto fail_with_free_doc;
    }
    *_doc = doc;
    *_desc_node = desc_node;
    return evr_ok;
 fail_with_free_doc:
    xmlFreeDoc(doc);
 fail:
    return evr_error;
}

int evr_seed_desc_append_claims(xmlDoc *doc, xmlNode *desc_node, struct evr_verify_ctx *vctx, struct evr_file *c, evr_claim_ref *claims, size_t claims_len){
    xmlNs *desc_ns = xmlNewNs(NULL, BAD_CAST evr_seed_desc_ns, NULL);
    if(!desc_ns){
        goto out;
    }
    xmlNode *claims_node = xmlNewNode(desc_ns, BAD_CAST "claims");
    if(!claims_node){
        xmlFreeNs(desc_ns);
        goto out;
    }
    // TODO maybe we should only add the node if the function returns
    // with evr_ok
    if(!xmlAddChild(desc_node, claims_node)){
        xmlFreeNode(claims_node);
        goto out;
    }
    xmlDoc *cached_claim_set = NULL;
    evr_blob_ref cached_claim_set_ref;
    evr_blob_ref current_claim_set_ref;
    int current_claim_index;
    evr_claim_ref *claims_end = &claims[claims_len];
    for(evr_claim_ref *it = claims; it != claims_end; ++it){
        evr_split_claim_ref(current_claim_set_ref, &current_claim_index, *it);
        if(!cached_claim_set || evr_cmp_blob_ref(cached_claim_set_ref, current_claim_set_ref) != 0){
            if(cached_claim_set){
                xmlFreeDoc(cached_claim_set);
                cached_claim_set = NULL;
            }
            memcpy(cached_claim_set_ref, current_claim_set_ref, evr_blob_ref_size);
            if(evr_fetch_signed_xml(&cached_claim_set, vctx, c, cached_claim_set_ref) != evr_ok){
                goto out;
            }
        }
        // TODO take from cached_claim_set and add to doc
        // TODO remove seed and index-seed attributes from appended claim
    }
    if(cached_claim_set){
        xmlFreeDoc(cached_claim_set);
    }
 out:
    // returns always evr_error because the implementation is not yet
    // done :)
    return evr_error;
}

int evr_seed_desc_append_attrs_visit_attr(void *ctx, evr_claim_ref seed, char *key, char *val);

int evr_seed_desc_append_attrs(xmlDoc *doc, xmlNode *desc_node, struct evr_buf_read *r, evr_claim_ref seed){
    const char prefix[] = "select * where ref=";
    char query[strlen(prefix) + (evr_claim_ref_str_size - 1) + 1];
    xmlNode *attrs_node = xmlNewNode(NULL, BAD_CAST "attr-index");
    if(!attrs_node){
        goto fail;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, query);
    evr_push_concat(&bp, prefix);
    evr_fmt_claim_ref(bp.pos, seed);
    evr_inc_buf_pos(&bp, evr_claim_ref_str_size - 1);
    evr_push_eos(&bp);
    if(evr_attri_write_search(r->f, query) != evr_ok){
        goto fail_with_free_attrs_node;
    }
    if(evr_attri_read_search(r, evr_seed_desc_append_attrs_visit_attr, attrs_node) != evr_ok){
        goto fail_with_free_attrs_node;
    }
    if(!xmlAddChild(desc_node, attrs_node)){
        goto fail_with_free_attrs_node;
    }
    return evr_ok;
 fail_with_free_attrs_node:
    xmlFreeNode(attrs_node);
 fail:
    return evr_error;
}

int evr_seed_desc_append_attrs_visit_attr(void *ctx, evr_claim_ref seed, char *key, char *val){
    xmlNode *attrs_node = ctx;
    xmlNode *an = xmlNewNode(NULL, BAD_CAST "attr");
    if(!an){
        return evr_error;
    }
    if(!xmlAddChild(attrs_node, an)){
        goto fail_with_free_an;
    }
    if(!xmlNewProp(an, BAD_CAST "k", BAD_CAST key)){
        goto fail_with_free_an;
    }
    if(!xmlNewProp(an, BAD_CAST "v", BAD_CAST val)){
        goto fail_with_free_an;
    }
    return evr_ok;
 fail_with_free_an:
    xmlFreeNode(an);
    return evr_error;
    
}
