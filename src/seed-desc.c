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

int evr_seed_desc_create_doc(xmlDoc **_doc, xmlNode **_set_node, evr_claim_ref entry_seed){
    xmlDoc *doc = xmlNewDoc(BAD_CAST "1.0");
    if(!doc){
        goto fail;
    }
    xmlNode *set_node = xmlNewNode(NULL, BAD_CAST "seed-description-set");
    if(!set_node){
        goto fail_with_free_doc;
    }
    xmlDocSetRootElement(doc, set_node);
    xmlNs *ns = xmlNewNs(set_node, BAD_CAST evr_seed_desc_ns, NULL);
    if(ns == NULL){
        goto fail_with_free_doc;
    }
    xmlSetNs(set_node, ns);
    evr_claim_ref_str entry_seed_str;
    evr_fmt_claim_ref(entry_seed_str, entry_seed);
    if(xmlSetProp(set_node, BAD_CAST "entry-seed", BAD_CAST entry_seed_str) == NULL){
        goto fail_with_free_doc;
    }
    *_doc = doc;
    *_set_node = set_node;
    return evr_ok;
 fail_with_free_doc:
    xmlFreeDoc(doc);
 fail:
    return evr_error;
}

int evr_seed_desc_append_desc(xmlDoc *doc, xmlNode *set_node, xmlNode **desc_node, evr_claim_ref seed){
    xmlNs *desc_ns = xmlSearchNsByHref(doc, set_node, BAD_CAST evr_seed_desc_ns);
    if(!desc_ns){
        goto fail;
    }
    *desc_node = xmlNewNode(desc_ns, BAD_CAST "seed-description");
    if(!desc_node){
        goto fail;
    }
    xmlSetNs(*desc_node, desc_ns);
    evr_claim_ref_str seed_str;
    evr_fmt_claim_ref(seed_str, seed);
    if(xmlSetProp(*desc_node, BAD_CAST "seed", BAD_CAST seed_str) == NULL){
        goto fail_with_free_desc_node;
    }
    if(!xmlAddChild(set_node, *desc_node)){
        goto fail_with_free_desc_node;
    }
    return evr_ok;
 fail_with_free_desc_node:
    xmlFreeNode(*desc_node);
 fail:
    return evr_error;
}

int evr_seed_desc_append_claims(xmlDoc *doc, xmlNode *desc_node, struct evr_verify_ctx *vctx, struct evr_file *c, evr_claim_ref *claims, size_t claims_len){
    // TODO replace xmlNewNs with xmlSearchNsByHref
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

struct evr_seed_desc_append_attrs_ctx {
    xmlDoc *doc;
    xmlNs *ns;
    xmlNode *attrs_node;
    int (*visit_attr)(void *ctx, char *key, char *val);
    void *visit_ctx;
};

int evr_seed_desc_append_attrs(xmlDoc *doc, xmlNode *desc_node, struct evr_buf_read *r, evr_claim_ref seed, int (*visit_attr)(void *ctx, char *key, char *val), void *visit_ctx){
    const char prefix[] = "select * where ref=";
    char query[strlen(prefix) + (evr_claim_ref_str_size - 1) + 1];
    struct evr_seed_desc_append_attrs_ctx ctx;
    ctx.doc = doc;
    ctx.ns = xmlSearchNsByHref(doc, desc_node, BAD_CAST evr_seed_desc_ns);
    if(!ctx.ns){
        goto fail;
    }
    ctx.attrs_node = xmlNewNode(ctx.ns, BAD_CAST "attr-index");
    if(!ctx.attrs_node){
        goto fail;
    }
    ctx.visit_attr = visit_attr;
    ctx.visit_ctx = visit_ctx;
    xmlSetNs(ctx.attrs_node, ctx.ns);
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, query);
    evr_push_concat(&bp, prefix);
    evr_fmt_claim_ref(bp.pos, seed);
    evr_inc_buf_pos(&bp, evr_claim_ref_str_size - 1);
    evr_push_eos(&bp);
    if(evr_attri_write_search(r->f, query) != evr_ok){
        goto fail_with_free_attrs_node;
    }
    if(evr_attri_read_search(r, NULL, evr_seed_desc_append_attrs_visit_attr, &ctx) != evr_ok){
        goto fail_with_free_attrs_node;
    }
    if(!xmlAddChild(desc_node, ctx.attrs_node)){
        goto fail_with_free_attrs_node;
    }
    return evr_ok;
 fail_with_free_attrs_node:
    xmlFreeNode(ctx.attrs_node);
 fail:
    return evr_error;
}

int evr_seed_desc_append_attrs_visit_attr(void *_ctx, evr_claim_ref seed, char *key, char *val){
    struct evr_seed_desc_append_attrs_ctx *ctx = _ctx;
    xmlNode *an = xmlNewNode(ctx->ns, BAD_CAST "attr");
    if(!an){
        return evr_error;
    }
    xmlSetNs(an, ctx->ns);
    if(!xmlAddChild(ctx->attrs_node, an)){
        goto fail_with_free_an;
    }
    if(!xmlNewProp(an, BAD_CAST "k", BAD_CAST key)){
        goto fail_with_free_an;
    }
    if(!xmlNewProp(an, BAD_CAST "v", BAD_CAST val)){
        goto fail_with_free_an;
    }
    if(ctx->visit_attr && ctx->visit_attr(ctx->visit_ctx, key, val) != evr_ok){
        goto fail_with_free_an;
    }
    return evr_ok;
 fail_with_free_an:
    xmlFreeNode(an);
    return evr_error;
    
}
