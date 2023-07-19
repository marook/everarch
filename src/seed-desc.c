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
#include "logger.h"

struct evr_seed_desc_backlog_item {
    evr_claim_ref seed;
    size_t traces_len;
    char **traces;
};

struct evr_seed_desc_backlog_item *evr_seed_desc_create_backlog(size_t backlog_len, size_t max_traces_len);
int evr_seed_desc_build_visit_attr(void *ctx, char *key, char *val);

#define max_backlog_len 256

struct evr_seed_desc_build_ctx {
    size_t backlog_len;
    struct evr_seed_desc_backlog_item *backlog;
    struct evr_claim_ref_tiny_set *visited_seeds;
    size_t current_traces_len;
    char **current_traces;
};

int evr_seed_desc_build(xmlDoc **_doc, struct evr_buf_read *c, evr_claim_ref seed, size_t traces_len, char **traces){
    int ret = evr_error;
    evr_claim_ref current_seed;
    char *current_traces[traces_len];
    xmlDoc *doc;
    xmlNode *set_node;
    if(evr_seed_desc_create_doc(&doc, &set_node, seed) != evr_ok){
        goto out;
    }
    struct evr_seed_desc_build_ctx ctx;
    ctx.backlog = evr_seed_desc_create_backlog(max_backlog_len, traces_len);
    if(!ctx.backlog){
        goto out_with_free_doc;
    }
    ctx.backlog_len = 1;
    memcpy(ctx.backlog[0].seed, seed, evr_claim_ref_size);
    ctx.backlog[0].traces_len = traces_len;
    memcpy(ctx.backlog[0].traces, traces, sizeof(char*) * traces_len);
    ctx.visited_seeds = evr_create_claim_ref_tiny_set(256);
    if(!ctx.visited_seeds){
        goto out_with_free_backlog;
    }
    if(evr_claim_ref_tiny_set_add(ctx.visited_seeds, seed) != evr_ok){
        goto out_with_free_visited_seeds;
    }
    ctx.current_traces = current_traces;
    while(ctx.backlog_len > 0){
        --ctx.backlog_len;
        struct evr_seed_desc_backlog_item *current_item = &ctx.backlog[ctx.backlog_len];
        memcpy(current_seed, current_item->seed, evr_claim_ref_size);
        ctx.current_traces_len = current_item->traces_len;
        memcpy(current_traces, current_item->traces, ctx.current_traces_len * sizeof(char*));
        xmlNode *desc_node;
        if(evr_seed_desc_append_desc(doc, set_node, &desc_node, current_seed) != evr_ok){
            goto out_with_free_visited_seeds;
        }
        // TODO append claims
        if(evr_seed_desc_append_attrs(doc, desc_node, c, current_seed, evr_seed_desc_build_visit_attr, &ctx) != evr_ok){
            goto out_with_free_visited_seeds;
        }
    }
    ret = evr_ok;
    *_doc = doc;
 out_with_free_visited_seeds:
    evr_free_claim_ref_tiny_set(ctx.visited_seeds);
 out_with_free_backlog:
    free(ctx.backlog);
 out_with_free_doc:
    if(ret != evr_ok){
        xmlFreeDoc(doc);
    }
 out:
    return ret;
}

struct evr_seed_desc_backlog_item *evr_seed_desc_create_backlog(size_t backlog_len, size_t max_traces_len){
    char *buf = malloc((sizeof(struct evr_seed_desc_backlog_item) + sizeof(char*) * max_traces_len) * backlog_len);
    if(!buf){
        return NULL;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_seed_desc_backlog_item *backlog = (struct evr_seed_desc_backlog_item*)bp.pos;
    struct evr_seed_desc_backlog_item *backlog_end = &backlog[backlog_len];
    evr_inc_buf_pos(&bp, sizeof(struct evr_seed_desc_backlog_item) * backlog_len);
    for(struct evr_seed_desc_backlog_item *b = backlog; b != backlog_end; ++b){
        b->traces = (char**)bp.pos;
        evr_inc_buf_pos(&bp, sizeof(char*) * max_traces_len);
    }
    return backlog;
}

int evr_seed_desc_build_visit_attr(void *_ctx, char *key, char *val){
    struct evr_seed_desc_build_ctx *ctx = _ctx;
    int key_is_ref = 0;
    char **tr_end = &ctx->current_traces[ctx->current_traces_len];
    size_t key_len = strlen(key);
    for(char **tr = ctx->current_traces; tr != tr_end; ++tr){
        if(strncmp(*tr, key, key_len) != 0){
            continue;
        }
        if((*tr)[key_len] != ',' && (*tr)[key_len] != '\0'){
            continue;
        }
        key_is_ref = 1;
    }
    if(!key_is_ref){
        return evr_ok;
    }
    log_debug("Following key %s with val %s while building seed-description", key, val);
    evr_claim_ref ref;
    if(evr_parse_claim_ref(ref, val) != evr_ok){
        log_error("Unable to parse claim ref %s when following key %s while building seed-description", val, key);
        return evr_error;
    }
    int add_res = evr_claim_ref_tiny_set_add(ctx->visited_seeds, ref);
    if(add_res == evr_exists){
        return evr_ok;
    }
    // we continue after this point ever if add_res ==
    // evr_error. there might be an error because ctx->visited_seeds
    // has exceeded it's size. if the size is exceeded we will just
    // report seed-descriptions for the same seed multiple times.
    if(ctx->backlog_len == max_backlog_len){
        log_error("seed-description backlog exceeded %zu items", (size_t)max_backlog_len);
        return evr_error;
    }
    struct evr_seed_desc_backlog_item *item = &ctx->backlog[ctx->backlog_len];
    memcpy(item->seed, ref, evr_claim_ref_size);
    item->traces_len = 0;
    for(char **tr = ctx->current_traces; tr != tr_end; ++tr){
        if(strncmp(*tr, key, key_len) != 0){
            continue;
        }
        if(*tr[key_len] != ','){
            continue;
        }
        item->traces[item->traces_len] = tr[key_len + 1];
        item->traces_len += 1;
    }
    ctx->backlog_len += 1;
    return evr_ok;
}

#undef max_backlog_len

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
            if(evr_fetch_signed_xml(&cached_claim_set, vctx, c, cached_claim_set_ref, NULL) != evr_ok){
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
