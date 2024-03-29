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

#include "attr-query-sql.h"

#include <stdlib.h>
#include <stdio.h>

#include "basics.h"
#include "errors.h"
#include "keys.h"

struct evr_attr_query_ref_cnd_data {
    evr_claim_ref ref;
};

int evr_append_ref_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd));

int evr_bind_ref_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column);

struct evr_attr_query_node *evr_attr_query_ref_cnd(char *ref_str){
    struct evr_attr_query_node *ret = NULL;
    char *buf = malloc(sizeof(struct evr_attr_query_node) + sizeof(struct evr_attr_query_ref_cnd_data));
    if(!buf){
        goto out;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_map_struct(&bp, ret);
    ret->append_cnd = evr_append_ref_cnd;
    ret->bind = evr_bind_ref_cnd;
    ret->free_data = NULL;
    struct evr_attr_query_ref_cnd_data *data;
    evr_map_struct(&bp, data);
    ret->data = data;
    if(evr_parse_claim_ref(data->ref, ref_str) != evr_ok){
        // log_error("Unable to parse claim ref in attr query: %s", ref_str);
        goto out_with_free_buf;
    }
    free(ref_str);
 out:
    return ret;
 out_with_free_buf:
    free(buf);
    return NULL;
}

int evr_append_ref_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd)){
    return append(ctx, "c.seed = ?");
}

int evr_bind_ref_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column){
    struct evr_attr_query_ref_cnd_data *data = node->data;
    if(sqlite3_bind_blob(stmt, (*column)++, data->ref, evr_claim_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        return evr_error;
    }
    return evr_ok;
}

struct evr_attr_query_eq_cnd_data {
    char *key;
    char *value;
};

int evr_append_eq_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd));

int evr_bind_eq_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column);

void evr_free_data_eq_cnd(void *data);

struct evr_attr_query_node *evr_attr_query_eq_cnd(char *key, char *value){
    struct evr_attr_query_node *ret = NULL;
    char *buf = malloc(sizeof(struct evr_attr_query_node) + sizeof(struct evr_attr_query_eq_cnd_data));
    if(!buf){
        goto out;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_map_struct(&bp, ret);
    ret->append_cnd = evr_append_eq_cnd;
    ret->bind = evr_bind_eq_cnd;
    ret->free_data = evr_free_data_eq_cnd;
    struct evr_attr_query_eq_cnd_data *data;
    evr_map_struct(&bp, data);
    ret->data = data;
    data->key = key;
    data->value = value;
 out:
    return ret;
}

int evr_append_eq_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd)){
    return append(ctx, "c.seed in (select seed from attr where key = ? and val_str = ? and valid_from <= ? and (valid_until > ? or valid_until is null) and val_str not null)");
}

int evr_bind_eq_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column){
    int ret = evr_error;
    struct evr_attr_query_eq_cnd_data *data = node->data;
    if(sqlite3_bind_text(stmt, (*column)++, data->key, -1, NULL) != SQLITE_OK){
        goto out;
    }
    if(sqlite3_bind_text(stmt, (*column)++, data->value, -1, NULL) != SQLITE_OK){
        goto out;
    }
    if(sqlite3_bind_int64(stmt, (*column)++, (sqlite3_int64)ctx->effective_time) != SQLITE_OK){
        goto out;
    }
    if(sqlite3_bind_int64(stmt, (*column)++, (sqlite3_int64)ctx->effective_time) != SQLITE_OK){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

void evr_free_data_eq_cnd(void *data){
    struct evr_attr_query_eq_cnd_data *d = data;
    free(d->key);
    free(d->value);
}

struct evr_attr_query_contains_cnd_data {
    char *key;
    char *needle;
};

int evr_append_contains_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd));

int evr_bind_contains_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column);

void evr_free_data_contains_cnd(void *data);

struct evr_attr_query_node *evr_attr_query_contains_cnd(char *key, char *needle){
    struct evr_attr_query_node *ret = NULL;
    char *buf = malloc(sizeof(struct evr_attr_query_node) + sizeof(struct evr_attr_query_contains_cnd_data));
    if(!buf){
        goto out;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_map_struct(&bp, ret);
    ret->append_cnd = evr_append_contains_cnd;
    ret->bind = evr_bind_contains_cnd;
    ret->free_data = evr_free_data_contains_cnd;
    struct evr_attr_query_contains_cnd_data *data;
    evr_map_struct(&bp, data);
    ret->data = data;
    data->key = key;
    data->needle = needle;
 out:
    return ret;
}

int evr_append_contains_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd)){
    // TODO lower only works for ascii -> use icu extension for utf-8 lower function
    return append(ctx, "c.seed in (select seed from attr where key = ? and glob(lower(\"*\" || ? || \"*\"), lower(val_str)) and valid_from <= ? and (valid_until > ? or valid_until is null) and val_str not null)");
}

int evr_bind_contains_cnd(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column){
    struct evr_attr_query_contains_cnd_data *data = node->data;
    if(sqlite3_bind_text(stmt, (*column)++, data->key, -1, NULL) != SQLITE_OK){
        return evr_error;
    }
    if(sqlite3_bind_text(stmt, (*column)++, data->needle, -1, NULL) != SQLITE_OK){
        return evr_error;
    }
    if(sqlite3_bind_int64(stmt, (*column)++, (sqlite3_int64)ctx->effective_time) != SQLITE_OK){
        return evr_error;
    }
    if(sqlite3_bind_int64(stmt, (*column)++, (sqlite3_int64)ctx->effective_time) != SQLITE_OK){
        return evr_error;
    }
    return evr_ok;
}

void evr_free_data_contains_cnd(void *data){
    struct evr_attr_query_contains_cnd_data *d = data;
    free(d->key);
    free(d->needle);
}

struct evr_attr_query_bool_bool_data {
    struct evr_attr_query_node *l;
    struct evr_attr_query_node *r;
};

int evr_append_bool_and(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd));

int evr_bind_bool(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column);

void evr_free_data_bool_data(void *data);

struct evr_attr_query_node *evr_attr_query_bool(struct evr_attr_query_node *l, struct evr_attr_query_node *r, int (*append_cnd)(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd)));

struct evr_attr_query_node *evr_attr_query_bool_and(struct evr_attr_query_node *l, struct evr_attr_query_node *r){
    return evr_attr_query_bool(l, r, evr_append_bool_and);
}

struct evr_attr_query_node *evr_attr_query_bool(struct evr_attr_query_node *l, struct evr_attr_query_node *r, int (*append_cnd)(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd))){
    struct evr_attr_query_node *ret = NULL;
    struct evr_attr_query_bool_bool_data *data;
    struct evr_buf_pos bp;
    char *buf;
    buf = malloc(sizeof(struct evr_attr_query_node) + sizeof(struct evr_attr_query_bool_bool_data));
    if(!buf){
        goto out;
    }
    evr_init_buf_pos(&bp, buf);
    evr_map_struct(&bp, ret);
    ret->append_cnd = append_cnd;
    ret->bind = evr_bind_bool;
    ret->free_data = evr_free_data_bool_data;
    evr_map_struct(&bp, data);
    ret->data = data;
    data->l = l;
    data->r = r;
 out:
    return ret;
}

int evr_append_bool(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd), char *join_str);

int evr_append_bool_and(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd)){
    return evr_append_bool(ctx, node, append, ") and (");
}

int evr_append_bool_or(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd));

struct evr_attr_query_node *evr_attr_query_bool_or(struct evr_attr_query_node *l, struct evr_attr_query_node *r){
    return evr_attr_query_bool(l, r, evr_append_bool_or);
}

int evr_append_bool_or(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd)){
    return evr_append_bool(ctx, node, append, ") or (");
}

int evr_append_bool(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd), char *join_str){
    int ret = evr_error;
    struct evr_attr_query_bool_bool_data *data = node->data;
    if(append(ctx, "(") != evr_ok){
        goto out;
    }
    if(data->l->append_cnd(ctx, data->l, append) != evr_ok){
        goto out;
    }
    if(append(ctx, join_str) != evr_ok){
        goto out;
    }
    if(data->r->append_cnd(ctx, data->r, append) != evr_ok){
        goto out;
    }
    if(append(ctx, ")") != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_bind_bool(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column){
    int ret = evr_error;
    struct evr_attr_query_bool_bool_data *data = node->data;
    if(data->l->bind(ctx, data->l, stmt, column) != evr_ok){
        goto out;
    }
    if(data->r->bind(ctx, data->r, stmt, column) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

void evr_free_data_bool_data(void *data){
    struct evr_attr_query_bool_bool_data *d = data;
    evr_free_attr_query_node(d->l);
    evr_free_attr_query_node(d->r);
}

void evr_free_attr_query_node(struct evr_attr_query_node *node){
    if(!node){
        return;
    }
    if(node->free_data){
        node->free_data(node->data);
    }
    free(node);
}

struct evr_attr_selector *evr_build_attr_selector(int type){
    struct evr_attr_selector *ret = malloc(sizeof(*ret));
    if(!ret){
        goto out;
    }
    ret->type = type;
 out:
    return ret;
}

struct evr_attr_query *evr_build_attr_query(struct evr_attr_selector *selector, struct evr_attr_query_node *root, evr_time effective_time, int limit, int offset){
    struct evr_attr_query *ret = malloc(sizeof(*ret));
    if(!ret){
        goto out;
    }
    ret->selector = selector;
    ret->root = root;
    ret->effective_time = effective_time;
    ret->limit = limit;
    ret->offset = offset;
 out:
    return ret;
}

void evr_free_attr_query(struct evr_attr_query *query){
    evr_free_attr_selector(query->selector);
    evr_free_attr_query_node(query->root);
    free(query);
}

int evr_parse_attr_query_int(int *i, char *s){
    if(sscanf(s, "%d", i) != 1){
        return evr_error;
    }
    return evr_ok;
}
