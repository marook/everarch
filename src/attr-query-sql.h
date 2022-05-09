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

#ifndef __attr_query_ast_h__
#define __attr_query_ast_h__

#include "config.h"

#include <time.h>
#include <sqlite3.h>

#include "basics.h"

// This appears to be a bug bison/flex. This typedef breaks a
// dependency cycle between the headers. See
// https://stackoverflow.com/questions/44103798/cyclic-dependency-in-reentrant-flex-bison-headers-with-union-yystype
typedef void * yyscan_t;

struct evr_attr_query_ctx {
    // TODO selected attributes
    evr_time t;
    void *more;
};

struct evr_attr_query_node {
    int (*append_cnd)(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, int (*append)(struct evr_attr_query_ctx *ctx, const char *cnd));
    int (*bind)(struct evr_attr_query_ctx *ctx, struct evr_attr_query_node *node, sqlite3_stmt *stmt, int *column);
    void (*free_data)(void *data);
    void *data;
};

// TODO make this a variadic macro and allow msg to be printf format string
#define evr_ret_node($$, node, msg)             \
    do {                                        \
        $$ = node;                              \
        if(!($$)) {                             \
            yyerror(res, msg);                  \
            YYERROR;                            \
        }                                       \
    } while(0)

struct evr_attr_query_node *evr_attr_query_ref_cnd(char *ref_str);

struct evr_attr_query_node *evr_attr_query_eq_cnd(char *key, char *value);

struct evr_attr_query_node *evr_attr_query_contains_cnd(char *key, char *needle);

struct evr_attr_query_node *evr_attr_query_bool_and(struct evr_attr_query_node *l, struct evr_attr_query_node *r);

void evr_free_attr_query_node(struct evr_attr_query_node *node);

#define evr_attr_selector_none 0x01
#define evr_attr_selector_all  0x02

struct evr_attr_selector {
    /**
     * type must be one of evr_attr_selector_*.
     */
    int type;
};

struct evr_attr_selector *evr_build_attr_selector(int type);

#define evr_free_attr_selector(s)               \
    do {                                        \
        if(s) free(s);                          \
    } while(0)

struct evr_attr_query {
    struct evr_attr_selector *selector;
    struct evr_attr_query_node *root;
};

struct evr_attr_query *evr_build_attr_query(struct evr_attr_selector *selector, struct evr_attr_query_node *root);

void evr_free_attr_query(struct evr_attr_query *query);

struct evr_attr_query_result {
    struct evr_attr_query *query;
    char *error;
};

#endif
