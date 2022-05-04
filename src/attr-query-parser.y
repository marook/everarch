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
 * The attr query language implements a boolean grammar for filtering
 * claims using their attributes.
 *
 * Each of the following lines are valid query examples:
 * tag=todo
 * mime-type=image/jpeg && tag=todo
 */

%{
#include "config.h"

#include <string.h>

#include "logger.h"
#include "attr-query-sql.h"

// This appears to be a bug. This typedef breaks a dependency cycle between the headers.
// See https://stackoverflow.com/questions/44103798/cyclic-dependency-in-reentrant-flex-bison-headers-with-union-yystype
typedef void * yyscan_t;

void yyerror(struct evr_attr_query_result *res, char const *e){
  res->error = strdup(e);
}

%}

%define api.push-pull push
%define api.pure full
%define parse.error detailed

%parse-param {struct evr_attr_query_result *res}

%union {
  struct evr_attr_query *query;
  struct evr_attr_selector *selector;
  struct evr_attr_query_node *node;
  char *string;
}

%{
int yylex(YYSTYPE *yylval_param);
%}

%token attr_key
%token BOOL_AND
%token EQ
%token <string> STRING
%destructor { free($$); } <string>;
%token REF
%token SELECT
%token WHERE
%token WILDCARD
%token END
%token UNKNOWN

%type <query> query;
%destructor { evr_free_attr_query($$); } <query>;
%type <selector> attr_selector;
%destructor { evr_free_attr_selector($$); } <selector>;
%type <node> conditions;
%type <node> condition;
%destructor { evr_free_attr_query_node($$); } <node>;

%%

line: query END { res->query = $1; };

query:
  conditions { $$ = evr_build_attr_query(evr_build_attr_selector(evr_attr_selector_none), $1); }
| SELECT attr_selector WHERE conditions { $$ = evr_build_attr_query($2, $4); }
;

attr_selector:
  WILDCARD { $$ = evr_build_attr_selector(evr_attr_selector_all); }
;

conditions:
  condition
| conditions BOOL_AND condition { evr_ret_node($$, evr_attr_query_bool_and($1, $3), "Unable to parse * && * condition."); }
;

condition:
  REF EQ STRING { evr_ret_node($$, evr_attr_query_ref_cnd($3), "Unable to parse ref=* condition."); }
| STRING EQ STRING { evr_ret_node($$, evr_attr_query_eq_cnd($1, $3), "Unable to parse *=* condition."); }
;

%%
