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

#include "errors.h"
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
%define parse.error verbose

%parse-param {struct evr_attr_query_result *res}

%union {
  struct evr_attr_query *query;
  struct evr_attr_selector *selector;
  struct evr_attr_query_node *node;
  char *string;
  evr_time timestamp;
  int i;
}

%{
int yylex(YYSTYPE *yylval_param);
%}

%token attr_key
%token BOOL_AND
%token BOOL_OR
%token EQ
%token B_OPEN
%token B_CLOSE
%token <string> STRING
%destructor { free($$); } <string>;
%token REF
%token SELECT
%token WHERE
%token WILDCARD
%token AT
%token OFFSET
%token LIMIT
%token CONTAINS
%token END
%token UNKNOWN

%type <query> query;
%destructor { evr_free_attr_query($$); } <query>;
%type <selector> attr_selector;
%destructor { evr_free_attr_selector($$); } <selector>;
%type <node> condition;
%type <node> condition_or_empty;
%destructor { evr_free_attr_query_node($$); } <node>;
%type <timestamp> at_expression;
%type <i> offset_expression;
%type <i> limit_expression;

%left EQ CONTAINS
%left BOOL_OR
%left BOOL_AND

%%

line:
  END { evr_time t; evr_now(&t); res->query = evr_build_attr_query(NULL, NULL, t, evr_default_attr_query_limit, 0); }
| query END { res->query = $1; }
;

query:
  condition_or_empty at_expression limit_expression offset_expression { $$ = evr_build_attr_query(evr_build_attr_selector(evr_attr_selector_none), $1, $2, $3, $4); }
| attr_selector WHERE condition_or_empty at_expression limit_expression offset_expression { $$ = evr_build_attr_query($1, $3, $4, $5, $6); }
| attr_selector at_expression limit_expression offset_expression {{ $$ = evr_build_attr_query($1, NULL, $2, $3, $4); }}
;

attr_selector:
%empty { $$ = NULL; }
|  SELECT WILDCARD { $$ = evr_build_attr_selector(evr_attr_selector_all); }
;

condition_or_empty:
%empty { $$ = NULL; }
| condition;

condition:
REF EQ STRING { evr_ret_node($$, evr_attr_query_ref_cnd($3), "Unable to parse ref=* condition."); }
| STRING EQ STRING { evr_ret_node($$, evr_attr_query_eq_cnd($1, $3), "Unable to parse *=* condition."); }
| STRING CONTAINS STRING { evr_ret_node($$, evr_attr_query_contains_cnd($1, $3), "Unable to parse *~* condition."); }
| B_OPEN condition B_CLOSE { $$ = $2; }
| condition BOOL_OR condition { evr_ret_node($$, evr_attr_query_bool_or($1, $3), "Unable to parse * && * condition."); }
| condition BOOL_AND condition { evr_ret_node($$, evr_attr_query_bool_and($1, $3), "Unable to parse * && * condition."); }
;

at_expression:
%empty { evr_now(&($$)); }
| AT STRING { int time_parse_res = evr_time_from_anything(&($$), $2); free($2); if(time_parse_res != evr_ok){ yyerror(res, "Unable to parse 'at' timestamp"); YYERROR; }  }
;

limit_expression:
%empty { $$ = evr_default_attr_query_limit; }
| LIMIT STRING { int int_parse_res = evr_parse_attr_query_int(&($$), $2); free($2); if(int_parse_res != evr_ok) { yyerror(res, "Unable to parse limit integer"); YYERROR; } }
;

offset_expression:
%empty { $$ = 0; }
| OFFSET STRING { int int_parse_res = evr_parse_attr_query_int(&($$), $2); free($2); if(int_parse_res != evr_ok) { yyerror(res, "Unable to parse offset integer"); YYERROR; } }
;

%%
