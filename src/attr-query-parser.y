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

#include "logger.h"
#include "attr-query-sql.h"

// This appears to be a bug. This typedef breaks a dependency cycle between the headers.
// See https://stackoverflow.com/questions/44103798/cyclic-dependency-in-reentrant-flex-bison-headers-with-union-yystype
typedef void * yyscan_t;

void yyerror(struct evr_attr_query_node **root, char const *e){
  // TODO transport errors towards request or something
  log_error("parser error: %s", e);
}

%}

%define api.push-pull push
%define api.pure full

%parse-param {struct evr_attr_query_node **root}

%union {
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

%type <node> conditions;
%type <node> condition;

%%

query: conditions { *root = $1; };

conditions:
  condition
| conditions BOOL_AND condition { $$ = evr_attr_query_bool_and($1, $3); }
;

condition:
  STRING EQ STRING { $$ = evr_attr_query_eq_cnd($1, $3); }
;

%%
