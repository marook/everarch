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

%{
#include "config.h"

#include <string.h>

#include "attr-query-sql.h"
#include "attr-query-parser.h"
%}

/*
 * See https://github.com/mwberry/yacc-examples/blob/master/push/push.lex#L6
 * for reasoning about reentrant and bison-bridge.
 */
%option reentrant
%option bison-bridge

%option noyywrap
%option noinput
%option nounput

%%

"&&"	{ return BOOL_AND; };
"="	{ return EQ; };
"select"	{ return SELECT; };
"where"		{ return WHERE; };
"*"	{ return WILDCARD; };

[a-zA-Z0-9][a-zA-Z0-9_.-]*	{ yylval->string = strdup(yytext); return STRING; };

[ \t]*	{ };

[\n] { return END; };
<<EOF>> { return END; };

.  { return UNKNOWN; };

%%
