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

#include "attr-query-parser.h"
#include "attr-query-lexer.h"
#include "attr-query-sql.h"
#include "logger.h"
#include "errors.h"

// This appears to be a bug. This typedef breaks a dependency cycle
// between the headers.
// See https://stackoverflow.com/questions/44103798/cyclic-dependency-in-reentrant-flex-bison-headers-with-union-yystype
typedef void * yyscan_t;

int append(const char *cnd);

int main(){
    int ret = 1;
    struct evr_attr_query_node *root = NULL;
    yyscan_t scanner;
    if(yylex_init(&scanner)){
        goto out;
    }
    if(!yy_scan_string("a=b && c=d", scanner)){
        goto out_with_destroy_scanner;
    }
    yypstate *ystate = yypstate_new();
    if(!ystate){
        goto out_with_destroy_scanner;
    }
    int status;
    YYSTYPE pushed_value;
    do {
        status = yypush_parse(ystate, yylex(&pushed_value, scanner), &pushed_value, &root);
    } while(status == YYPUSH_MORE);
    if(root) {
        if(root->append_cnd(NULL, root, append) != evr_ok){
            log_error("append_cnd failed");
            goto out;
        }
        evr_free_attr_query_node(root);
    } else {
        log_error("Failed to parse query");
        goto out_with_delete_ystate;
    }
    ret = 0;
 out_with_delete_ystate:
    yypstate_delete(ystate);
 out_with_destroy_scanner:
    yylex_destroy(scanner);
 out:
    return ret;
}

int append(const char *cnd){
    log_debug(">>> append: %s", cnd);
    return evr_ok;
}
