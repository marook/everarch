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

#include "config.h"

#include "auth.h"
#include "assert.h"
#include "test.h"

void test_parse_auth_token(){
    evr_auth_token t;
    assert(is_err(evr_parse_auth_token(t, "")));
    assert(is_err(evr_parse_auth_token(t, "00")));
    assert(is_ok(evr_parse_auth_token(t, "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff")));
    assert(t[0] == 0);
    assert(t[1] == (char)0xff);
}

void test_parse_and_push_auth_token(){
    struct evr_auth_token_cfg *cfg = NULL;
    assert(is_ok(evr_parse_and_push_auth_token(&cfg, "ye-host:1234:00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff")));
    assert(is_str_eq(cfg->host, "ye-host"));
    assert(is_str_eq(cfg->port, "1234"));
    assert(cfg->token[0] == 0);
    assert(cfg->token[1] == (char)0xff);
    evr_free_auth_token_chain(cfg);
}

int main(){
    run_test(test_parse_auth_token);
    run_test(test_parse_and_push_auth_token);
    return 0;
}
