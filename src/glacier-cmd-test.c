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

#include "glacier-cmd.h"
#include "test.h"
#include "assert.h"

void test_format_parse_cmd_header(){
    struct evr_cmd_header in;
    in.type = evr_cmd_type_get_blob;
    in.body_size = 42;
    char buffer[evr_cmd_header_n_size];
    assert(is_ok(evr_format_cmd_header(buffer, &in)));
    struct evr_cmd_header out;
    assert(is_ok(evr_parse_cmd_header(&out, buffer)));
    assert(out.type == evr_cmd_type_get_blob);
    assert(out.body_size == 42);
}

void test_format_parse_resp_header(){
    struct evr_resp_header in;
    in.status_code = evr_status_code_unknown_cmd;
    in.body_size = 666;
    char buffer[evr_resp_header_n_size];
    assert(is_ok(evr_format_resp_header(buffer, &in)));
    struct evr_resp_header out;
    assert(is_ok(evr_parse_resp_header(&out, buffer)));
    assert(out.status_code == evr_status_code_unknown_cmd);
    assert(out.body_size == 666);
}

int main(){
    evr_init_basics();
    run_test(test_format_parse_cmd_header);
    run_test(test_format_parse_resp_header);
    return 0;
}
