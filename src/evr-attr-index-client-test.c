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

#include "assert.h"
#include "test.h"
#include "evr-attr-index-client.h"
#include "file-mem.h"
#include "logger.h"

void test_write_auth_token(){
    struct evr_file_mem fm;
    evr_init_file_mem(&fm, 1024);
    assert(fm.data);
    struct evr_file f;
    evr_file_bind_file_mem(&f, &fm);
    evr_auth_token t;
    memset(t, 42, sizeof(t));
    assert(is_ok(evr_attri_write_auth_token(&f, t)));
    assert(fm.data);
    char expected[] = "a 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\n";
    assert(fm.offset == sizeof(expected) - 1);
    assert(memcmp(fm.data->data, expected, sizeof(expected) - 1) == 0);
    free(fm.data);
}

void test_write_list_claims_for_seed(){
    struct evr_file_mem fm;
    evr_init_file_mem(&fm, 1024);
    assert(fm.data);
    struct evr_file f;
    evr_file_bind_file_mem(&f, &fm);
    evr_claim_ref seed;
    assert(is_ok(evr_parse_claim_ref(seed, "sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff-1234")));
    assert(is_ok(evr_attri_write_list_claims_for_seed(&f, seed)));
    char expected[] = "c sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff-1234\n";
    assert(fm.offset == sizeof(expected) - 1);
    assert(memcmp(fm.data->data, expected, sizeof(expected) - 1) == 0);
    free(fm.data);
}

int main(){
    evr_init_basics();
    run_test(test_write_auth_token);
    run_test(test_write_list_claims_for_seed);
    return 0;
}
