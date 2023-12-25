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
#include "errors.h"

void test_write_auth_token(void){
    struct evr_file_mem fm;
    assert(is_ok(evr_init_file_mem(&fm, 1024, 1024)));
    assert(fm.data);
    struct evr_file f;
    evr_file_bind_file_mem(&f, &fm);
    evr_auth_token t;
    memset(t, 42, sizeof(t));
    assert(is_ok(evr_attri_write_auth_token(&f, t)));
    assert(fm.data);
    char expected[] = "a token 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\n";
    assert(fm.offset == sizeof(expected) - 1);
    assert(memcmp(fm.data, expected, sizeof(expected) - 1) == 0);
    evr_destroy_file_mem(&fm);
}

void test_write_list_claims_for_seed(void){
    struct evr_file_mem fm;
    assert(is_ok(evr_init_file_mem(&fm, 1024, 1024)));
    assert(fm.data);
    struct evr_file f;
    evr_file_bind_file_mem(&f, &fm);
    evr_claim_ref seed;
    assert(is_ok(evr_parse_claim_ref(seed, "sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff-1234")));
    assert(is_ok(evr_attri_write_list_claims_for_seed(&f, seed)));
    char expected[] = "c sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff-1234\n";
    assert(fm.offset == sizeof(expected) - 1);
    assert(memcmp(fm.data, expected, sizeof(expected) - 1) == 0);
    evr_destroy_file_mem(&fm);
}

int test_read_search_visit_attr(void *ctx, evr_claim_ref claim_ref, char *key, char *val){
    int *state = ctx;
    evr_claim_ref expected_claim_ref;
    assert(is_ok(evr_parse_claim_ref(expected_claim_ref, "sha3-224-1bcc97e1092fcc9532881316663c6025d1b7c7faf92571cb2de5a995-0000")));
    assert(evr_cmp_claim_ref(claim_ref, expected_claim_ref) == 0);
    switch(*state){
    default:
        log_error("Unexpected state %d", *state);
        return evr_error;
    case 1:
        assert(is_str_eq(key, "title"));
        assert(is_str_eq(val, " my=title "));
        break;
    case 2:
        assert(is_str_eq(key, "file"));
        assert(is_str_eq(val, "sha3-224-1bcc97e1092fcc9532881316663c6025d1b7c7faf92571cb2de5a995-0000"));
        break;
    }
    *state += 1;
    return evr_ok;
}

void test_read_search(void){
    struct evr_file_mem fm;
    assert(is_ok(evr_init_file_mem(&fm, 1024, 1024)));
    assert(fm.data);
    struct evr_file f;
    evr_file_bind_file_mem(&f, &fm);
    char resp[] =
        "OK\n"
        "sha3-224-1bcc97e1092fcc9532881316663c6025d1b7c7faf92571cb2de5a995-0000\n"
        "	title= my=title \n"
        "	file=sha3-224-1bcc97e1092fcc9532881316663c6025d1b7c7faf92571cb2de5a995-0000\n"
        "\n"
        ;
    assert(is_ok(write_n(&f, resp, sizeof(resp) - 1)));
    fm.offset = 0;
    struct evr_buf_read *r = evr_create_buf_read(&f, 7);
    assert(r);
    int state = 1;
    assert(is_ok(evr_attri_read_search(r, NULL, test_read_search_visit_attr, &state)));
    assert(state == 3);
    evr_free_buf_read(r);
    evr_destroy_file_mem(&fm);
}

int main(void){
    evr_init_basics();
    run_test(test_write_auth_token);
    run_test(test_write_list_claims_for_seed);
    run_test(test_read_search);
    return 0;
}
