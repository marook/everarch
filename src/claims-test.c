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

#include "assert.h"
#include "claims.h"
#include "test.h"

time_t t0 = 0;

void assert_file_claim(const struct evr_file_claim *claim, const char *expected_file_document);

void test_empty_claim_without_finalize(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    assert_ok(evr_free_claim_set(&cs));
}

void test_empty_claim(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    assert_ok(evr_finalize_claim_set(&cs));
    assert_str_eq((char*)cs.out->content, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<claim-set dc:created=\"1970-01-01T00:00:00Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\"/>\n");
    assert_ok(evr_free_claim_set(&cs));
}

void test_file_claim_with_filename(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    evr_blob_key_t key;
    memset(key, 0, sizeof(key));
    const struct evr_file_claim claim = {
        "test.txt",
        1,
        &key,
    };
    assert_file_claim(&claim, "<file dc:title=\"test.txt\"><body><segment ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\"/></body></file>");
}

void test_file_claim_with_null_filename(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    evr_blob_key_t key;
    memset(key, 0, sizeof(key));
    const struct evr_file_claim claim = {
        NULL,
        1,
        &key,
    };
    assert_file_claim(&claim, "<file><body><segment ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\"/></body></file>");
}

void test_file_claim_with_empty_filename(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    evr_blob_key_t key;
    memset(key, 0, sizeof(key));
    const struct evr_file_claim claim = {
        "",
        1,
        &key,
    };
    assert_file_claim(&claim, "<file><body><segment ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\"/></body></file>");
}

void assert_file_claim(const struct evr_file_claim *claim, const char *expected_file_document){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    assert_ok(evr_append_file_claim(&cs, claim));
    assert_ok(evr_finalize_claim_set(&cs));
    assert_not_null(strstr((char*)cs.out->content, expected_file_document));
    assert_ok(evr_free_claim_set(&cs));
}

int main(){
    run_test(test_empty_claim_without_finalize);
    run_test(test_empty_claim);
    run_test(test_file_claim_with_filename);
    run_test(test_file_claim_with_null_filename);
    run_test(test_file_claim_with_empty_filename);
    return 0;
}
