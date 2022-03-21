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

#include <string.h>

#include "assert.h"
#include "keys.h"
#include "test.h"
#include "logger.h"

void test_evr_fmt_key_into(){
    evr_blob_ref_str fmt_key;
    evr_blob_ref key;
    memset(key, 0, evr_blob_ref_size);
    evr_fmt_blob_ref(fmt_key, key);
    assert_str_eq(fmt_key, "sha3-224-00000000000000000000000000000000000000000000000000000000");
    memset(key, 255, evr_blob_ref_size);
    evr_fmt_blob_ref(fmt_key, key);
    assert_str_eq(fmt_key, "sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

void test_evr_parse_blob_ref(){
    evr_blob_ref key;
    assert_ok(evr_parse_blob_ref(key, "sha3-224-010203ff000000000000000000000000000000000000000000000000"));
    assert_equal(key[0], 0x01);
    assert_equal(key[1], 0x02);
    assert_equal(key[2], 0x03);
    assert_equal(key[3], 0xff);
}

void test_calc_blob_key(){
    evr_blob_ref key;
    evr_blob_ref_str fmt_key;
    char *chunks = "hello world";
    assert_ok(evr_calc_blob_ref(key, strlen(chunks), (char**)&chunks));
    evr_fmt_blob_ref(fmt_key, key);
    assert_str_eq(fmt_key, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5");
}

void test_build_fmt_claim_ref(){
    evr_blob_ref bref;
    evr_parse_blob_ref(bref, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5");
    evr_claim_ref cref;
    evr_build_claim_ref(cref, bref, 65000);
    evr_claim_ref_str cref_str;
    evr_fmt_claim_ref(cref_str, cref);
    assert_str_eq(cref_str, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5-fde8");
    evr_build_claim_ref(cref, bref, 0);
    evr_fmt_claim_ref(cref_str, cref);
    assert_str_eq(cref_str, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5-0000");
}

void test_parse_fmt_claim_ref(){
    evr_claim_ref in;
    evr_parse_claim_ref(in, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5-fde8");
    evr_claim_ref_str out_str;
    evr_fmt_claim_ref(out_str, in);
    assert_str_eq(out_str, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5-fde8");
}

int main(){
    run_test(test_evr_fmt_key_into);
    run_test(test_evr_parse_blob_ref);
    run_test(test_calc_blob_key);
    run_test(test_build_fmt_claim_ref);
    run_test(test_parse_fmt_claim_ref);
    return 0;
}
