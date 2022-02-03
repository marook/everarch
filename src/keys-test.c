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

#include <string.h>

#include "assert.h"
#include "keys.h"
#include "test.h"
#include "logger.h"

void test_evr_fmt_key_into(){
    evr_fmt_blob_key_t fmt_key;
    evr_blob_key_t key;
    memset(key, 0, evr_blob_key_size);
    evr_fmt_blob_key(fmt_key, key);
    assert_str_eq(fmt_key, "sha3-224-00000000000000000000000000000000000000000000000000000000");
    memset(key, 255, evr_blob_key_size);
    evr_fmt_blob_key(fmt_key, key);
    assert_str_eq(fmt_key, "sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

void test_evr_parse_blob_key(){
    evr_blob_key_t key;
    assert_ok(evr_parse_blob_key(key, "sha3-224-010203ff000000000000000000000000000000000000000000000000"));
    assert_equal(key[0], 0x01);
    assert_equal(key[1], 0x02);
    assert_equal(key[2], 0x03);
    assert_equal(key[3], 0xff);
}

void test_calc_blob_key(){
    evr_blob_key_t key;
    evr_fmt_blob_key_t fmt_key;
    char *chunks = "hello world";
    assert_ok(evr_calc_blob_key(key, strlen(chunks), (char**)&chunks));
    evr_fmt_blob_key(fmt_key, key);
    assert_str_eq(fmt_key, "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5");
}

int main(){
    run_test(test_evr_fmt_key_into);
    run_test(test_evr_parse_blob_key);
    run_test(test_calc_blob_key);
    return 0;
}
