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
#include "open-files.h"
#include "evr-glacier-client.h"

// mock
int evr_req_cmd_get_blob(struct evr_file *f, evr_blob_ref key, struct evr_resp_header *resp){
    return evr_error;
}

void test_open_close_many_files_sequentially(){
    struct evr_open_file_set set;
    assert(is_ok(evr_init_open_file_set(&set)));
    uint64_t fh;
    for(size_t i = 0; i < 100; ++i){
        assert_msg(is_ok(evr_allocate_open_file(&set, &fh)), "Unable to open for the %zu time", i + 1);
        assert(is_ok(evr_close_open_file(&set, fh)));
    }
    assert(is_ok(evr_empty_open_file_set(&set)));
}

void test_open_close_two_files_parallel(){
    struct evr_open_file_set set;
    assert(is_ok(evr_init_open_file_set(&set)));
    const size_t fh_len = 2;
    uint64_t fh[fh_len];
    for(size_t i = 0; i < fh_len; ++i){
        assert(is_ok(evr_allocate_open_file(&set, &fh[i])));
    }
    for(size_t i = 0; i < fh_len; ++i){
        assert(is_ok(evr_close_open_file(&set, fh[i])));
    }
    assert(is_ok(evr_empty_open_file_set(&set)));
}

int main(){
    evr_init_basics();
    run_test(test_open_close_many_files_sequentially);
    run_test(test_open_close_two_files_parallel);
    return 0;
}
