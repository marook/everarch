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

#include <ctype.h>
#include <string.h>

#include "assert.h"
#include "dyn-mem.h"
#include "test.h"

int is_ignored(int c);

void test_rtrim_empty_array(){
    dynamic_array *a = alloc_dynamic_array(1);
    rtrim_dynamic_array(a, is_ignored);
    assert_size_eq(a->size_used, 0);
    free(a);
}

void test_rtrim_end_of_array(){
    dynamic_array *a = alloc_dynamic_array(1024);
    strcpy((char*)a->data, "test   ");
    a->size_used = strlen((char*)a->data) + 1;
    rtrim_dynamic_array(a, is_ignored);
    assert_size_eq(a->size_used, strlen("test"));
    free(a);
}

int is_ignored(int c){
    return c == 0 || isspace(c);
}

void test_allocate_chunk_set(){
    chunk_set_t *cs = evr_allocate_chunk_set(3);
    assert_not_null(cs);
    assert_equal(cs->chunks_len, 3);
    // write into every byte of the chunk set to force an error in
    // valgrind if too less memory was allocated.
    for(int i = 0; i < cs->chunks_len; i++){
        uint8_t *c = cs->chunks[i];
        memset(c, 42, evr_chunk_size);
    }
    evr_free_chunk_set(cs);
}

int main(){
    run_test(test_rtrim_empty_array);
    run_test(test_rtrim_end_of_array);
    run_test(test_allocate_chunk_set);
    return 0;
}
