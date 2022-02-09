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

void test_fill_dynamic_array(){
    struct dynamic_array *a = alloc_dynamic_array(1);
    assert_not_null(a);
    a->size_used = 1;
    *(char*)a->data = 42;
    free(a);
}

void test_rtrim_empty_array(){
    struct dynamic_array *a = alloc_dynamic_array(1);
    assert_not_null(a);
    rtrim_dynamic_array(a, is_ignored);
    assert_size_eq(a->size_used, 0);
    free(a);
}

void test_rtrim_end_of_array(){
    struct dynamic_array *a = alloc_dynamic_array(1024);
    assert_not_null(a);
    strcpy((char*)a->data, "test   ");
    a->size_used = strlen((char*)a->data) + 1;
    rtrim_dynamic_array(a, is_ignored);
    assert_size_eq(a->size_used, strlen("test"));
    free(a);
}

void test_grow_dynamic_array_at_least_existing(){
    struct dynamic_array *a = alloc_dynamic_array(1);
    assert_not_null(a);
    assert_equal(a->size_allocated, 1);
    a->size_used = 1;
    *(char*)a->data = 42;
    a = grow_dynamic_array_at_least(a, 2);
    assert_not_null(a);
    assert_equal(a->size_allocated, 2);
    assert_equal(a->size_used, 1);
    assert_equal(*(char*)a->data, 42);
    free(a);
}

void test_grow_dynamic_array_at_least_null(){
    struct dynamic_array *a = NULL;
    a = grow_dynamic_array_at_least(a, 1);
    assert_not_null(a);
    assert_equal(a->size_allocated, 1);
    assert_equal(a->size_used, 0);
    free(a);
}

int is_ignored(int c){
    return c == 0 || isspace(c);
}

void test_allocate_chunk_set(){
    struct chunk_set *cs = evr_allocate_chunk_set(3);
    assert_not_null(cs);
    assert_equal(cs->chunks_len, 3);
    // write into every byte of the chunk set to force an error in
    // valgrind if too less memory was allocated.
    for(int i = 0; i < cs->chunks_len; i++){
        char *c = cs->chunks[i];
        memset(c, 42, evr_chunk_size);
    }
    evr_free_chunk_set(cs);
}

int main(){
    run_test(test_fill_dynamic_array);
    run_test(test_rtrim_empty_array);
    run_test(test_rtrim_end_of_array);
    run_test(test_grow_dynamic_array_at_least_existing);
    run_test(test_grow_dynamic_array_at_least_null);
    run_test(test_allocate_chunk_set);
    return 0;
}
