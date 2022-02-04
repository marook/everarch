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

#include <fcntl.h>
#include <unistd.h>

#include "assert.h"
#include "files.h"
#include "test.h"

void test_read_empty_json_with_big_buffer(){
    dynamic_array *buffer = alloc_dynamic_array(1024);
    assert_not_null(buffer);
    assert_zero(read_file_str(&buffer, "etc/configuration/empty.json", 1024));
    assert_str_eq((char*)buffer->data, "{}\n");
    assert_size_eq(buffer->size_used, 4);
    free(buffer);
}

void test_read_empty_json_with_small_buffer(){
    dynamic_array *buffer = alloc_dynamic_array(1);
    assert_not_null(buffer);
    assert_zero(read_file_str(&buffer, "etc/configuration/empty.json", 1024));
    assert_str_eq((char*)buffer->data, "{}\n");
    assert_size_eq(buffer->size_used, 4);
    free(buffer);
}

void test_read_into_chunks_with_small_file(){
    int f = open("etc/configuration/empty.json", O_RDONLY);
    assert_truthy(f);
    chunk_set_t *cs = read_into_chunks(f, 2);
    close(f);
    assert_not_null(cs);
    assert_equal(cs->chunks_len, 1);
    assert_equal(cs->size_used, 2);
    assert_equal(cs->chunks[0][0], '{');
    assert_equal(cs->chunks[0][1], '}');
    evr_free_chunk_set(cs);
}

void test_append_into_chunk_set_with_small_file(){
    int f = open("etc/configuration/empty.json", O_RDONLY);
    assert_truthy(f);
    chunk_set_t *cs = evr_allocate_chunk_set(0);
    assert_not_null(cs);
    assert_ok(append_into_chunk_set(cs, f));
    close(f);
    assert_not_null(cs);
    assert_equal(cs->chunks_len, 1);
    assert_equal(cs->size_used, 3);
    assert_equal(cs->chunks[0][0], '{');
    assert_equal(cs->chunks[0][1], '}');
    assert_equal(cs->chunks[0][2], '\n');
    evr_free_chunk_set(cs);
    
}

int main(){
    run_test(test_read_empty_json_with_big_buffer);
    run_test(test_read_empty_json_with_small_buffer);
    run_test(test_read_into_chunks_with_small_file);
    run_test(test_append_into_chunk_set_with_small_file);
    return 0;
}
