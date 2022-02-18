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

#include <fcntl.h>
#include <unistd.h>

#include "assert.h"
#include "files.h"
#include "test.h"
#include "errors.h"
#include "logger.h"

void test_read_fd_partial_file(){
    struct dynamic_array *buf = alloc_dynamic_array(1024);
    assert_not_null(buf);
    int f = open("/dev/random", O_RDONLY);
    assert_greater_then(f, -1);
    assert_ok(read_fd(&buf, f, 1024));
    assert_not_null(buf);
    assert_equal(buf->size_used, 1024);
    char sum = 0;
    for(size_t i = 0; i < buf->size_used; ++i){
        sum += buf->data[i];
    }
    log_debug("Accessed every byte in buf (%d)", sum);
    close(f);
    free(buf);
}

void test_read_empty_json_with_big_buffer(){
    struct dynamic_array *buffer = alloc_dynamic_array(1024);
    assert_not_null(buffer);
    assert_zero(read_file_str(&buffer, "etc/configuration/empty.json", 1024));
    assert_str_eq((char*)buffer->data, "{}\n");
    assert_size_eq(buffer->size_used, 4);
    free(buffer);
}

void test_read_empty_json_with_small_buffer(){
    struct dynamic_array *buffer = alloc_dynamic_array(1);
    assert_not_null(buffer);
    assert_zero(read_file_str(&buffer, "etc/configuration/empty.json", 1024));
    assert_str_eq((char*)buffer->data, "{}\n");
    assert_size_eq(buffer->size_used, 4);
    free(buffer);
}

void test_read_into_chunks_with_small_file(){
    int f = open("etc/configuration/empty.json", O_RDONLY);
    assert_truthy(f);
    struct chunk_set *cs = read_into_chunks(f, 2);
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
    struct chunk_set *cs = evr_allocate_chunk_set(0);
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

int slice_counter;
int small_slices_counter;
size_t slice_size_sum;

int visit_slice(char *buf, size_t size, void *ctx);

void test_rollsum_split_infinite_file(){
    slice_counter = 0;
    small_slices_counter = 0;
    slice_size_sum = 0;
    int f = open("/dev/random", O_RDONLY);
    size_t max_read = 10 << 20;
    assert_ok(evr_rollsum_split(f, max_read, visit_slice, NULL));
    close(f);
    assert_greater_then(2, small_slices_counter);
    assert_equal(slice_size_sum, max_read);
    log_info("Splitted into slices with average size of %d bytes", max_read / slice_counter);
}

void test_rollsum_split_tiny_file(){
    slice_counter = 0;
    small_slices_counter = 0;
    slice_size_sum = 0;
    int f = open("etc/configuration/empty.json", O_RDONLY);
    assert_equal(evr_rollsum_split(f, 10, visit_slice, NULL), evr_end);
    close(f);
    assert_greater_then(2, small_slices_counter);
    assert_equal(slice_counter, 1);
    assert_equal(slice_size_sum, 3);
}

int visit_slice(char *buf, size_t size, void *ctx){
    assert_null(ctx);
    slice_counter += 1;
    slice_size_sum += size;
    if(size < 64 << 10){ // 64k
        small_slices_counter += 1;
    }
    assert_greater_then(10 << 20, size); // 10M
    const char *end = &buf[size];
    int sum = 0;
    for(const char *it = buf; it != end; ++it){
        sum += *it;
    }
    if(size == 0 && sum > 0){
        // bogus operation so we make sure the for loop above is not
        // optimized away by the smart compiler.
        fail("Never ever");
    }
    return evr_ok;
}

int main(){
    run_test(test_read_fd_partial_file);
    run_test(test_read_empty_json_with_big_buffer);
    run_test(test_read_empty_json_with_small_buffer);
    run_test(test_read_into_chunks_with_small_file);
    run_test(test_append_into_chunk_set_with_small_file);
    run_test(test_rollsum_split_infinite_file);
    run_test(test_rollsum_split_tiny_file);
    return 0;
}
