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

#define random_path "/dev/urandom"

void test_read_fd_partial_file(){
    struct dynamic_array *buf = alloc_dynamic_array(1024);
    assert(buf);
    int f = open(random_path, O_RDONLY);
    assert(f > -1);
    assert(is_ok(read_fd(&buf, f, 1024)));
    assert(buf);
    assert(buf->size_used == 1024);
    char sum = 0;
    for(size_t i = 0; i < buf->size_used; ++i){
        sum += buf->data[i];
    }
    log_debug("Accessed every byte in buf (%d)", sum);
    close(f);
    free(buf);
}

void test_read_into_chunks_with_small_file(){
    int fd = open("../etc/configuration/empty.json", O_RDONLY);
    assert(fd >= 0);
    struct evr_file f;
    evr_file_bind_fd(&f, fd);
    struct chunk_set *cs = read_into_chunks(&f, 2, NULL, NULL);
    assert(f.close(&f) == 0);
    assert(cs);
    assert(cs->chunks_len == 1);
    assert(cs->size_used == 2);
    assert(cs->chunks[0][0] == '{');
    assert(cs->chunks[0][1] == '}');
    evr_free_chunk_set(cs);
}

void test_append_into_chunk_set_with_small_file(){
    int f = open("../etc/configuration/empty.json", O_RDONLY);
    assert(f >= 0);
    struct chunk_set *cs = evr_allocate_chunk_set(0);
    assert(cs);
    assert(is_ok(append_into_chunk_set(cs, f)));
    close(f);
    assert(cs);
    assert(cs->chunks_len == 1);
    assert(cs->size_used == 3);
    assert(cs->chunks[0][0] == '{');
    assert(cs->chunks[0][1] == '}');
    assert(cs->chunks[0][2] == '\n');
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
    int f = open(random_path, O_RDONLY);
    size_t max_read = 10 << 20;
    assert(is_ok(evr_rollsum_split(f, max_read, visit_slice, NULL)));
    close(f);
    assert(small_slices_counter < 2);
    assert(slice_size_sum == max_read);
    log_info("Splitted into slices with average size of %d bytes", max_read / slice_counter);
}

void test_rollsum_split_tiny_file(){
    slice_counter = 0;
    small_slices_counter = 0;
    slice_size_sum = 0;
    int f = open("../etc/configuration/empty.json", O_RDONLY);
    assert(evr_rollsum_split(f, 10, visit_slice, NULL) == evr_end);
    close(f);
    assert(small_slices_counter < 2);
    assert(slice_counter == 1);
    assert(slice_size_sum == 3);
}

int visit_slice(char *buf, size_t size, void *ctx){
    assert(ctx == NULL);
    slice_counter += 1;
    slice_size_sum += size;
    if(size < 64<<10){ // 64k
        small_slices_counter += 1;
    }
    assert(size < 10<<20); // 10M
    const char *end = &buf[size];
    int sum = 0;
    for(const char *it = buf; it != end; ++it){
        sum += *it;
    }
    if(size == 0 && sum > 0){
        // bogus operation so we make sure the for loop above is not
        // optimized away by the smart compiler.
        fail();
    }
    return evr_ok;
}

int main(){
    run_test(test_read_fd_partial_file);
    run_test(test_read_into_chunks_with_small_file);
    run_test(test_append_into_chunk_set_with_small_file);
    run_test(test_rollsum_split_infinite_file);
    run_test(test_rollsum_split_tiny_file);
    return 0;
}
