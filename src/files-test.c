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
#include "file-mem.h"

#define random_path "/dev/urandom"

void test_read_fd_partial_file(void){
    struct dynamic_array *buf = alloc_dynamic_array(1024);
    assert(buf);
    int f = open(random_path, O_RDONLY);
    assert(f > -1);
    assert(is_ok(read_fd(&buf, f, 1024)));
    assert(buf);
    assert(buf->size_used == 1024);
#ifdef EVR_LOG_DEBUG
    char sum = 0;
    for(size_t i = 0; i < buf->size_used; ++i){
        sum += buf->data[i];
    }
    log_debug("Accessed every byte in buf (%d)", sum);
#endif
    close(f);
    free(buf);
}

void test_read_into_chunks_with_small_file(void){
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

void test_append_into_chunk_set_with_small_file(void){
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

void test_rollsum_split_infinite_file(void){
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

void test_rollsum_split_tiny_file(void){
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

void test_buf_read_bytes_ready(void){
    struct evr_file_mem fm;
    assert(is_ok(evr_init_file_mem(&fm, 32, 32)));
    assert(fm.data);
    struct evr_file f;
    evr_file_bind_file_mem(&f, &fm);
    char data[] = "hello!";
    assert(is_ok(write_n(&f, data, sizeof(data) - 1)));
    fm.offset = 0;
    struct evr_buf_read *br = evr_create_buf_read(&f, 2);
    assert(br);
    size_t bytes_ready = evr_buf_read_bytes_ready(br);
    assert_msg(bytes_ready == 0, "But was %zu", bytes_ready);
    ssize_t bytes_read = evr_buf_read_read(br);
    // br ring buffer has allocated 2^2 = 4 bytes so it has capacity
    // of 3.
    assert_msg(bytes_read == 3, "But was %zd", bytes_read);
    bytes_ready = evr_buf_read_bytes_ready(br);
    assert_msg(bytes_ready == 3, "But was %zu", bytes_ready);
    assert(evr_buf_read_peek(br, 0) == 'h');
    assert(evr_buf_read_peek(br, 1) == 'e');
    char rbuf[3];
    rbuf[0] = 'x';
    assert(is_ok(evr_buf_read_pop(br, rbuf, 1)));
    assert(rbuf[0] == 'h');
    bytes_ready = evr_buf_read_bytes_ready(br);
    assert_msg(bytes_ready == 2, "But was %zu", bytes_ready);
    assert(evr_buf_read_peek(br, 0) == 'e');
    bytes_read = evr_buf_read_read(br);
    assert_msg(bytes_read == 1, "But was %zd", bytes_read);
    bytes_ready = evr_buf_read_bytes_ready(br);
    assert_msg(bytes_ready == 3, "But was %zu", bytes_ready);
    assert(evr_buf_read_peek(br, 0) == 'e');
    assert(evr_buf_read_peek(br, 1) == 'l');
    assert(evr_buf_read_peek(br, 2) == 'l');
    rbuf[0] = 'x';
    rbuf[1] = 'x';
    assert(is_ok(evr_buf_read_pop(br, rbuf, 2)));
    assert(rbuf[0] == 'e');
    assert(rbuf[1] == 'l');
    bytes_read = 0;
    while(bytes_read < 2){
        // we read the bytes in this while loop because currently the
        // implementation is not very optimized and requires multiple
        // underlying read calls to fetch two bytes IF they overlap
        // the limits of the ring buffer. this while loop
        // implementation must not break even if the implementation is
        // optimized in the future.
        int brc = evr_buf_read_read(br);
        assert(brc > 0);
        bytes_read += brc;
    }
    bytes_ready = evr_buf_read_bytes_ready(br);
    assert_msg(bytes_ready == 3, "But was %zu", bytes_ready);
    assert(evr_buf_read_peek(br, 0) == 'l');
    bytes_read = evr_buf_read_read(br);
    assert(evr_buf_read_peek(br, 1) == 'o');
    bytes_read = evr_buf_read_read(br);
    assert(evr_buf_read_peek(br, 2) == '!');
    bytes_read = evr_buf_read_read(br);
    assert(evr_buf_read_read(br) == 0);
    evr_free_buf_read(br);
    evr_destroy_file_mem(&fm);
}

int main(void){
    evr_init_basics();
    run_test(test_read_fd_partial_file);
    run_test(test_read_into_chunks_with_small_file);
    run_test(test_append_into_chunk_set_with_small_file);
    run_test(test_rollsum_split_infinite_file);
    run_test(test_rollsum_split_tiny_file);
    run_test(test_buf_read_bytes_ready);
    return 0;
}
