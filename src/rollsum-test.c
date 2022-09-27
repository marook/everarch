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
#include <stdlib.h>

#include "assert.h"
#include "rollsum.h"
#include "test.h"
#include "logger.h"

#define window_size 64

#define avg_blob_size (1 << 13)

int split(struct Rollsum *rs){
    return (rs->s2 & (avg_blob_size - 1)) == (-1 & (avg_blob_size - 1));
}

#define max_splits 100

int print_splits(char *buffer, size_t buffer_size, size_t *splits);

void test_zero_input_rollsum(){
    const size_t buffer_size = 5 * 8 * 1024;
    char *buffer = malloc(buffer_size);
    assert(buffer);
    srand(1);
    for(size_t i = 0; i < buffer_size; ++i){
        buffer[i] = rand();
    }

    size_t splits0[max_splits];
    memset(splits0, 0, sizeof(size_t) * max_splits);
    int splits0_len = print_splits(buffer, buffer_size, splits0);

    log_info("buffer[12] += 1");
    buffer[12] += 1;
    size_t splits1[max_splits];
    memset(splits1, 0, sizeof(size_t) * max_splits);
    int splits1_len = print_splits(buffer, buffer_size, splits1);
    buffer[12] -= 1; // restore
    
    log_info("del buffer[12]");
    memmove(&buffer[12], &buffer[13], buffer_size - 13);
    size_t splits2[max_splits];
    memset(splits2, 0, sizeof(size_t) * max_splits);
    size_t splits2_len = print_splits(buffer, buffer_size, splits2);

    assert(splits0_len == splits1_len);
    assert(splits0_len == splits2_len);
    assert(splits0_len >= 1);
    // there are some not very perfect assumptions involved in the
    // next assertion. we assume that the "del buffer[12]" affects the
    // first split. also we assume it affects the first split in a way
    // that makes the split shift. happend to me with glibc rand
    // numbers.
    assert(splits1[0] == splits2[0] + 1);

    free(buffer);
}

int print_splits(char *buffer, size_t buffer_size, size_t *splits){
    struct Rollsum rs;
    RollsumInit(&rs);
    int split_count = 0;
    size_t last_split = 0;
    printf("Splits: ");
    for(size_t i = 0; i < buffer_size; ++i){
        if(i < window_size){
            RollsumRollin(&rs, (unsigned char)buffer[i]);
        } else {
            RollsumRotate(&rs, (unsigned char)buffer[i - window_size], (unsigned char)buffer[i]);
        }
        if(split(&rs)){
            splits[split_count] = i;
            ++split_count;
            printf(" %ld(+%ld)", i, i - last_split);
            last_split = i;
        }
    }
    printf("\n");
    log_info("Splitted on average every %d bytes", buffer_size / split_count);
    return split_count;
}

int main(){
    evr_init_basics();
    run_test(test_zero_input_rollsum);
    return 0;
}
