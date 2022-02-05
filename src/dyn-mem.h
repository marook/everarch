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

#ifndef __dyn_mem_h__
#define __dyn_mem_h__

#include <stdint.h>
#include <stdlib.h>

#include "basics.h"

struct dynamic_array {
    /**
     * size_allocated is the maximal number of bytes which are
     * allocated for data.
     */
    size_t size_allocated;

    /**
     * size_used is the currently number of bytes used within data.
     *
     * size_used must never be greater that size_allocated.
     */
    size_t size_used;
    
    void *data;
};

/**
 * alloc_dynamic_array allocates a dynamic_array using malloc.
 *
 * Returns NULL if the memory could not be allocated.
 *
 * The returned dynamic_array can be freed using free(…).
 */
struct dynamic_array *alloc_dynamic_array(size_t initial_size);

#define grow_dynamic_array(da) grow_dynamic_array_at_least(da, 0)

/**
 * grow_dynamic_array grows the dynamic array using realloc.
 *
 * min_size is the minimum size_allocated after the grow.
 *
 * Returns NULL if the memory could not be allocated. The former memory
 * is freed in that case.
 */
struct dynamic_array *grow_dynamic_array_at_least(struct dynamic_array *da, size_t min_size);

void rtrim_dynamic_array(struct dynamic_array *da, int (*istrimmed)(int c));

/**
 * evr_chunk_size is the size of one chunk within the
 * struct evr_writing_blob in bytes.
 */
#define evr_chunk_size (1*1024*1024)
#define evr_chunk_set_max_chunks (evr_max_blob_data_size / evr_chunk_size + 1)

struct chunk_set {
    size_t chunks_len;
    size_t size_used;
    char *chunks[evr_chunk_set_max_chunks];
};

/**
 * evr_allocate_chunks allocates n chunks.
 *
 * Returns NULL if the chunk set could not be allocated.
 */
struct chunk_set *evr_allocate_chunk_set(size_t chunks_len);

int evr_grow_chunk_set(struct chunk_set *cs, size_t new_chunks_len);

void evr_free_chunk_set(struct chunk_set *cs);

#endif
