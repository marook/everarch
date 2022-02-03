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

typedef struct {
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
} dynamic_array;

/**
 * alloc_dynamic_array allocates a dynamic_array using malloc.
 *
 * Returns NULL if the memory could not be allocated.
 *
 * The returned dynamic_array can be freed using free(…).
 */
dynamic_array *alloc_dynamic_array(size_t initial_size);

#define grow_dynamic_array(da) grow_dynamic_array_at_least(da, 0)

/**
 * grow_dynamic_array grows the dynamic array using realloc.
 *
 * min_size is the minimum size_allocated after the grow.
 *
 * Returns NULL if the memory could not be allocated. The former memory
 * is freed in that case.
 */
dynamic_array *grow_dynamic_array_at_least(dynamic_array *da, size_t min_size);

void rtrim_dynamic_array(dynamic_array *da, int (*istrimmed)(int c));

/**
 * evr_chunk_size is the size of one chunk within the
 * evr_writing_blob_t struct in bytes.
 */
#define evr_chunk_size (1*1024*1024)

typedef struct {
    size_t chunks_len;
    char **chunks;
} chunk_set_t;

/**
 * evr_allocate_chunks allocates n chunks.
 *
 * Returns NULL if the chunk set could not be allocated.
 */
chunk_set_t *evr_allocate_chunk_set(size_t chunks_len);

void evr_free_chunk_set(chunk_set_t *cs);

#endif
