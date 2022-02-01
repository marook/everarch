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

#include "dyn-mem.h"

inline size_t get_dynamic_array_size(size_t data_size);

dynamic_array *alloc_dynamic_array(size_t initial_size){
    size_t da_size = get_dynamic_array_size(initial_size);
    dynamic_array *da = (dynamic_array*)malloc(da_size);
    if(!da){
        return NULL;
    }
    da->size_allocated = initial_size;
    da->size_used = 0;
    da->data = &(da[1]);
    return da;
}

dynamic_array *grow_dynamic_array_at_least(dynamic_array *da, size_t min_size){
    // + 1 because we want to avoid size not growing when small
    size_t new_size = (size_t)(da->size_allocated * 1.5) + 1;
    if(new_size < min_size){
        new_size = min_size;
    }
    size_t new_da_size = get_dynamic_array_size(new_size);
    dynamic_array *new_da = (dynamic_array*)realloc(da, new_da_size);
    if(!new_da){
        free(da);
        return NULL;
    }
    new_da->size_allocated = new_size;
    new_da->data = &(new_da[1]);
    return new_da;
}

inline size_t get_dynamic_array_size(size_t data_size){
    return sizeof(dynamic_array) + data_size;
}

void rtrim_dynamic_array(dynamic_array *da, int (*istrimmed)(int c)){
    char *it = &(((char*)da->data)[da->size_used]);
    for(; it-1 > (char*)da->data; it--){
        if(!istrimmed(*(it - 1))){
            break;
        }
    }
    da->size_used = it - (char*)da->data;
}

chunk_set_t* evr_allocate_chunk_set(size_t chunks_len){
    size_t header_size = sizeof(chunk_set_t) + sizeof(uint8_t**) * chunks_len;
    uint8_t *p = malloc(header_size + chunks_len * evr_chunk_size);
    if(!p){
        return NULL;
    }
    chunk_set_t *cs = (chunk_set_t*)p;
    p = (uint8_t*)&cs[1];
    cs->chunks_len = chunks_len;
    cs->chunks = (uint8_t**)p;
    p = (uint8_t*)&cs->chunks[chunks_len];
    for(int i = 0; i < chunks_len; i++){
        cs->chunks[i] = p;
        p += evr_chunk_size;
    }
    return cs;
}

void evr_free_chunk_set(chunk_set_t *cs){
    free(cs);
}