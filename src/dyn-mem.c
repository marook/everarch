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

#include "errors.h"

inline size_t get_dynamic_array_size(size_t data_size);
char *evr_alloc_chunk();
void evr_free_chunk(char *chunk);

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
    if(chunks_len > evr_chunk_set_max_chunks){
        return NULL;
    }
    chunk_set_t *cs = malloc(sizeof(chunk_set_t));
    if(!cs){
        return NULL;
    }
    cs->chunks_len = chunks_len;
    cs->size_used = 0;
    for(size_t i = 0; i < chunks_len; i++){
        cs->chunks[i] = evr_alloc_chunk();
        if(!cs->chunks[i]){
            for(size_t j = 0; j < i; ++j){
                evr_free_chunk(cs->chunks[j]);
            }
            free(cs);
            return NULL;
        }
    }
    return cs;
}

int evr_grow_chunk_set(chunk_set_t *cs, size_t new_chunks_len){
    int ret = evr_error;
    if(new_chunks_len > evr_chunk_set_max_chunks){
        goto out;
    }
    for(size_t i = cs->chunks_len; i < new_chunks_len; ++i){
        cs->chunks[i] = evr_alloc_chunk();
        if(!cs->chunks[i]){
            for(size_t j = cs->chunks_len; j < i; ++j){
                evr_free_chunk(cs->chunks[j]);
            }
            goto out;
        }
    }
    cs->chunks_len = new_chunks_len;
    ret = evr_ok;
 out:
    return ret;
}

void evr_free_chunk_set(chunk_set_t *cs){
    for(int i = cs->chunks_len - 1; i >= 0; --i){
        evr_free_chunk(cs->chunks[i]);
    }
    free(cs);
}

char *evr_alloc_chunk(){
    // TODO chunks should be organized in a pool in the future.
    return malloc(evr_chunk_size);
}

void evr_free_chunk(char *chunk){
    free(chunk);
}
