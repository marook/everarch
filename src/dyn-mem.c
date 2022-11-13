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

#include <string.h>

#include "errors.h"

inline size_t get_dynamic_array_size(size_t data_size);
char *evr_alloc_chunk();
void evr_free_chunk(char *chunk);

struct dynamic_array *alloc_dynamic_array(size_t initial_size){
    size_t da_size;
    if(initial_size == 0){
        da_size = evr_page_size;
        initial_size = da_size - sizeof(struct dynamic_array);
    } else {
        da_size = get_dynamic_array_size(initial_size);
    }
    struct dynamic_array *da = (struct dynamic_array*)malloc(da_size);
    if(!da){
        return NULL;
    }
    da->size_allocated = initial_size;
    da->size_used = 0;
    da->data = (char*)&(da[1]);
    return da;
}

struct dynamic_array *grow_dynamic_array_at_least(struct dynamic_array *da, size_t min_size){
    // + 1 because we want to avoid size not growing when small
    size_t new_size = da ? (size_t)(da->size_allocated * 1.5) + 1 : 0;
    if(new_size < min_size){
        new_size = min_size;
    }
    size_t new_da_size = get_dynamic_array_size(new_size);
    struct dynamic_array *new_da;
    if(da) {
        new_da = (struct dynamic_array*)realloc(da, new_da_size);
    } else {
        new_da = (struct dynamic_array*)malloc(new_da_size);
    }
    if(!new_da){
        if(da){
            free(da);
        }
        return NULL;
    }
    new_da->size_allocated = new_size;
    if(!da){
        new_da->size_used = 0;
    }
    new_da->data = (char*)&(new_da[1]);
    return new_da;
}

inline size_t get_dynamic_array_size(size_t data_size){
    return sizeof(struct dynamic_array) + data_size;
}

void rtrim_dynamic_array(struct dynamic_array *da, int (*istrimmed)(int c)){
    char *it = &(((char*)da->data)[da->size_used]);
    for(; it-1 > (char*)da->data; it--){
        if(!istrimmed(*(it - 1))){
            break;
        }
    }
    da->size_used = it - (char*)da->data;
}

int dynamic_array_remove(struct dynamic_array *da, size_t offset, size_t size){
    size_t end = offset + size;
    if(end < da->size_used){
        memmove(&da->data[offset], &da->data[offset + size], da->size_used - end);
    } else if(end > da->size_used){
        return evr_error;
    }
    da->size_used -= size;
    return evr_ok;
}

struct dynamic_array *write_n_dynamic_array(struct dynamic_array *da, const char* data, size_t data_size){
    size_t new_size_used = da->size_used + data_size;
    if(new_size_used > da->size_allocated){
        da = grow_dynamic_array_at_least(da, new_size_used);
        if(!da){
            return NULL;
        }
    }
    memcpy(&((char*)da->data)[da->size_used], data, data_size);
    da->size_used = new_size_used;
    return da;
}

struct chunk_set* evr_allocate_chunk_set(size_t chunks_len){
    struct chunk_set *cs = malloc(sizeof(struct chunk_set));
    if(evr_init_chunk_set(cs, chunks_len) != evr_ok){
        free(cs);
        return NULL;
    }
    return cs;
}

int evr_init_chunk_set(struct chunk_set *cs, size_t chunks_len){
    if(chunks_len > evr_chunk_set_max_chunks){
        return evr_error;
    }
    cs->chunks_len = chunks_len;
    cs->size_used = 0;
    for(size_t i = 0; i < chunks_len; i++){
        cs->chunks[i] = evr_alloc_chunk();
        if(!cs->chunks[i]){
            for(size_t j = 0; j < i; ++j){
                evr_free_chunk(cs->chunks[j]);
            }
            return evr_error;
        }
    }
    return evr_ok;
}

int evr_grow_chunk_set(struct chunk_set *cs, size_t new_chunks_len){
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

void evr_free_chunk_set(struct chunk_set *cs){
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

int evr_chunk_setify(struct chunk_set *cs, char *buf, size_t size){
    int ret = evr_error;
    cs->chunks_len = size / evr_chunk_size + 1;
    if(cs->chunks_len > evr_chunk_set_max_chunks){
        goto out;
    }
    cs->size_used = size;
    for(size_t i = 0; i < cs->chunks_len; ++i){
        cs->chunks[i] = buf + i * evr_chunk_size;
    }
    ret = evr_ok;
 out:
    return ret;
}

struct evr_llbuf *evr_create_llbuf(struct evr_buf_pos *bp, size_t data_size){
    char *buf = malloc(sizeof(struct evr_buf_pos) + data_size);
    if(!buf){
        return NULL;
    }
    evr_init_buf_pos(bp, buf);
    struct evr_llbuf *llb;
    evr_map_struct(bp, llb);
    llb->next = NULL;
    llb->data = bp->pos;
    return llb;
}

int evr_llbuf_prepend(struct evr_llbuf **llb, struct evr_buf_pos *bp, size_t data_size){
    struct evr_llbuf *old = *llb;
    *llb = evr_create_llbuf(bp, data_size);
    if(!*llb){
        *llb = old;
        return evr_error;
    }
    (*llb)->next = old;
    return evr_ok;
}

void evr_free_llbuf_chain(struct evr_llbuf *llb, void (*free_item)(void *item)){
    struct evr_llbuf *l;
    while(llb){
        if(free_item){
            free_item(llb->data);
        }
        l = llb->next;
        free(llb);
        llb = l;
    }
}

void evr_init_llbuf_s(struct evr_llbuf_s *llb, size_t child_size){
    llb->first = NULL;
    llb->last = NULL;
    llb->block_count = 0;
    llb->block_child_count = max(1, (evr_page_size - sizeof(struct evr_llbuf)) / child_size);
    llb->child_count = 0;
    llb->child_size = child_size;
}

int evr_llbuf_s_append(struct evr_llbuf_s *llb, void **child){
    if(llb->child_count + 1 >= llb->block_count * llb->block_child_count){
        // grow llbuf
        struct evr_buf_pos bp;
        struct evr_llbuf *blk = evr_create_llbuf(&bp, llb->child_size);
        if(!blk){
            return evr_error;
        }
        if(llb->last){
            llb->last->next = blk;
        } else {
            llb->first = blk;
        }
        llb->last = blk;
        llb->block_count += 1;
    }
    size_t blk_child_index = llb->child_count % llb->block_child_count;
    *child = &((char*)llb->last->data)[blk_child_index * llb->child_size];
    ++llb->child_count;
    return evr_ok;
}

void evr_init_llbuf_s_iter(struct evr_llbuf_s_iter *iter, struct evr_llbuf_s *llb){
    iter->llb = llb;
    iter->block = llb->first;
    iter->child = iter->block ? iter->block->data : NULL;
    iter->remaining_children = llb->child_count;
}
