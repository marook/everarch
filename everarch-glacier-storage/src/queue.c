/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021  Markus Peröbner
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

#include <stdlib.h>

#include "queue.h"

queue_t *evr_queue_create(size_t capacity){
    size_t internal_capacity = capacity + 1;
    queue_t *q = aligned_alloc(L1_CACHE_BYTES, sizeof(queue_t) + sizeof(void*) * internal_capacity);
    if(!q){
        return NULL;
    }
    q->start = (void**)(q + 1);
    q->end = q->start + internal_capacity;
    q->first = q->start;
    q->last = q->start;
    q->reading = q->first;
    q->writing = q->last;
    return q;
}

void evr_queue_free(queue_t *q){
    free(q);
}

int evr_queue_put(queue_t *q, void *p){
    void **last = q->last;
    void **w = last + 1;
    if(w == q->end){
        w = q->start;
    }
    if(w == q->first){
        return evr_queue_full;
    }
    if(!__atomic_compare_exchange(&(q->writing), &last, &w, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)){
        // queue is being written by someone else
        return evr_queue_blocked;
    }
    asm("mfence");
    *w = p;
    asm("mfence");
    q->last = w;
    return evr_ok;
}

int evr_queue_put_blocking(queue_t *q, void *p){
    while(1){
        int result = evr_queue_put(q, p);
        if(result == evr_queue_blocked){
            continue;
        }
        return result;
    }
}

int evr_queue_pop(queue_t *q, void **p){
    void **first = q->first;
    if(first == q->last){
        return evr_queue_empty;
    }
    void **r = first + 1;
    if(r == q->end){
        r = q->start;
    }
    if(!__atomic_compare_exchange(&(q->reading), &first, &r, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)){
        // queue is being read by someone else
        return evr_queue_blocked;
    }
    asm("mfence");
    *p = *r;
    asm("mfence");
    q->first = r;
    return evr_ok;
}
