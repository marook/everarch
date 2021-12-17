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

#ifndef __queue_h__
#define __queue_h__

#include <stddef.h>

#include "errors.h"
#include "memory.h"

#define evr_queue_blocked 1
#define evr_queue_full 2
#define evr_queue_empty 3

/**
 * queue_t defines a queue of pointers.
 *
 * The following diagram illustrates a queue with capacity 3. The
 * internal capacity is increaded by 1 in order to prevent the start
 * pointer from overtaking the end pointer.
 *
 * |---|---|---|---|
 * | 0 | 1 | 2 | 3 |
 * |---|---|---|---|
 *   ^           ^
 *   start       end
 *   first
 *   last
 *   reading
 *   writing
 *
 * The following explains the changes performed by a evr_queue_put
 * call on the queue. First the internal writing target pointer is
 * calculated. As w = writing + 1.
 *
 * |---|---|---|---|
 * | 0 | 1 | 2 | 3 |
 * |---|---|---|---|
 *   ^           ^
 *   first
 *   last
 *   reading
 *   writing
 *       ^
 *       w
 * 
 */
typedef struct {
    void **start;
    void **end;
    
    void **first;
    void **last;

    void **reading ____cacheline_aligned;
    void **writing ____cacheline_aligned;
} queue_t;

/**
 * evr_queue_create allocates a new queue with given capacity.
 */
queue_t *evr_queue_create(size_t capacity);

void evr_queue_free(queue_t *q);

/**
 * evr_queue_put adds the queue item p to the queue in a non blocking
 * and thread safe manner.
 */
int evr_queue_put(queue_t *q, void *p);

int evr_queue_put_blocking(queue_t *q, void *p);

/**
 * evr_queue_pop takes the next queue item from the queue in a non
 * blocking and thread safe manner.
 */
int evr_queue_pop(queue_t *q, void **p);

#endif
