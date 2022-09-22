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

/*
 * queue.h defines a queue which is intended for inter-thread
 * communication. It is implemented as a ring buffer with predefined
 * maximum size.
 *
 * The consumer should be implemented like this:
 *
 * struct evr_queue *q = evr_create_queue(…);
 * if(!q) …
 * void *entry = …
 * while(…){
 *   int take_res = evr_queue_take(q, entry);
 *   if(take_res == evr_ok){
 *     // process entry
 *   } else if(take_res != evr_not_found){
 *     // an error occured, and you should handle it
 *   }
 * }
 * evr_free_queue(q);
 *
 * A producer should be implemented like this:
 *
 * struct evr_queue *q = // retrieved from consumer
 * void *entry = …
 * while(…){
 *   // produce entry here
 *   if(evr_queue_put(q, entry) != evr_ok){
 *     // an error occured, and you should handle it
 *   }
 * }
 * evr_queue_end_producing(q);
 */

#ifndef queue_h
#define queue_h

#include "config.h"

#include <threads.h>

struct evr_queue {
    int state;
    mtx_t lock;
    cnd_t fill;
    /**
     * status indicates if an error occured during writing this context.
     * Most likely an error indicates that the ring buffer capacity was
     * exceeded.
     */
    int status;
    size_t writing_i;
    size_t reading_i;
    size_t items_len;
    size_t item_size;
    char *items_buf;
    mtx_t producing;
};

/**
 * evr_create_queue allocates a new initially empty queue.
 *
 * items_len_exp is the exponent to the base of 2 which defines the
 * length of the queue.
 */
struct evr_queue *evr_create_queue(size_t items_len_exp, size_t item_size);

void evr_queue_end_producing(struct evr_queue *q);

int evr_free_queue(struct evr_queue *q, int *status);

int evr_queue_get_status(struct evr_queue *q);

/**
 * evr_queue_take blocks for a moment and retrieves and removes the
 * next entry from the queue.
 *
 * Returns evr_not_found if no entry was available.
 */
int evr_queue_take(struct evr_queue *q, void *entry);

/**
 * evr_queue_put puts the given entry into the queue.
 *
 * Returns evr_temporary_occupied if the queue is out of capacity.
 */
int evr_queue_put(struct evr_queue *q, void *entry);

#endif
