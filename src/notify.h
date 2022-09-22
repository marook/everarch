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
 * notify.h defines a notification mechanism using messages sent
 * between many producer and consumer threads.
 *
 * There are some constraints involved.
 *
 * You must call evr_notify_register and evr_notify_unregister from
 * the thread which consumes messages from the messages
 * queue. Otherwise the queue might be destroyed in the moment the
 * consumer tries to read messages from it.
 */

#ifndef notify_h
#define notify_h

#include "config.h"

#include <threads.h>

#include "queue.h"

struct evr_observer {
    struct evr_queue *messages;
    void *ctx;
};

struct evr_notify_ctx {
    mtx_t lock;
    size_t observers_len;
    struct evr_observer *observers;
    size_t msgs_len_exp;
    size_t msg_size;
};

struct evr_notify_ctx *evr_create_notify_ctx(size_t observers_len, size_t msgs_len_exp, size_t msg_size);

int evr_free_notify_ctx(struct evr_notify_ctx *nt);

/**
 * evr_notify_send puts entry into observer queues.
 *
 * Returns evr_ok even if one of the observer queues had no more
 * capacity.
 */
int evr_notify_send(struct evr_notify_ctx *nt, void *entry, int (*filter)(void *ctx, void *obs_ctx, void *entry), void *ctx);

/**
 * evr_notify_register registers a new message queue and retuns it.
 *
 * Returns evr_temporary_occupied if no more space was available new
 * queue.
 */
struct evr_queue *evr_notify_register(struct evr_notify_ctx *nt, void *ctx);

int evr_notify_unregister(struct evr_notify_ctx *nt, struct evr_queue *messages);

#endif
