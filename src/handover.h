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
 * handover.h declares data structures and functions for passing
 * single slot values from producer to consumer threads.
 */

#ifndef handover_h
#define handover_h

#include "config.h"

#include <threads.h>

/**
 * evr_handover_state_run indicates the handover is still running and
 * despite the handover is not occupied new entries might follow in
 * the future.
 */
#define evr_handover_state_run 1

/**
 * evr_handover_state_abort indicates the workers should end as soon
 * as possible even if the handover is still occupied.
 */
#define evr_handover_state_abort 2

/**
 * evr_handover_state_finish indicates that the last entry has been
 * put into the handover. Any worker must end when the handover
 * becomes availible.
 */
#define evr_handover_state_finish 3

struct evr_handover_ctx {
    /**
     * state must be one of evr_handover_state_*
     */
    int state;

    /**
     * occupied is 1 if the handover is occupied. It's 0 if the
     * handover is available.
     */
    int occupied;

    mtx_t lock;
    cnd_t on_push;
    cnd_t on_empty;
};

int evr_init_handover_ctx(struct evr_handover_ctx *ctx);

int evr_free_handover_ctx(struct evr_handover_ctx *ctx);

int evr_finish_handover(struct evr_handover_ctx *ctx, size_t handover_thrds);

int evr_abort_handover(struct evr_handover_ctx *ctx, size_t handover_thrds);

int evr_wait_for_handover_available(struct evr_handover_ctx *ctx);

/**
 * Waits until either the handover is occupied or it should end.
 *
 * Returns evr_ok if the handover is occupied. Returns evr_end if the
 * handover consuming should end.
 */
int evr_wait_for_handover_occupied(struct evr_handover_ctx *ctx);

int evr_lock_handover(struct evr_handover_ctx *ctx);

int evr_unlock_handover(struct evr_handover_ctx *ctx);

int evr_occupy_handover(struct evr_handover_ctx *ctx);

int evr_empty_handover(struct evr_handover_ctx *ctx);

#endif
