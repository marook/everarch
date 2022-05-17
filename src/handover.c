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

#include "handover.h"

#include "errors.h"
#include "logger.h"

int evr_init_handover_ctx(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    ctx->state = evr_handover_state_run;
    ctx->occupied = 0;
    if(mtx_init(&ctx->lock, mtx_plain) != thrd_success){
        goto out;
    }
    if(cnd_init(&ctx->on_push) != thrd_success){
        goto out_with_free_lock;
    }
    if(cnd_init(&ctx->on_empty) != thrd_success){
        goto out_with_free_on_push;
    }
    ret = evr_ok;
 out:
    return ret;
 out_with_free_on_push:
    cnd_destroy(&ctx->on_push);
 out_with_free_lock:
    mtx_destroy(&ctx->lock);
    return ret;
}

int evr_free_handover_ctx(struct evr_handover_ctx *ctx){
    cnd_destroy(&ctx->on_empty);
    cnd_destroy(&ctx->on_push);
    mtx_destroy(&ctx->lock);
    return evr_ok;
}

int evr_end_handover(struct evr_handover_ctx *ctx, size_t handover_thrds, int end_state);

int evr_finish_handover(struct evr_handover_ctx *ctx, size_t handover_thrds){
    return evr_end_handover(ctx, handover_thrds, evr_handover_state_finish);
}

int evr_abort_handover(struct evr_handover_ctx *ctx, size_t handover_thrds){
    return evr_end_handover(ctx, handover_thrds, evr_handover_state_abort);
}

int evr_end_handover(struct evr_handover_ctx *ctx, size_t handover_thrds, int end_state){
    int ret = evr_error;
    ctx->state = end_state;
    for(size_t i = 0; i < handover_thrds; ++i){
        if(cnd_signal(&ctx->on_push) != thrd_success){
            evr_panic("Failed to signal on_push on termination");
            goto out;
        }
        if(cnd_signal(&ctx->on_empty) != thrd_success){
            evr_panic("Failed to signal on_empty on termination");
            goto out;
        }
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_wait_for_handover_available(struct evr_handover_ctx *ctx){
    if(evr_lock_handover(ctx) != evr_ok){
        evr_panic("Failed to lock handover lock");
        return evr_error;
    }
    while(1){
        if(ctx->state == evr_handover_state_abort || ctx->state == evr_handover_state_finish){
            goto out_with_ret_end;
        }
        if(!ctx->occupied){
            break;
        }
        if(cnd_wait(&ctx->on_empty, &ctx->lock) != thrd_success){
            evr_panic("Failed to wait for empty handover signal");
            return evr_error;
        }
    }
    return evr_ok;
 out_with_ret_end:
    if(mtx_unlock(&ctx->lock) != thrd_success){
        evr_panic("Failed to unlock handover lock");
        return evr_error;
    }
    return evr_end;
}

int evr_wait_for_handover_occupied(struct evr_handover_ctx *ctx){
    if(evr_lock_handover(ctx) != evr_ok){
        evr_panic("Failed to lock handover lock");
        return evr_error;
    }
    while(1){
        if(ctx->state == evr_handover_state_abort){
            goto out_with_ret_end;
        }
        if(ctx->state == evr_handover_state_finish && !ctx->occupied){
            goto out_with_ret_end;
        }
        if(ctx->occupied){
            break;
        }
        if(cnd_wait(&ctx->on_push, &ctx->lock) != thrd_success){
            evr_panic("Failed to wait for handover push");
            return evr_error;
        }
    }
    return evr_ok;
 out_with_ret_end:
    if(mtx_unlock(&ctx->lock) != thrd_success){
        evr_panic("Failed to unlock handover lock");
        return evr_error;
    }
    return evr_end;
}

int evr_lock_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    if(mtx_lock(&ctx->lock) != thrd_success){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_unlock_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    if(mtx_unlock(&ctx->lock) != thrd_success){
        evr_panic("Failed to unlock handover");
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_occupy_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    ctx->occupied = 1;
    if(cnd_signal(&ctx->on_push) != thrd_success){
        evr_panic("Failed to signal spec pushed on occupy");
        goto out;
    }
    if(evr_unlock_handover(ctx) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_empty_handover(struct evr_handover_ctx *ctx){
    int ret = evr_error;
    ctx->occupied = 0;
    if(cnd_signal(&ctx->on_empty) != thrd_success){
        evr_panic("Failed to signal handover empty");
        goto out;
    }
    if(evr_unlock_handover(ctx) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}
