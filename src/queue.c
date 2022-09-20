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

#include "queue.h"

#include <stdlib.h>
#include <string.h>

#include "basics.h"
#include "errors.h"
#include "logger.h"

struct evr_queue *evr_create_queue(size_t items_len_exp, size_t item_size){
    size_t items_len = 1 << items_len_exp;
    char *buf = malloc(sizeof(struct evr_queue) + items_len * item_size);
    if(!buf){
        return NULL;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_queue *q;
    evr_map_struct(&bp, q);
    if(mtx_init(&q->lock, mtx_timed) != thrd_success){
        goto out_with_free_buf;
    }
    if(cnd_init(&q->fill) != thrd_success){
        goto out_with_free_lock;
    }
    q->status = evr_ok;
    q->writing_i = 0;
    q->reading_i = 0;
    q->items_len = items_len;
    q->item_size = item_size;
    q->items_buf = bp.pos;
    if(mtx_init(&q->producing, mtx_plain) != thrd_success){
        goto out_with_free_fill;
    }
    if(mtx_lock(&q->producing) != thrd_success){
        goto out_with_free_producing;
    }
    return q;
 out_with_free_producing:
    mtx_destroy(&q->producing);
 out_with_free_fill:
    cnd_destroy(&q->fill);
 out_with_free_lock:
    mtx_destroy(&q->lock);
 out_with_free_buf:
    free(buf);
    return NULL;
}

void evr_queue_end_producing(struct evr_queue *q){
    if(mtx_unlock(&q->producing) != thrd_success){
        evr_panic("Unable to unlock queue producing mutex on evr_queue_end_producing");
    }
}

int evr_free_queue(struct evr_queue *q, int *status){
    int ret = evr_ok;
    if(!q){
        if(status){
            *status = evr_ok;
        }
        goto out;
    }
    if(mtx_lock(&q->producing) != thrd_success){
        evr_panic("Unable to lock queue producing mutex on evr_free_queue");
        ret = evr_error;
    }
    if(mtx_unlock(&q->producing) != thrd_success){
        evr_panic("Unable to unlock queue producing mutex on evr_free_queue");
        ret = evr_error;
    }
    mtx_destroy(&q->producing);
    cnd_destroy(&q->fill);
    mtx_destroy(&q->lock);
    if(ret == evr_ok && status){
        *status = q->status;
    }
    free(q);
 out:
    return ret;
}

int evr_queue_take(struct evr_queue *q, void *entry){
    int ret = evr_error;
    if(mtx_lock(&q->lock) != thrd_success){
        goto out;
    }
    if(q->status != evr_ok){
        goto out_with_unlock;
    }
    if(q->writing_i == q->reading_i){
        time_t t;
        time(&t);
        struct timespec timeout;
        timeout.tv_sec = t + 1;
        timeout.tv_nsec = 0;
        // cnd_timedwait returns an error either if a timeout is met
        // or another error occured. so we don't check the error
        // response.
        cnd_timedwait(&q->fill, &q->lock, &timeout);
        if(q->writing_i == q->reading_i){
            ret = evr_not_found;
            goto out_with_unlock;
        }
    }
    memcpy(entry, &q->items_buf[q->reading_i * q->item_size], q->item_size);
    q->reading_i = (q->reading_i + 1) & (q->items_len - 1);
    ret = evr_ok;
 out_with_unlock:
    if(mtx_unlock(&q->lock) != thrd_success){
        evr_panic("Unable to unlock queue lock");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_queue_put(struct evr_queue *q, void *entry){
    int ret = evr_error;
    if(mtx_lock(&q->lock) != thrd_success){
        goto out;
    }
    if(q->status != evr_ok){
        goto out_with_unlock;
    }
    size_t next_writing_i = (q->writing_i + 1) & (q->items_len - 1);
    if(next_writing_i == q->reading_i){
        q->status = evr_temporary_occupied;
        ret = evr_temporary_occupied;
    } else {
        memcpy(&q->items_buf[q->writing_i * q->item_size], entry, q->item_size);
        q->writing_i = next_writing_i;
        ret = evr_ok;
    }
    if(cnd_signal(&q->fill) != thrd_success){
        evr_panic("Unable to signal queue filled");
        ret = evr_error;
    }
 out_with_unlock:
    if(mtx_unlock(&q->lock) != thrd_success){
        evr_panic("Failed to unlock queue lock");
        ret = evr_error;
    }
 out:
    return ret;
}
