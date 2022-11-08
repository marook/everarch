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

#include "notify.h"

#include <stdlib.h>

#include "basics.h"
#include "errors.h"
#include "logger.h"

struct evr_notify_ctx *evr_create_notify_ctx(size_t observers_len, size_t msgs_len_exp, size_t msg_size){
    char *buf = malloc(sizeof(struct evr_notify_ctx) + observers_len * sizeof(struct evr_observer));
    if(!buf){
        return NULL;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_notify_ctx *nt;
    evr_map_struct(&bp, nt);
    if(mtx_init(&nt->lock, mtx_plain) != thrd_success){
        goto out_with_free;
    }
    nt->observers_len = observers_len;
    nt->observers = (struct evr_observer*)bp.pos;
    nt->msgs_len_exp = msgs_len_exp;
    nt->msg_size = msg_size;
    struct evr_observer *end = &nt->observers[observers_len];
    for(struct evr_observer *it = nt->observers; it != end; ++it){
        it->messages = NULL;
    }
    return nt;
 out_with_free:
    free(buf);
    return NULL;
}

int evr_free_notify_ctx(struct evr_notify_ctx *nt){
    int ret = evr_error;
    // poll until all observers are gone
    log_debug("Notify context %p is waiting until all observers are gone", nt);
    while(1){
        if(mtx_lock(&nt->lock) != thrd_success){
            goto out;
        }
        int active_observer = 0;
        struct evr_observer *end = &nt->observers[nt->observers_len];
        for(struct evr_observer *it = nt->observers; it != end; ++it){
            if(it->messages){
                active_observer = 1;
                break;
            }
        }
        if(active_observer == 0){
            break;
        }
        if(mtx_unlock(&nt->lock) != thrd_success){
            evr_panic("Unable to unlock notify context lock");
            goto out;
        }
        struct timespec sleep_duration = {
            0,
            100000000
        };
        if(thrd_sleep(&sleep_duration, NULL) != 0){
            goto out;
        }
    }
    log_debug("Notify context %p detected all observers are gone", nt);
    ret = evr_ok;
    if(mtx_unlock(&nt->lock) != thrd_success){
        evr_panic("Unable to unlock notify lock");
        ret = evr_error;
    }
    mtx_destroy(&nt->lock);
    free(nt);
 out:
    return ret;
}

int evr_notify_send(struct evr_notify_ctx *nt, void *entry, int (*filter)(void *ctx, void *obs_ctx, void *entry), void *ctx){
    int ret = evr_error;
    if(mtx_lock(&nt->lock) != thrd_success){
        goto out;
    }
    ret = evr_ok;
    struct evr_observer *end = &nt->observers[nt->observers_len];
    for(struct evr_observer *it = nt->observers; it != end; ++it){
        if(!it->messages || (filter && !filter(ctx, it->ctx, entry))){
            continue;
        }
        int put_res = evr_queue_put(it->messages, entry);
        if(put_res != evr_ok && put_res != evr_temporary_occupied){
            ret = evr_error;
            // don't stop on the first queue if it produces an
            // error. in order to get a defined state after the
            // evr_notify_send call we will still put the entry into
            // the other queues.
        }
    }
    if(mtx_unlock(&nt->lock) != thrd_success){
        evr_panic("Unable to unlock notify lock");
        ret = evr_error;
    }
 out:
    return ret;
}

struct evr_queue *evr_notify_register(struct evr_notify_ctx *nt, void *ctx){
    struct evr_queue *ret = NULL;
    if(mtx_lock(&nt->lock) != thrd_success){
        goto out;
    }
    struct evr_observer *end = &nt->observers[nt->observers_len];
    for(struct evr_observer *it = nt->observers; it != end; ++it){
        if(it->messages){
            continue;
        }
        it->messages = evr_create_queue(nt->msgs_len_exp, nt->msg_size);
        if(!it->messages){
            goto out_with_free_lock;
        }
        it->ctx = ctx;
        ret = it->messages;
        break;
    }
 out_with_free_lock:
    if(mtx_unlock(&nt->lock) != thrd_success){
        evr_panic("Unable to unlock notify lock");
    }
 out:
    return ret;
}

int evr_notify_unregister(struct evr_notify_ctx *nt, struct evr_queue *messages){
    int ret = evr_error;
    if(!messages){
        goto out;
    }
    if(mtx_lock(&nt->lock) != thrd_success){
        goto out;
    }
    struct evr_observer *end = &nt->observers[nt->observers_len];
    for(struct evr_observer *it = nt->observers; it != end; ++it){
        if(it->messages != messages){
            continue;
        }
        // we can call evr_queue_end_producing here because the
        // nt->lock makes sure nobody is currently producing
        // messages. also after we set it->messages to NULL nobody
        // will produce anymore messages for this queue.
        evr_queue_end_producing(it->messages);
        if(evr_free_queue(it->messages, NULL) != evr_ok){
            evr_panic("Unable to free messages queue");
            goto out_with_free_lock;
        }
        it->messages = NULL;
        ret = evr_ok;
        break;
    }
 out_with_free_lock:
    if(mtx_unlock(&nt->lock) != thrd_success){
        evr_panic("Unable to unlock notify lock");
        ret = evr_error;
    }
 out:
    return ret;
}
