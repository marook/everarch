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

#include "config.h"

#include "concurrent-glacier.h"

#include <stdatomic.h>

#include "errors.h"
#include "logger.h"
#include "notify.h"

#define evr_persister_task_queue_length 32

struct evr_persister_ctx {
    struct evr_persister_task *tasks[evr_persister_task_queue_length + 1];
    struct evr_persister_task **writing;
    struct evr_persister_task **reading;
    mtx_t worker_lock;
    cnd_t has_tasks;
    struct evr_glacier_write_ctx *write_ctx;
    int working;
    struct evr_notify_ctx *watchers;
};

struct evr_persister_ctx evr_persister;

thrd_t evr_persister_thread;

int evr_persister_worker(void *context);

int evr_persister_start(struct evr_glacier_storage_cfg *config){
    if(mtx_init(&evr_persister.worker_lock, mtx_plain) != thrd_success){
        goto worker_lock_init_fail;
    }
    if(cnd_init(&evr_persister.has_tasks) != thrd_success){
        goto out_with_free_worker_lock;
    }
    evr_persister.writing = evr_persister.tasks;
    evr_persister.reading = evr_persister.tasks;
    evr_persister.working = 1;
    evr_persister.watchers = evr_create_notify_ctx(32, 8, sizeof(struct evr_modified_blob));
    if(!evr_persister.watchers){
        goto out_with_free_has_tasks;
    }
    if(evr_create_glacier_write_ctx(&evr_persister.write_ctx, config) != evr_ok){
        goto out_with_free_watchers;
    }
    atomic_thread_fence(memory_order_release);
    if(thrd_create(&evr_persister_thread, evr_persister_worker, NULL) != thrd_success){
        goto thread_create_fail;
    }
    log_debug("evr persister started with glacier %s", config->bucket_dir_path);
    return evr_ok;
 thread_create_fail:
    evr_free_glacier_write_ctx(evr_persister.write_ctx);
 out_with_free_watchers:
    if(evr_free_notify_ctx(evr_persister.watchers) != evr_ok){
        evr_panic("Unable to free notify ctx for glacier persister");
    }
 out_with_free_has_tasks:
    cnd_destroy(&evr_persister.has_tasks);
 out_with_free_worker_lock:
    mtx_destroy(&evr_persister.worker_lock);
 worker_lock_init_fail:
    return evr_error;
}

int evr_persister_stop(){
    evr_persister.working = 0;
    if(mtx_lock(&evr_persister.worker_lock) != thrd_success){
        goto fail;
    }
    atomic_thread_fence(memory_order_seq_cst);
    if(cnd_signal(&evr_persister.has_tasks) != thrd_success){
        goto fail;
    }
    atomic_thread_fence(memory_order_seq_cst);
    if(mtx_unlock(&evr_persister.worker_lock) != thrd_success){
        goto fail;
    }
    int worker_result;
    if(thrd_join(evr_persister_thread, &worker_result) != thrd_success){
        goto fail;
    }
    if(worker_result != evr_ok){
        goto fail;
    }
    if(evr_free_glacier_write_ctx(evr_persister.write_ctx) != evr_ok){
        goto fail;
    }
    cnd_destroy(&evr_persister.has_tasks);
    mtx_destroy(&evr_persister.worker_lock);
    log_debug("evr persister stopped");
    return evr_ok;
 fail:
    return evr_error;
}

int evr_persister_init_task(struct evr_persister_task *task, struct evr_writing_blob *blob){
    task->blob = blob;
    if(mtx_init(&task->done, mtx_plain) != thrd_success){
        return evr_error;
    }
    return evr_ok;
}

int evr_persister_destroy_task(struct evr_persister_task *task){
    mtx_destroy(&task->done);
    return evr_ok;
}

inline struct evr_persister_task** evr_persister_ctx_step(struct evr_persister_task **p);

int evr_persister_queue_task(struct evr_persister_task *task){
    int result = evr_ok;
    // task->done is locked before locking
    // evr_persister.worker_lock. the goal is to outsource workload
    // from the part where evr_persister.worker_lock is
    // locked. (not sure if this argumentation is really valid because
    // of the CPU's allowance to change execution order).
    if(mtx_lock(&task->done) != thrd_success){
        goto fail;
    }
    if(mtx_lock(&evr_persister.worker_lock) != thrd_success){
        goto fail;
    }
    atomic_thread_fence(memory_order_seq_cst);
    struct evr_persister_task **allocated_task = evr_persister.writing;
    struct evr_persister_task **next_writing = evr_persister_ctx_step(allocated_task);
    if(next_writing == evr_persister.reading){
        result = evr_temporary_occupied;
        if(mtx_unlock(&task->done) != thrd_success){
            goto fail;
        }
        goto defined_cleanup;
    }
    *allocated_task = task;
    evr_persister.writing = next_writing;
 defined_cleanup:
    atomic_thread_fence(memory_order_seq_cst);
    if(cnd_signal(&evr_persister.has_tasks) != thrd_success){
        goto fail;
    }
    atomic_thread_fence(memory_order_seq_cst);
    if(mtx_unlock(&evr_persister.worker_lock) != thrd_success){
        goto fail;
    }
    return result;
 fail:
    return evr_error;
}

int evr_persister_watch_filter(void *ctx, void *obs_ctx, void *entry);

int evr_persister_worker(void *context){
    log_debug("evr_persister_worker starting");
    int result = evr_error;
    if(mtx_lock(&evr_persister.worker_lock) != thrd_success){
        result = evr_error;
        goto out;
    }
    struct evr_persister_task *task;
    evr_blob_ref task_key;
    int task_flags;
    evr_time task_last_modified;
    while(evr_persister.working){
        while(evr_persister.working) {
            if(evr_persister.writing == evr_persister.reading){
                break;
            } else {
                task = *evr_persister.reading;
                evr_persister.reading = evr_persister_ctx_step(evr_persister.reading);
            }
            if(mtx_unlock(&evr_persister.worker_lock) != thrd_success){
                evr_panic("Unable to unlock evr_persister_worker worker_lock");
                goto out;
            }
            int task_res = evr_glacier_append_blob(evr_persister.write_ctx, task->blob, &task->last_modified);
            task->result = task_res;
            if(task_res == evr_ok){
                memcpy(task_key, task->blob->key, evr_blob_ref_size);
                task_flags = task->blob->flags;
                task_last_modified = task->last_modified;
            }
            if(mtx_unlock(&task->done) != thrd_success){
                evr_panic("Unable to unlock task done lock");
                goto out;
            }
            if(task_res == evr_ok){
                struct evr_modified_blob mod_blob;
                memcpy(mod_blob.key, task_key, evr_blob_ref_size);
                mod_blob.last_modified = task_last_modified;
                mod_blob.flags = task_flags;
                if(evr_notify_send(evr_persister.watchers, &mod_blob, evr_persister_watch_filter, NULL) != evr_ok){
                    evr_blob_ref_str task_key_str;
                    evr_fmt_blob_ref(task_key_str, task_key);
                    log_error("Persister failed to notify watchers about modified blob %s", task_key_str);
                    goto out;
                }
            }
            if(mtx_lock(&evr_persister.worker_lock) != thrd_success){
                goto out;
            }
        }
        if(!evr_persister.working){
            break;
        }
        if(cnd_wait(&evr_persister.has_tasks, &evr_persister.worker_lock) != thrd_success){
            goto out_with_unlock_worker_lock;
        }
    }
    result = evr_ok;
 out_with_unlock_worker_lock:
    if(mtx_unlock(&evr_persister.worker_lock) != thrd_success){
        evr_panic("Unable to unlock evr_persister_worker worker_lock");
        result = evr_error;
    }
 out:
    if(result != evr_ok){
        evr_panic("evr_persister_worker ending with result %d", result);
    } else {
        log_debug("evr_persister_worker ending with result %d", result);
    }
    return result;
}

int evr_persister_watch_filter(void *ctx, void *obs_ctx, void *entry){
    struct evr_blob_filter *f = obs_ctx;
    struct evr_modified_blob *mod_blob = entry;
    return (f->flags_filter & mod_blob->flags) == f->flags_filter;
}

inline struct evr_persister_task** evr_persister_ctx_step(struct evr_persister_task **p){
    p++;
    if(p == &(evr_persister.tasks[evr_persister_task_queue_length + 1])){
        p = evr_persister.tasks;
    }
    return p;
}

int evr_persister_wait_for_task(struct evr_persister_task *task){
    if(mtx_lock(&task->done) != thrd_success){
        return evr_error;
    }
    atomic_thread_fence(memory_order_acquire);
    return evr_ok;
}

struct evr_queue *evr_persister_add_watcher(struct evr_blob_filter *filter){
    return evr_notify_register(evr_persister.watchers, filter);
}

int evr_persister_rm_watcher(struct evr_queue *msgs){
    return evr_notify_unregister(evr_persister.watchers, msgs);
}
