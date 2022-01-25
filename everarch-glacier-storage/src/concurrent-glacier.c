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

#include <stdatomic.h>

#include "errors.h"
#include "logger.h"

#include "concurrent-glacier.h"

#define evr_persister_task_queue_length 32

typedef struct {
    mtx_t tasks_lock;
    evr_persister_task *tasks[evr_persister_task_queue_length + 1];
    evr_persister_task **writing;
    evr_persister_task **reading;
    mtx_t worker_lock;
    cnd_t has_tasks;
    evr_glacier_write_ctx *write_ctx;
    int working;
} evr_persister_ctx;

evr_persister_ctx evr_persister;

thrd_t evr_persister_thread;

int evr_persister_worker(void *context);

int evr_persister_start(evr_glacier_storage_configuration *config){
    if(mtx_init(&evr_persister.tasks_lock, mtx_plain) != thrd_success){
        goto lock_init_fail;
    }
    if(mtx_init(&evr_persister.worker_lock, mtx_plain) != thrd_success){
        goto worker_lock_init_fail;
    }
    evr_persister.writing = evr_persister.tasks;
    evr_persister.reading = evr_persister.tasks;
    evr_persister.working = 1;
    evr_persister.write_ctx = evr_create_glacier_write_ctx(config);
    if(!evr_persister.write_ctx){
        goto create_write_ctx_fail;
    }
    atomic_thread_fence(memory_order_release);
    if(thrd_create(&evr_persister_thread, evr_persister_worker, NULL) != thrd_success){
        goto thread_create_fail;
    }
    log_debug("evr persister started with glacier %s", config->bucket_dir_path);
    return evr_ok;
 thread_create_fail:
    evr_free_glacier_write_ctx(evr_persister.write_ctx);
 create_write_ctx_fail:
    mtx_destroy(&evr_persister.worker_lock);
 worker_lock_init_fail:
    mtx_destroy(&evr_persister.tasks_lock);
 lock_init_fail:
    return evr_error;
}

int evr_persister_stop(){
    evr_persister.working = 0;
    if(cnd_signal(&evr_persister.has_tasks) != thrd_success){
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
    mtx_destroy(&evr_persister.worker_lock);
    mtx_destroy(&evr_persister.tasks_lock);
    log_debug("evr persister stopped");
    return evr_ok;
 fail:
    return evr_error;
}

int evr_persister_init_task(evr_persister_task *task, evr_writing_blob_t *blob){
    task->blob = blob;
    if(mtx_init(&task->done, mtx_plain) != thrd_success){
        return evr_error;
    }
    return evr_ok;
}

int evr_persister_destroy_task(evr_persister_task *task){
    mtx_destroy(&task->done);
    return evr_ok;
}

inline evr_persister_task** evr_persister_ctx_step(evr_persister_task **p);

int evr_persister_queue_task(evr_persister_task *task){
    int result = evr_ok;
    // task->done is locked before locking
    // evr_persister.tasks_lock. the goal is to outsource workload
    // from the part where evr_persister.tasks_lock is
    // locked. (not sure if this argumentation is really valid because
    // of the CPU's allowance to change execution order).
    if(mtx_lock(&task->done) != thrd_success){
        goto done_lock_fail;
    }
    if(mtx_lock(&evr_persister.tasks_lock) != thrd_success){
        goto lock_tasks_lock_fail;
    }
    atomic_thread_fence(memory_order_acquire);
    evr_persister_task **allocated_task = evr_persister.writing;
    evr_persister_task **next_writing = evr_persister_ctx_step(allocated_task);
    if(next_writing == evr_persister.reading){
        result = evr_temporary_occupied;
        goto defined_cleanup;
    }
    *allocated_task = task;
    evr_persister.writing = next_writing;
    atomic_thread_fence(memory_order_release);
 defined_cleanup:
    if(mtx_unlock(&evr_persister.tasks_lock) != thrd_success){
        result = evr_error;
        goto unlock_task_lock_fail;
    }
    if(cnd_signal(&evr_persister.has_tasks) != thrd_success){
        goto signal_has_tasks_fail;
    }
    return result;
 signal_has_tasks_fail:
 unlock_task_lock_fail:
 lock_tasks_lock_fail:
    // mtx_unlock(task->done) not necessary because task may be broken
    // after this function returns evr_error.
 done_lock_fail:
    return result;
}

int evr_persister_process_task(evr_persister_task *task);

int evr_persister_worker(void *context){
    int result = evr_ok;
    if(mtx_lock(&evr_persister.worker_lock) != thrd_success){
        result = evr_error;
        goto end;
    }
    while(evr_persister.working){
        while(evr_persister.working) {
            // TODO mtx_lock(tasks_lock) followed by mfence also appears in evr_persister_queue_task. can we and do we want to centralize it?
            if(mtx_lock(&evr_persister.tasks_lock) != thrd_success){
                result = evr_error;
                goto end;
            }
            atomic_thread_fence(memory_order_acquire);
            evr_persister_task *task;
            if(evr_persister.writing == evr_persister.reading){
                task = NULL;
            } else {
                task = *evr_persister.reading;
                evr_persister.reading = evr_persister_ctx_step(evr_persister.reading);
                atomic_thread_fence(memory_order_release);
            }
            // TODO mtx_unlock(tasks_lock) followed by mfence also appears in evr_persister_queue_task. can we and do we want to centralize it?
            if(mtx_unlock(&evr_persister.tasks_lock) != thrd_success){
                result = evr_error;
                goto end;
            }
            if(!task){
                break;
            }
            if(evr_persister_process_task(task) != evr_ok){
                result = evr_error;
                goto end;
            }
        }
        if(cnd_wait(&evr_persister.has_tasks, &evr_persister.worker_lock) != thrd_success){
            result = evr_error;
            goto end;
        }
    }
 end:
    if(mtx_unlock(&evr_persister.worker_lock) != thrd_success){
        result = evr_error;
    }
    return result;
}

inline evr_persister_task** evr_persister_ctx_step(evr_persister_task **p){
    p++;
    if(p == &(evr_persister.tasks[evr_persister_task_queue_length + 1])){
        p = evr_persister.tasks;
    }
    return p;
}

int evr_persister_process_task(evr_persister_task *task){
    int result = evr_ok;
    if(evr_glacier_append_blob(evr_persister.write_ctx, task->blob) != evr_ok){
        result = evr_error;
        goto end;
    }
 end:
    task->result = result;
    atomic_thread_fence(memory_order_release);
    if(mtx_unlock(&task->done) != thrd_success){
        return evr_error;
    } else {
        return evr_ok;
    }
}

int evr_persister_wait_for_task(evr_persister_task *task){
    if(mtx_lock(&task->done) != thrd_success){
        return evr_error;
    }
    atomic_thread_fence(memory_order_acquire);
    return evr_ok;
}
