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
 * concurrent-glacier.h provides functions for concurrent access to the
 * glacier API.
 *
 * The implementation relies upon the fact that the sqlite3 db is
 * configured to use multi threading BEFORE calling any function from
 * concurrent-glacier.h:
 *
 * if(sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK){
 *   // handle error
 * }
 */

#ifndef __evr_concurrent_glacier_h__
#define __evr_concurrent_glacier_h__

#include <threads.h>

#include "glacier.h"

struct evr_modified_blob {
    evr_blob_ref key;
    evr_time last_modified;
    int flags;
};

/**
 * evr_persister_start starts the persister background thread.
 *
 * config must not be freed until evr_persister_stop is called.
 */
int evr_persister_start(struct evr_glacier_storage_cfg *config);

/**
 * evr_persister_stop gracefully stops the persister. Blocks until the
 * currently processed task is done if there is any.
 */
int evr_persister_stop(void);

struct evr_persister_task {
    struct evr_writing_blob *blob;

    /**
     * done is locked by evr_persister_queue_task and released after
     * the blob has been succesfully persisted or failed to persist.
     */
    mtx_t done;

    /**
     * result indicates if the blob could be persisted. Will be set
     * after done is unlocked. evr_ok indicates blob was
     * persisted. evr_error indicated blob could not be persisted.
     */
    int result;

    /**
     * last_modified contains the blob's last modification timestamp
     * after done is unlocked.
     */
    evr_time last_modified;

    int sync_strategy;
};

/**
 * evr_persister_init_task initializes task.
 *
 * blob may not be freed until evr_persister_destroy_task is called.
 */
int evr_persister_init_task(struct evr_persister_task *task, struct evr_writing_blob *blob);

int evr_persister_destroy_task(struct evr_persister_task *task);

/**
 * evr_persister_queue_task schedules task for writing to glacier
 * storage.
 *
 * Returns evr_ok if the task was successfully queued. Otherwise
 * evr_error. task.done locking state is undefined if evr_error is
 * returned.
 *
 * task may only be freed after done is unlocked.
 */
int evr_persister_queue_task(struct evr_persister_task *task);

/**
 * evr_persister_wait_for_task waits until task is done.
 *
 * Returns evr_ok even if the task's work has failed. Check
 * task->result manually if required.
 */
int evr_persister_wait_for_task(struct evr_persister_task *task);

/**
 * evr_persister_add_watcher creates a queue which will be filled with
 * struct evr_modified_blob items.
 */
struct evr_queue *evr_persister_add_watcher(struct evr_blob_filter *filter);

int evr_persister_rm_watcher(struct evr_queue *msgs);

#endif
