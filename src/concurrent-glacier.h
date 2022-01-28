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

#ifndef __evr_concurrent_glacier_h__
#define __evr_concurrent_glacier_h__

#include <threads.h>

#include "glacier.h"

/**
 * evr_persister_start starts the persister background thread.
 *
 * config must not be freed until evr_persister_stop is called.
 */
int evr_persister_start(evr_glacier_storage_configuration *config);

/**
 * evr_persister_stop gracefully stops the persister. Blocks until the
 * currently processed task is done if there is any.
 */
int evr_persister_stop();

typedef struct {
    evr_writing_blob_t *blob;

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
} evr_persister_task;

/**
 * evr_persister_init_task initializes task.
 *
 * blob may not be freed until evr_persister_destroy_task is called.
 */
int evr_persister_init_task(evr_persister_task *task, evr_writing_blob_t *blob);

int evr_persister_destroy_task(evr_persister_task *task);

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
int evr_persister_queue_task(evr_persister_task *task);

/**
 * evr_persister_wait_for_task waits until task is done.
 *
 * Returns evr_ok even if the task's work has failed. Check
 * task->result manually if required.
 */
int evr_persister_wait_for_task(evr_persister_task *task);

#endif
