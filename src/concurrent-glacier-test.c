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

#include <time.h>
#include <threads.h>

#include "assert.h"
#include "configuration-testutil.h"
#include "errors.h"
#include "glacier.h"
#include "test.h"
#include "concurrent-glacier.h"
#include "logger.h"

int evr_glacier_append_blob_result = evr_ok;

struct timespec short_delay = {
    0,
    10000000
};

struct timespec *append_blob_delay = NULL;

int evr_create_glacier_write_ctx(struct evr_glacier_write_ctx **ctx, struct evr_glacier_storage_cfg *config){
    *ctx = (struct evr_glacier_write_ctx*)1;
    return evr_ok;
}

int evr_free_glacier_write_ctx(struct evr_glacier_write_ctx *ctx){
    return evr_ok;
}

int evr_glacier_append_blob(struct evr_glacier_write_ctx *ctx, struct evr_writing_blob *blob, evr_time *last_modified){
    assert(ctx);
    assert(blob);
    assert(last_modified);
    if(append_blob_delay){
        assert(thrd_sleep(append_blob_delay, NULL) == 0);
    }
    *last_modified = 123;
    return evr_glacier_append_blob_result;
}

struct evr_glacier_storage_cfg *test_config;

void evr_temp_persister_start(void){
    assert(is_ok(evr_persister_start(test_config)));
}

void evr_temp_persister_stop(void){
    assert(is_ok(evr_persister_stop()));
}

void test_queue_one_blob_success(void){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = NULL;
    evr_temp_persister_start();
    struct evr_writing_blob blob;
    struct evr_persister_task task;
    assert(is_ok(evr_persister_init_task(&task, &blob)));
    assert(is_ok(evr_persister_queue_task(&task)));
    assert(is_ok(evr_persister_wait_for_task(&task)));
    assert(is_ok(task.result));
    assert(task.last_modified == 123);
    assert(is_ok(evr_persister_destroy_task(&task)));
    evr_temp_persister_stop();
}

void test_queue_one_blob_write_error(void){
    evr_glacier_append_blob_result = evr_error;
    append_blob_delay = NULL;
    evr_temp_persister_start();
    struct evr_writing_blob blob;
    struct evr_persister_task task;
    assert(is_ok(evr_persister_init_task(&task, &blob)));
    assert(is_ok(evr_persister_queue_task(&task)));
    assert(is_ok(evr_persister_wait_for_task(&task)));
    assert(is_err(task.result));
    assert(is_ok(evr_persister_destroy_task(&task)));
    evr_temp_persister_stop();
}

void queue_and_process_many_blobs(struct timespec *queue_delay);

void test_queue_many_blobs_race(void){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = NULL;
    for(int i = 0; i < 1000; i++){
        queue_and_process_many_blobs(NULL);
    }
}

void test_queue_many_blobs_slow_append(void){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = &short_delay;
    queue_and_process_many_blobs(NULL);
}

void test_queue_many_blobs_slow_queue(void){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = NULL;
    queue_and_process_many_blobs(&short_delay);
}

#define many_blobs_count 100

void queue_and_process_many_blobs(struct timespec *queue_delay){
    evr_temp_persister_start();
    struct evr_writing_blob *blobs = malloc(sizeof(struct evr_writing_blob) * many_blobs_count);
    assert(blobs);
    struct evr_persister_task *tasks = malloc(sizeof(struct evr_persister_task) * many_blobs_count);
    assert(tasks);
    log_info("Initializing tasks...");
    for(int i = 0; i < many_blobs_count; i++){
        assert(is_ok(evr_persister_init_task(&tasks[i], &blobs[i])));
    }
    log_info("Queueing tasks...");
    for(int i = 0; i < many_blobs_count;){
        int result = evr_persister_queue_task(&tasks[i]);
        if(result == evr_temporary_occupied){
            continue;
        }
        assert(is_ok(result));
        i++;
        if(queue_delay){
            assert(thrd_sleep(queue_delay, NULL) == 0);
        }
    }
    log_info("Waiting for tasks...");
    for(int i = many_blobs_count - 1; i >= 0; i--){
        struct evr_persister_task *task = &tasks[i];
        assert(is_ok(evr_persister_wait_for_task(task)));
        assert(is_ok(task->result));
    }
    log_info("Destroying tasks...");
    for(int i = 0; i < many_blobs_count; i++){
        assert(is_ok(evr_persister_destroy_task(&tasks[i])));
    }
    evr_temp_persister_stop();
}

int main(void){
    evr_init_basics();
    test_config = create_temp_evr_glacier_storage_cfg();
    assert(test_config);
    run_test(test_queue_one_blob_success);
    run_test(test_queue_one_blob_write_error);
    run_test(test_queue_many_blobs_race);
    run_test(test_queue_many_blobs_slow_append);
    run_test(test_queue_many_blobs_slow_queue);
    evr_free_glacier_storage_cfg(test_config);
    return 0;
}
