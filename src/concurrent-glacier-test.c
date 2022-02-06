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

struct evr_glacier_write_ctx *evr_create_glacier_write_ctx(evr_glacier_storage_configuration *config){
    return (struct evr_glacier_write_ctx*)1;
}

int evr_free_glacier_write_ctx(struct evr_glacier_write_ctx *ctx){
    return evr_ok;
}

int evr_glacier_append_blob(struct evr_glacier_write_ctx *ctx, const struct evr_writing_blob *blob){
    assert_not_null_msg(ctx, "evr_glacier_write_ctx must not be null");
    assert_not_null_msg(blob, "blob must not be null");
    if(append_blob_delay){
        assert_equal(thrd_sleep(append_blob_delay, NULL), 0);
    }
    return evr_glacier_append_blob_result;
}

evr_glacier_storage_configuration *test_config;

void evr_temp_persister_start(){
    assert_ok(evr_persister_start(test_config));
}

void evr_temp_persister_stop(){
    assert_ok(evr_persister_stop());
}

void test_queue_one_blob_success(){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = NULL;
    evr_temp_persister_start();
    struct evr_writing_blob blob;
    struct evr_persister_task task;
    assert_ok(evr_persister_init_task(&task, &blob));
    assert_ok(evr_persister_queue_task(&task));
    assert_ok(evr_persister_wait_for_task(&task));
    assert_ok(task.result);
    assert_ok(evr_persister_destroy_task(&task));
    evr_temp_persister_stop();
}

void test_queue_one_blob_write_error(){
    evr_glacier_append_blob_result = evr_error;
    append_blob_delay = NULL;
    evr_temp_persister_start();
    struct evr_writing_blob blob;
    struct evr_persister_task task;
    assert_ok(evr_persister_init_task(&task, &blob));
    assert_ok(evr_persister_queue_task(&task));
    assert_ok(evr_persister_wait_for_task(&task));
    assert_equal(task.result, evr_error);
    assert_ok(evr_persister_destroy_task(&task));
    evr_temp_persister_stop();
}

void queue_and_process_many_blobs();

void test_queue_many_blobs_race(){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = NULL;
    for(int i = 0; i < 1000; i++){
        queue_and_process_many_blobs(NULL);
    }
}

void test_queue_many_blobs_slow_append(){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = &short_delay;
    queue_and_process_many_blobs(NULL);
}

void test_queue_many_blobs_slow_queue(){
    evr_glacier_append_blob_result = evr_ok;
    append_blob_delay = NULL;
    queue_and_process_many_blobs(&short_delay);
}

#define many_blobs_count 100

void queue_and_process_many_blobs(struct timespec *queue_delay){
    evr_temp_persister_start();
    struct evr_writing_blob *blobs = malloc(sizeof(struct evr_writing_blob) * many_blobs_count);
    assert_not_null(blobs);
    struct evr_persister_task *tasks = malloc(sizeof(struct evr_persister_task) * many_blobs_count);
    assert_not_null(tasks);
    log_info("Initializing tasks...");
    for(int i = 0; i < many_blobs_count; i++){
        assert_ok(evr_persister_init_task(&tasks[i], &blobs[i]));
    }
    log_info("Queueing tasks...");
    for(int i = 0; i < many_blobs_count;){
        int result = evr_persister_queue_task(&tasks[i]);
        if(result == evr_temporary_occupied){
            continue;
        }
        assert_ok(result);
        i++;
        if(queue_delay){
            assert_equal(thrd_sleep(queue_delay, NULL), 0);
        }
    }
    log_info("Waiting for tasks...");
    for(int i = many_blobs_count - 1; i >= 0; i--){
        struct evr_persister_task *task = &tasks[i];
        assert_ok(evr_persister_wait_for_task(task));
        assert_equal(task->result, evr_ok);
    }
    log_info("Destroying tasks...");
    for(int i = 0; i < many_blobs_count; i++){
        assert_ok(evr_persister_destroy_task(&tasks[i]));
    }
    evr_temp_persister_stop();
}

int main(){
    test_config = create_temp_evr_glacier_storage_configuration();
    assert_not_null(test_config);
    run_test(test_queue_one_blob_success);
    run_test(test_queue_one_blob_write_error);
    run_test(test_queue_many_blobs_race);
    run_test(test_queue_many_blobs_slow_append);
    run_test(test_queue_many_blobs_slow_queue);
    free_evr_glacier_storage_configuration(test_config);
    return 0;
}
