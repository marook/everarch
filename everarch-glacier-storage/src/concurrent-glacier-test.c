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

#include "assert.h"
#include "configuration-testutil.h"
#include "errors.h"
#include "glacier.h"
#include "test.h"
#include "concurrent-glacier.h"

int evr_glacier_append_blob_result = evr_ok;

evr_glacier_write_ctx *evr_create_glacier_write_ctx(evr_glacier_storage_configuration *config){
    return (evr_glacier_write_ctx*)1;
}

int evr_free_glacier_write_ctx(evr_glacier_write_ctx *ctx){
    return evr_ok;
}

int evr_glacier_append_blob(evr_glacier_write_ctx *ctx, const evr_writing_blob_t *blob){
    assert_not_null_msg(ctx, "evr_glacier_write_ctx must not be null");
    assert_not_null_msg(blob, "blob must not be null");
    return evr_glacier_append_blob_result;
}

evr_glacier_storage_configuration *test_config;

void evr_temp_persister_start(){
    test_config = create_temp_evr_glacier_storage_configuration();
    assert_not_null(test_config);
    assert_ok(evr_persister_start(test_config));
}

void evr_temp_persister_stop(){
    assert_ok(evr_persister_stop());
    free_evr_glacier_storage_configuration(test_config);
}

void test_queue_one_blob_success(){
    evr_glacier_append_blob_result = evr_ok;
    evr_temp_persister_start();
    evr_writing_blob_t blob;
    evr_persister_task task;
    assert_ok(evr_persister_init_task(&task, &blob));
    assert_ok(evr_persister_queue_task(&task));
    assert_ok(evr_persister_wait_for_task(&task));
    assert_ok(task.result);
    evr_persister_destroy_task(&task);
    evr_temp_persister_stop();
}

void test_queue_one_blob_write_error(){
    evr_glacier_append_blob_result = evr_error;
    evr_temp_persister_start();
    evr_writing_blob_t blob;
    evr_persister_task task;
    assert_ok(evr_persister_init_task(&task, &blob));
    assert_ok(evr_persister_queue_task(&task));
    assert_ok(evr_persister_wait_for_task(&task));
    assert_equal(task.result, evr_error);
    evr_persister_destroy_task(&task);
    evr_temp_persister_stop();
}

int main(){
    run_test(test_queue_one_blob_success);
    run_test(test_queue_one_blob_write_error);
    return 0;
}
