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

#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "assert.h"
#include "configuration-testutil.h"
#include "dyn-mem.h"
#include "glacier.h"
#include "test.h"
#include "logger.h"

int status_mock_ret;
int status_mock_expected_exists;
int status_mock_expected_flags;
int status_mock_expected_blob_size;

int status_mock(void *arg, int exists, int flags, size_t blob_size);
int store_into_dynamic_array(void *arg, const char *data, size_t data_len);
int store_into_void(void *arg, const char *data, size_t data_len);
struct evr_glacier_storage_cfg* clone_config(struct evr_glacier_storage_cfg *config);
char* clone_string(const char* s);
void free_glacier_ctx(struct evr_glacier_write_ctx *ctx);

void test_evr_glacier_open_same_empty_glacier_twice(){
    struct evr_glacier_storage_cfg *config = create_temp_evr_glacier_storage_cfg();
    for(int i = 0; i < 2; i++){
        log_info("Round %d…", i);
        struct evr_glacier_storage_cfg *round_config = clone_config(config);
        struct evr_glacier_write_ctx *ctx = evr_create_glacier_write_ctx(round_config);
        assert(ctx);
        assert(ctx->current_bucket_index == 1);
        assert(ctx->current_bucket_f >= 0);
        assert(ctx->current_bucket_pos == 4);
        free_glacier_ctx(ctx);
    }
    evr_free_glacier_storage_cfg(config);
}

void test_evr_glacier_create_context_twice_fails(){
    struct evr_glacier_storage_cfg *config = create_temp_evr_glacier_storage_cfg();
    struct evr_glacier_write_ctx *ctx1 = evr_create_glacier_write_ctx(config);
    assert(ctx1);
    struct evr_glacier_write_ctx *ctx2 = evr_create_glacier_write_ctx(config);
    assert(ctx2 == NULL);
    free_glacier_ctx(ctx1);
}

struct visit_blobs_ctx {
    evr_blob_ref *visited_keys;
    size_t visited_keys_len;
};

void visit_blobs(struct evr_glacier_read_ctx *ctx, struct evr_blob_filter *filter, struct visit_blobs_ctx *vbctx);

void test_evr_glacier_write_smal_blobs(){
    struct evr_glacier_storage_cfg *config = create_temp_evr_glacier_storage_cfg();
    struct evr_glacier_write_ctx *write_ctx = evr_create_glacier_write_ctx(config);
    assert(write_ctx);
    evr_blob_ref first_key;
    assert(is_ok(evr_parse_blob_ref(first_key, "sha3-224-20000000000000000000000000000000000000000000000000000000")));
    evr_blob_ref second_key;
    assert(is_ok(evr_parse_blob_ref(second_key, "sha3-224-10000000000000000000000000000000000000000000000000000000")));
    evr_time first_last_modified;
    {
        log_info("Write a blob");
        void *buffer = malloc(256);
        assert(buffer);
        void *p = buffer;
        struct evr_writing_blob *wb = (struct evr_writing_blob*)p;
        memcpy(wb->key, first_key, evr_blob_ref_size);
        wb->flags = 0;
        p = &wb[1];
        wb->chunks = (char**)p;
        p = (void*)(wb->chunks + 1);
        wb->chunks[0] = (char*)p;
        const char *data = "hello world";
        size_t data_len = strlen(data);
        memcpy(wb->chunks[0], data, data_len);
        wb->size = data_len;
        assert(is_ok(evr_glacier_append_blob(write_ctx, wb, &first_last_modified)));
        assert(write_ctx->current_bucket_index == 1);
        assert_msg(write_ctx->current_bucket_pos == 57, "current_bucket_pos was %d", write_ctx->current_bucket_pos);
        assert(first_last_modified > 1644937656);
        free(buffer);
    }
    // the following nanosleep makes sure that first_last_modified is
    // before second_last_modified (even on your rock solid, ultra pro
    // gaming pc)
    const struct timespec delay = {
        0,
        5 * 1000000
    };
    assert(nanosleep(&delay, NULL) == 0);
    evr_time second_last_modified;
    {
        log_info("Write another unrelated blob");
        void *buffer = malloc(256);
        assert(buffer);
        void *p = buffer;
        struct evr_writing_blob *wb = (struct evr_writing_blob*)p;
        memcpy(wb->key, second_key, evr_blob_ref_size);
        wb->flags = 0;
        p = &wb[1];
        wb->chunks = (char**)p;
        p = (void*)(wb->chunks + 1);
        wb->chunks[0] = (char*)p;
        const char *data = "xxx";
        size_t data_len = strlen(data);
        memcpy(wb->chunks[0], data, data_len);
        wb->size = data_len;
        assert(is_ok(evr_glacier_append_blob(write_ctx, wb, &second_last_modified)));
        assert(write_ctx->current_bucket_index == 1);
        assert_msg(write_ctx->current_bucket_pos == 102, "current_bucket_pos was %d", write_ctx->current_bucket_pos);
        assert(second_last_modified > 1644937656);
        free(buffer);
    }
    assert(first_last_modified < second_last_modified);
    struct evr_glacier_read_ctx *read_ctx = evr_create_glacier_read_ctx(config);
    assert(read_ctx);
    {
        log_info("Read the written blob");
        struct dynamic_array *data_buffer = alloc_dynamic_array(128);
        assert(data_buffer);
        status_mock_ret = evr_ok;
        status_mock_expected_exists = 1;
        status_mock_expected_flags = 0;
        status_mock_expected_blob_size = 11;
        assert(is_ok(evr_glacier_read_blob(read_ctx, first_key, status_mock, store_into_dynamic_array, &data_buffer)));
        assert(data_buffer->size_used == 11);
        assert(memcmp("hello world", data_buffer->data, data_buffer->size_used) == 0);
        free(data_buffer);
    }
    {
        log_info("Read not existing key");
        evr_blob_ref key;
        assert(is_ok(evr_parse_blob_ref(key, "sha3-224-30000000000000000000000000000000000000000000000000000000")));
        status_mock_ret = evr_ok;
        status_mock_expected_exists = 0;
        status_mock_expected_flags = 0;
        status_mock_expected_blob_size = 0;
        assert(evr_glacier_read_blob(read_ctx, key, status_mock, store_into_void, NULL) == evr_not_found);
    }
    {
        log_info("List blobs order by blob ref");
        evr_blob_ref visited_keys[2];
        struct visit_blobs_ctx visit_ctx = {
            visited_keys,
            0,
        };
        struct evr_blob_filter filter = {
            evr_cmd_watch_sort_order_ref,
            0,
            0,
        };
        visit_blobs(read_ctx, &filter, &visit_ctx);
        assert(visit_ctx.visited_keys_len == 2);
        assert(memcmp(visited_keys[0], second_key, evr_blob_ref_size) == 0);
        assert(memcmp(visited_keys[1], first_key, evr_blob_ref_size) == 0);
    }
    assert(is_ok(evr_free_glacier_read_ctx(read_ctx)));
    free_glacier_ctx(write_ctx);
}

int blob_visitor(void *context, const evr_blob_ref key, int flags, evr_time last_modified, int last_blob);

void visit_blobs(struct evr_glacier_read_ctx *ctx, struct evr_blob_filter *filter, struct visit_blobs_ctx *vbctx){
    assert(is_ok(evr_glacier_list_blobs(ctx, blob_visitor, filter, vbctx)));
}

int blob_visitor(void *context, const evr_blob_ref key, int flags, evr_time last_modified, int last_blob){
    struct visit_blobs_ctx *ctx = context;
    memcpy(&ctx->visited_keys[ctx->visited_keys_len], key, evr_blob_ref_size);
    ++(ctx->visited_keys_len);
    return evr_ok;
}

int status_mock(void *arg, int exists, int flags, size_t blob_size){
    assert(exists == status_mock_expected_exists);
    assert(flags == status_mock_expected_flags);
    assert(blob_size == status_mock_expected_blob_size);
    return status_mock_ret;
}

int store_into_dynamic_array(void *arg, const char *data, size_t data_len){
    struct dynamic_array **buffer = (struct dynamic_array**)arg;
    size_t new_size_used = (*buffer)->size_used + data_len;
    if(new_size_used > (*buffer)->size_allocated){
        *buffer = grow_dynamic_array_at_least(*buffer, new_size_used);
        if(!*buffer){
            return 1;
        }
    }
    memcpy(&(((uint8_t*)(*buffer)->data)[(*buffer)->size_used]), data, data_len);
    (*buffer)->size_used = new_size_used;
    return 0;
}

int store_into_void(void *arg, const char *data, size_t data_len){
    return 0;
}

void test_evr_glacier_write_big_blob(){
    struct evr_glacier_storage_cfg *config = create_temp_evr_glacier_storage_cfg();
    struct evr_glacier_write_ctx *ctx = evr_create_glacier_write_ctx(config);
    assert(ctx);
    {
        log_info("Write a blob");
        void *buffer = malloc(256);
        assert(buffer);
        void *p = buffer;
        struct evr_writing_blob *wb = (struct evr_writing_blob*)p;
        memset(wb->key, 1, evr_blob_ref_size);
        wb->flags = 0;
        p = &wb[1];
        wb->chunks = (char**)p;
        p = (void*)(wb->chunks + 2);
        wb->chunks[0] = malloc(evr_chunk_size);
        assert(wb->chunks[0]);
        memset(wb->chunks[0], 0x33, evr_chunk_size);
        size_t chunk_1_len = evr_chunk_size / 2;
        wb->chunks[1] = malloc(chunk_1_len);
        assert(wb->chunks[1]);
        memset(wb->chunks[1], 0x44, chunk_1_len);
        wb->size = evr_chunk_size + chunk_1_len;
        evr_time last_modified;
        assert(is_ok(evr_glacier_append_blob(ctx, wb, &last_modified)));
        free(wb->chunks[0]);
        free(wb->chunks[1]);
        free(buffer);
    }
    assert(ctx->current_bucket_index == 1);
    free_glacier_ctx(ctx);
}

void test_evr_glacier_write_blob_twice(){
    struct evr_glacier_storage_cfg *config = create_temp_evr_glacier_storage_cfg();
    struct evr_glacier_write_ctx *ctx = evr_create_glacier_write_ctx(config);
    assert(ctx);
    char *chunks[] = {
        "hello",
    };
    struct evr_writing_blob wb;
    memset(wb.key, 1, evr_blob_ref_size);
    wb.flags = 0;
    wb.size = strlen(chunks[0]);
    wb.chunks = chunks;
    evr_time last_modified = 6;
    assert(is_ok(evr_glacier_append_blob(ctx, &wb, &last_modified)));
    last_modified = 12;
    // duplicate inserts of same blob must be treated as success. they
    // can happend with a small propability if multiple clients put
    // the same blob in parallel.
    assert(is_ok(evr_glacier_append_blob(ctx, &wb, &last_modified)));
    free_glacier_ctx(ctx);
}

struct evr_glacier_storage_cfg* clone_config(struct evr_glacier_storage_cfg *config){
    struct evr_glacier_storage_cfg *clone = (struct evr_glacier_storage_cfg*)malloc(sizeof(struct evr_glacier_storage_cfg));
    assert(clone);
    clone->host = clone_string(config->host);
    clone->port = clone_string(config->port);
    clone->ssl_cert_path = clone_string(config->ssl_cert_path);
    clone->ssl_key_path = clone_string(config->ssl_key_path);
    clone->auth_token_set = config->auth_token_set;
    memcpy(clone->auth_token, config->auth_token, sizeof(clone->auth_token));
    clone->max_bucket_size = config->max_bucket_size;
    clone->bucket_dir_path = clone_string(config->bucket_dir_path);
    return clone;
}

char* clone_string(const char* s){
    if(!s){
        return NULL;
    }
    size_t s_len = strlen(s);
    char *c = (char*)malloc(s_len + 1);
    assert(c);
    memcpy(c, s, s_len + 1);
    return c;
}

void free_glacier_ctx(struct evr_glacier_write_ctx *ctx){
    // TODO delete buckets dir
    struct evr_glacier_storage_cfg *config = ctx->config;
    assert(is_ok(evr_free_glacier_write_ctx(ctx)));
    evr_free_glacier_storage_cfg(config);
}

void test_evr_free_glacier_read_ctx_with_null_ctx(){
    evr_free_glacier_read_ctx(NULL);
}

void test_evr_free_glacier_write_ctx_with_null_ctx(){
    evr_free_glacier_write_ctx(NULL);
}

void test_open_bucket_with_extra_data_at_end(){
    struct evr_glacier_storage_cfg *config = create_temp_evr_glacier_storage_cfg();
    // open for the first time
    struct evr_glacier_write_ctx *write_ctx = evr_create_glacier_write_ctx(clone_config(config));
    assert(write_ctx);
    char *chunks[] = {
        "hello",
    };
    struct evr_writing_blob wb;
    memset(wb.key, 1, evr_blob_ref_size);
    wb.flags = 0;
    wb.size = strlen(chunks[0]);
    wb.chunks = chunks;
    evr_time last_modified = 6;
    assert(is_ok(evr_glacier_append_blob(write_ctx, &wb, &last_modified)));
    free_glacier_ctx(write_ctx);
    // append a few bytes to the first bucket
    {
        const size_t bucket_dir_path_len = strlen(config->bucket_dir_path);
        const char bucket_file_name[] = "/00001.blob";
        const size_t bucket_file_name_len = strlen(bucket_file_name);
        char bucket_path[bucket_dir_path_len + bucket_file_name_len + 1];
        memcpy(bucket_path, config->bucket_dir_path, bucket_dir_path_len);
        memcpy(&bucket_path[bucket_dir_path_len], bucket_file_name, bucket_file_name_len);
        bucket_path[bucket_dir_path_len + bucket_file_name_len] = '\0';
        int f = open(bucket_path, O_RDWR);
        assert(f >= 0);
        lseek(f, 0, SEEK_END);
        assert(write(f, "x", 2) > 0);
        assert(close(f) == 0);
    }
    // open for the second time
    write_ctx = evr_create_glacier_write_ctx(config);
    assert(write_ctx == NULL);
    evr_free_glacier_storage_cfg(config);
}

int main(){
    run_test(test_evr_glacier_open_same_empty_glacier_twice);
    run_test(test_evr_glacier_create_context_twice_fails);
    run_test(test_evr_glacier_write_smal_blobs);
    run_test(test_evr_glacier_write_big_blob);
    run_test(test_evr_glacier_write_blob_twice);
    run_test(test_evr_free_glacier_read_ctx_with_null_ctx);
    run_test(test_evr_free_glacier_write_ctx_with_null_ctx);
    run_test(test_open_bucket_with_extra_data_at_end);
    return 0;
}
