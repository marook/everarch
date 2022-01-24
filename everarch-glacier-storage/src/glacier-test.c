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

#include <string.h>

#include "assert.h"
#include "configuration-testutil.h"
#include "dynamic_array.h"
#include "glacier.h"
#include "test.h"

int store_into_dynamic_array(void *arg, const uint8_t *data, size_t data_len);
int store_into_void(void *arg, const uint8_t *data, size_t data_len);
evr_glacier_storage_configuration* clone_config(evr_glacier_storage_configuration *config);
char* clone_string(const char* s);
void free_glacier_ctx(evr_glacier_write_ctx *ctx);

void test_evr_glacier_open_same_empty_glacier_twice(){
    evr_glacier_storage_configuration *config = create_temp_evr_glacier_storage_configuration();
    for(int i = 0; i < 2; i++){
        printf("Round %d…\n", i);
        evr_glacier_storage_configuration *round_config = clone_config(config);
        evr_glacier_write_ctx *ctx = evr_create_glacier_write_ctx(round_config);
        assert_not_null(ctx);
        assert_equal(ctx->current_bucket_index, 1);
        assert_greater_equal(ctx->current_bucket_f, 0);
        assert_equal(ctx->current_bucket_pos, 4);
        free_glacier_ctx(ctx);
    }
    free_evr_glacier_storage_configuration(config);
}

void test_evr_glacier_create_context_twice_fails(){
    evr_glacier_storage_configuration *config = create_temp_evr_glacier_storage_configuration();
    evr_glacier_write_ctx *ctx1 = evr_create_glacier_write_ctx(config);
    assert_not_null(ctx1);
    evr_glacier_write_ctx *ctx2 = evr_create_glacier_write_ctx(config);
    assert_null(ctx2);
    free_glacier_ctx(ctx1);
}

void test_evr_glacier_write_smal_blob(){
    evr_glacier_storage_configuration *config = create_temp_evr_glacier_storage_configuration();
    evr_glacier_write_ctx *write_ctx = evr_create_glacier_write_ctx(config);
    assert_not_null(write_ctx);
    {
        // write a blob
        void *buffer = malloc(256);
        assert_not_null(buffer);
        void *p = buffer;
        evr_writing_blob_t *wb = (evr_writing_blob_t*)p;
        wb->key.type = 0x22;
        const char *key = "hello";
        size_t key_len = strlen(key);
        wb->key.key_len = key_len;
        p = (void*)(wb + 1);
        wb->key.key = (uint8_t*)p;
        memcpy(wb->key.key, key, key_len);
        p = (void*)&(wb->key.key[key_len]);
        wb->chunks = (uint8_t**)p;
        p = (void*)(wb->chunks + 1);
        wb->chunks[0] = (uint8_t*)p;
        const char *data = "world";
        size_t data_len = strlen(data);
        memcpy(wb->chunks[0], data, data_len);
        wb->size = data_len;
        assert_zero(evr_glacier_append_blob(write_ctx, wb));
        assert_equal(write_ctx->current_bucket_index, 1);
        assert_equal(write_ctx->current_bucket_pos, 20);
        free(buffer);
    }
    evr_glacier_read_ctx *read_ctx = evr_create_glacier_read_ctx(config);
    assert_not_null(read_ctx);
    {
        // read the written blob
        const char *key = "hello";
        size_t key_len = strlen(key);
        evr_blob_key_t *evr_key = malloc(sizeof(evr_blob_key_t) + key_len);
        assert_not_null(evr_key);
        evr_key->type = 0x22;
        evr_key->key_len = key_len;
        evr_key->key = (uint8_t*)(evr_key + 1);
        memcpy(evr_key->key, key, key_len);
        dynamic_array *data_buffer = alloc_dynamic_array(128);
        assert_not_null(data_buffer);
        assert_zero(evr_glacier_read_blob(read_ctx, evr_key, store_into_dynamic_array, &data_buffer));
        free(evr_key);
        assert_equal(data_buffer->size_used, 5);
        assert_zero(memcmp("world", data_buffer->data, 5));
        free(data_buffer);
    }
    {
        // read not existing key
        const char *key = "peng";
        size_t key_len = strlen(key);
        evr_blob_key_t *evr_key = malloc(sizeof(evr_blob_key_t) + key_len);
        assert_not_null(evr_key);
        evr_key->type = 0x22;
        evr_key->key_len = key_len;
        evr_key->key = (uint8_t*)(evr_key + 1);
        memcpy(evr_key->key, key, key_len);
        assert_equal(evr_glacier_read_blob(read_ctx, evr_key, store_into_void, NULL), evr_not_found);
        free(evr_key);
    }
    assert_zero(evr_free_glacier_read_ctx(read_ctx));
    free_glacier_ctx(write_ctx);
}

int store_into_dynamic_array(void *arg, const uint8_t *data, size_t data_len){
    dynamic_array **buffer = (dynamic_array**)arg;
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

int store_into_void(void *arg, const uint8_t *data, size_t data_len){
    return 0;
}

void test_evr_glacier_write_big_blob(){
    evr_glacier_storage_configuration *config = create_temp_evr_glacier_storage_configuration();
    evr_glacier_write_ctx *ctx = evr_create_glacier_write_ctx(config);
    assert_not_null(ctx);
    {
        // write a blob
        void *buffer = malloc(256);
        assert_not_null(buffer);
        void *p = buffer;
        evr_writing_blob_t *wb = (evr_writing_blob_t*)p;
        wb->key.type = 0x22;
        const char key[] = {0x11};
        size_t key_len = sizeof(key);
        wb->key.key_len = key_len;
        p = (void*)(wb + 1);
        wb->key.key = (uint8_t*)p;
        memcpy(wb->key.key, key, key_len);
        p = (void*)&(wb->key.key[key_len]);
        wb->chunks = (uint8_t**)p;
        p = (void*)(wb->chunks + 2);
        wb->chunks[0] = malloc(evr_chunk_size);
        assert_not_null(wb->chunks[0]);
        memset(wb->chunks[0], 0x33, evr_chunk_size);
        size_t chunk_1_len = evr_chunk_size / 2;
        wb->chunks[1] = malloc(chunk_1_len);
        assert_not_null(wb->chunks[1]);
        memset(wb->chunks[1], 0x44, chunk_1_len);
        wb->size = evr_chunk_size + chunk_1_len;
        assert_zero(evr_glacier_append_blob(ctx, wb));
        free(wb->chunks[0]);
        free(wb->chunks[1]);
        free(buffer);
    }
    assert_equal(ctx->current_bucket_index, 1);
    free_glacier_ctx(ctx);
}

evr_glacier_storage_configuration* clone_config(evr_glacier_storage_configuration *config){
    evr_glacier_storage_configuration *clone = (evr_glacier_storage_configuration*)malloc(sizeof(evr_glacier_storage_configuration));
    assert_not_null(clone);
    clone->cert_path = clone_string(config->cert_path);
    clone->key_path = clone_string(config->key_path);
    clone->cert_root_path = clone_string(config->cert_root_path);
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
    assert_not_null(c);
    memcpy(c, s, s_len + 1);
    return c;
}

void free_glacier_ctx(evr_glacier_write_ctx *ctx){
    // TODO delete buckets dir
    evr_glacier_storage_configuration *config = ctx->config;
    assert_zero(evr_free_glacier_write_ctx(ctx));
    free_evr_glacier_storage_configuration(config);
}

void test_evr_free_glacier_read_ctx_with_null_ctx(){
    evr_free_glacier_read_ctx(NULL);
}

void test_evr_free_glacier_write_ctx_with_null_ctx(){
    evr_free_glacier_write_ctx(NULL);
}

int main(){
    run_test(test_evr_glacier_open_same_empty_glacier_twice);
    run_test(test_evr_glacier_create_context_twice_fails);
    run_test(test_evr_glacier_write_smal_blob);
    run_test(test_evr_glacier_write_big_blob);
    run_test(test_evr_free_glacier_read_ctx_with_null_ctx);
    run_test(test_evr_free_glacier_write_ctx_with_null_ctx);
    return 0;
}
