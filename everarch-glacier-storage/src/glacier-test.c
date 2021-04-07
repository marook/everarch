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
#include "glacier.h"
#include "test.h"

const char *bucket_dir_template = "/tmp/evr-glacier-test-XXXXXX";

evr_glacier_storage_configuration* clone_config(evr_glacier_storage_configuration *config);
char* clone_string(const char* s);
void free_glacier_ctx(evr_glacier_ctx *ctx);

char *new_bucket_dir_path(){
    size_t dir_len = strlen(bucket_dir_template);
    char *s = (char*)malloc(dir_len + 1);
    assert_not_null(s);
    memcpy(s, bucket_dir_template, dir_len + 1);
    assert_not_null(mkdtemp(s));
    return s;
}

evr_glacier_storage_configuration *create_temp_evr_glacier_storage_configuration(){
    evr_glacier_storage_configuration *config = create_evr_glacier_storage_configuration();
    assert_not_null(config);
    if(config->bucket_dir_path){
        free(config->bucket_dir_path);
    }
    config->bucket_dir_path = new_bucket_dir_path();
    printf("Using %s as bucket dir\n", config->bucket_dir_path);
    return config;
}

void test_evr_glacier_open_same_empty_glacier_twice(){
    evr_glacier_storage_configuration *config = create_temp_evr_glacier_storage_configuration();
    for(int i = 0; i < 2; i++){
        printf("Round %d…\n", i);
        evr_glacier_storage_configuration *round_config = clone_config(config);
        evr_glacier_ctx *ctx = create_evr_glacier_ctx(round_config);
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
    evr_glacier_ctx *ctx1 = create_evr_glacier_ctx(config);
    assert_not_null(ctx1);
    evr_glacier_ctx *ctx2 = create_evr_glacier_ctx(config);
    assert_null(ctx2);
    free_glacier_ctx(ctx1);
}

void test_evr_glacier_write_blob(){
    evr_glacier_storage_configuration *config = create_temp_evr_glacier_storage_configuration();
    evr_glacier_ctx *ctx = create_evr_glacier_ctx(config);
    assert_not_null(ctx);
    {
        // write a blob
        void *buffer = malloc(256);
        assert_not_null(buffer);
        void *p = buffer;
        written_blob *wb = (written_blob*)p;
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
        evr_bucket_pos bucket_pos;
        assert_zero(evr_glacier_bucket_append(ctx, &bucket_pos, wb));
        free(buffer);
        assert_equal(bucket_pos.index, 1);
        assert_equal(bucket_pos.offset, 4);
    }
    assert_equal(ctx->current_bucket_index, 1);
    assert_equal(ctx->current_bucket_pos, 20);
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

void free_glacier_ctx(evr_glacier_ctx *ctx){
    // TODO delete buckets dir
    assert_zero(free_evr_glacier_ctx(ctx));
}

int main(){
    run_test(test_evr_glacier_open_same_empty_glacier_twice);
    run_test(test_evr_glacier_create_context_twice_fails);
    run_test(test_evr_glacier_write_blob);
}
