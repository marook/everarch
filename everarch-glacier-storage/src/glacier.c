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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "glacier.h"
#include "logger.h"

const evr_hash_algorithm_t evr_hash_algorithm_sha224 = 1;

const size_t evr_chunk_size = 1*1024*1024;
const size_t evr_max_blob_data_size = 16*1024*1024;
const size_t evr_max_chunks_per_blob = evr_max_blob_data_size / evr_chunk_size + 1;
const char *glacier_dir_lock_file_path = "/lock";
const char *glacier_dir_index_db_path = "/index.db";
const size_t evr_read_buffer_size = 1*1024*1024;

void build_glacier_file_path(char *glacier_file_path, size_t glacier_file_path_size, const char *bucket_dir_path, const char* path_suffix);

int evr_open_index_db(evr_glacier_storage_configuration *config, int sqliteFlags, sqlite3 **db);

int evr_close_index_db(evr_glacier_storage_configuration *config, sqlite3 *db);

int unlink_lock_file(evr_glacier_write_ctx *ctx);

int evr_create_index_db(evr_glacier_write_ctx *ctx);

int evr_prepare_stmt(sqlite3 *db, const char *sql, sqlite3_stmt **stmt);

int move_to_last_bucket(evr_glacier_write_ctx *ctx);

int open_current_bucket(evr_glacier_write_ctx *ctx);

int evr_open_bucket(const evr_glacier_storage_configuration *config, evr_bucket_index_t bucket_index, int open_flags);

int create_next_bucket(evr_glacier_write_ctx *ctx);

int close_current_bucket(evr_glacier_write_ctx *ctx);

evr_glacier_read_ctx *evr_create_glacier_read_ctx(evr_glacier_storage_configuration *config){
    evr_glacier_read_ctx *ctx = (evr_glacier_read_ctx*)malloc(sizeof(evr_glacier_read_ctx) + evr_read_buffer_size);
    if(!ctx){
        goto fail;
    }
    ctx->config = config;
    ctx->read_buffer = (uint8_t*)(ctx + 1);
    ctx->db = NULL;
    ctx->find_blob_stmt = NULL;
    if(evr_open_index_db(config, SQLITE_OPEN_READONLY, &(ctx->db))){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "select bucket_index, bucket_blob_offset, blob_size from blob_position where key = ?", &(ctx->find_blob_stmt))){
        goto fail_with_db;
    }
    return ctx;
 fail_with_db:
    sqlite3_finalize(ctx->find_blob_stmt);
    sqlite3_close(ctx->db);
    free(ctx);
 fail:
    return NULL;
}

int evr_free_glacier_read_ctx(evr_glacier_read_ctx *ctx){
    if(!ctx){
        return 0;
    }
    int ret = 1;
    if(sqlite3_finalize(ctx->find_blob_stmt) != SQLITE_OK){
        goto end;
    }
    if(evr_close_index_db(ctx->config, ctx->db)){
        goto end;
    }
    ret = 0;
 end:
    free(ctx);
    return ret;
}

int evr_glacier_read_blob(evr_glacier_read_ctx *ctx, const evr_blob_key_t *key, int (*on_data)(void *on_data_arg, const uint8_t *data, size_t data_len), void *on_data_arg){
    int ret = evr_error;
    {
        size_t key_buffer_len = sizeof(evr_hash_algorithm_t) + key->key_len;
        void *key_buffer = alloca(key_buffer_len);
        void *p = key_buffer;
        *((evr_hash_algorithm_t*)p) = key->type;
        p = (evr_hash_algorithm_t*)p + 1;
        memcpy(p, key->key, key->key_len);
        if(sqlite3_bind_blob(ctx->find_blob_stmt, 1, key_buffer, key_buffer_len, SQLITE_TRANSIENT) != SQLITE_OK){
            goto end_with_find_reset;
        }
    }
    int step_result = sqlite3_step(ctx->find_blob_stmt);
    if(step_result == SQLITE_DONE){
        ret = evr_not_found;
        goto end_with_find_reset;
    }
    if(step_result != SQLITE_ROW){
        goto end_with_find_reset;
    }
    evr_bucket_index_t bucket_index = sqlite3_column_int64(ctx->find_blob_stmt, 0);
    evr_bucket_pos_t bucket_blob_offset = sqlite3_column_int(ctx->find_blob_stmt, 1);
    evr_blob_size_t blob_size = sqlite3_column_int(ctx->find_blob_stmt, 2);
    int bucket_f = evr_open_bucket(ctx->config, bucket_index, O_RDONLY);
    if(bucket_f == -1){
        goto end_with_find_reset;
    }
    if(lseek(bucket_f, bucket_blob_offset, SEEK_SET) == -1){
        goto end_with_open_bucket;
    }
    for(ssize_t bytes_read = 0; bytes_read < blob_size;){
        ssize_t buffer_bytes_read = read(bucket_f, ctx->read_buffer, evr_read_buffer_size);
        if(buffer_bytes_read == -1){
            goto end_with_open_bucket;
        }
        if(on_data(on_data_arg, ctx->read_buffer, buffer_bytes_read)){
            goto end_with_open_bucket;
        }
        bytes_read += buffer_bytes_read;
    }
    ret = evr_ok;
 end_with_open_bucket:
    if(close(bucket_f)){
        ret = evr_error;
    }
 end_with_find_reset:
    if(sqlite3_reset(ctx->find_blob_stmt) != SQLITE_OK){
        ret = evr_error;
    }
    return ret;
}

evr_glacier_write_ctx *evr_create_glacier_write_ctx(evr_glacier_storage_configuration *config){
    evr_glacier_write_ctx *ctx = (evr_glacier_write_ctx*)malloc(sizeof(evr_glacier_write_ctx));
    if(!ctx){
        goto fail;
    }
    ctx->config = config;
    if(!ctx->config){
        goto fail_free;
    }
    ctx->current_bucket_index = 0;
    ctx->current_bucket_f = -1;
    ctx->current_bucket_pos = 0;
    ctx->db = NULL;
    ctx->insert_blob_stmt = NULL;
    {
        // this block trims trailing '/' from bucket_dir_path
        size_t len = strlen(config->bucket_dir_path);
        char *end = &(config->bucket_dir_path[len - 1]);
        for(; end >= config->bucket_dir_path; end--){
            if(*end != '/'){
                *(end+1) = '\0';
                break;
            }
        }
    }
    // TODO :bdircre: build bucket dir if not existing
    size_t glacier_file_path_max_size = strlen(config->bucket_dir_path) + 10;
    char *glacier_file_path = alloca(glacier_file_path_max_size);
    {
        // aquire lock file
        build_glacier_file_path(glacier_file_path, glacier_file_path_max_size, config->bucket_dir_path, glacier_dir_lock_file_path);
        if(glacier_file_path[0] == '\0'){
            goto fail_free;
        }
        int lock_f = open(glacier_file_path, O_CREAT | O_EXCL, 0600);
        if(lock_f == -1){
            if(EEXIST == errno){
                log_error("glacier storage lock file %s already exists\n", glacier_file_path);
                goto fail_free;
            }
            log_error("glacier storage could not create lock file %s\n", glacier_file_path);
            goto fail_free;
        }
        close(lock_f);
    }
    if(evr_open_index_db(config, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, &(ctx->db))){
        goto fail_with_db;
    }
    if(evr_create_index_db(ctx)){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "insert into blob_position (key, bucket_index, bucket_blob_offset, blob_size) values (?, ?, ?, ?)", &(ctx->insert_blob_stmt))){
        goto fail_with_db;
    }
    if(move_to_last_bucket(ctx)){
        goto fail_with_db;
    }
    if(ctx->current_bucket_index == 0){
        if(create_next_bucket(ctx)){
            goto fail_with_db;
        }
    } else {
        if(open_current_bucket(ctx)){
            goto fail_with_db;
        }
        if(lseek(ctx->current_bucket_f, 0, SEEK_SET) != 0){
            goto fail_with_open_bucket;
        }
        ssize_t bytes_read = read(ctx->current_bucket_f, &(ctx->current_bucket_pos), sizeof(evr_bucket_pos_t));
        int read_errno = errno;
        if(bytes_read != sizeof(evr_bucket_pos_t)){
            const char *error = bytes_read == -1 ? strerror(read_errno) : "Short read";
            log_error("Failed to read bucket end pointer within glacier directory %s: %s\n", ctx->config->bucket_dir_path, error);
            goto fail_with_open_bucket;
        }
        ctx->current_bucket_pos = evr_be_to_bucket_pos(ctx->current_bucket_pos);
        off_t end_offset = lseek(ctx->current_bucket_f, 0, SEEK_END);
        if(end_offset == -1){
            goto fail_with_open_bucket;
        }
        if(ctx->current_bucket_pos != end_offset){
            // TODO :beprep: repair file
            log_error("Bucket end pointer (%d) and file end offset (%ld) don't match in glacier directory %s.", ctx->current_bucket_pos, end_offset, ctx->config->bucket_dir_path);
            goto fail_with_open_bucket;
        }
    }
    return ctx;
 fail_with_open_bucket:
    close(ctx->current_bucket_f);
 fail_with_db:
    sqlite3_finalize(ctx->insert_blob_stmt);
    sqlite3_close(ctx->db);
    unlink_lock_file(ctx);
 fail_free:
    free(ctx);
 fail:
    return NULL;
}

int evr_create_index_db(evr_glacier_write_ctx *ctx){
    // the following structure_sql creates the structure of the sqlite
    // index db used to quickly lookup blob positions. the db
    // containst the following tables and columns:
    //
    // blob_position
    // - key is the blob's key including type and key data.
    // - bucket_index is the index of the bucket file which is part of
    //   the bucket file's file name.
    // - bucket_blob_offset is the offset within the bucket file at
    //   which the blob data begins.
    // - blob_size is the size of the blob in bytes
    const char *structure_sql =
        "create table if not exists blob_position (key blob primary key not null, bucket_index integer not null, bucket_blob_offset integer not null, blob_size integer not null)";
    char *error;
    if(sqlite3_exec(ctx->db, structure_sql, NULL, NULL, &error) != SQLITE_OK){
        log_error("Failed to create index db structure for glacier %s: %s\n", ctx->config->bucket_dir_path, error);
        sqlite3_free(error);
        return 1;
    }
    return 0;
}

int evr_prepare_stmt(sqlite3 *db, const char *sql, sqlite3_stmt **stmt){
    if(sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("Failed to prepare statement \"%s\": %s\n", sql, sqlite_error_msg);
        return 1;
    }
    return 0;
}

int move_to_last_bucket(evr_glacier_write_ctx *ctx){
    int ret = 1;
    evr_bucket_index_t max_bucket_index = 0;
    DIR *dir = opendir(ctx->config->bucket_dir_path);
    if(!dir){
        goto end;
    }
    errno = 0;
    while(1){
        struct dirent *d = readdir(dir);
        if(!d){
            if(errno){
                goto end_close_dir;
            }
            break;
        }
        char *end = d->d_name;
        for(; isdigit(*end); end++){}
        if(*end != '.'){
            continue;
        }
        *end = '\0';
        evr_bucket_index_t index = 0;
        if(!sscanf(d->d_name, "%lx", &index)){
            continue;
        }
        if(index > max_bucket_index){
            max_bucket_index = index;
        }
    }
    ret = 0;
    ctx->current_bucket_index = max_bucket_index;
 end_close_dir:
    closedir(dir);
 end:
    return ret;
}

int open_current_bucket(evr_glacier_write_ctx *ctx) {
    ctx->current_bucket_f = evr_open_bucket(ctx->config, ctx->current_bucket_index, O_RDWR | O_CREAT);
    if(ctx->current_bucket_f == -1){
        return 1;
    }
    return 0;
}

int evr_open_bucket(const evr_glacier_storage_configuration *config, evr_bucket_index_t bucket_index, int open_flags){
    char *bucket_path;
    {
        // this block builds bucket_path
        size_t bucket_dir_path_len = strlen(config->bucket_dir_path);
        size_t bucket_path_max_len = bucket_dir_path_len + 30;
        bucket_path = alloca(bucket_path_max_len);
        char *end = bucket_path + bucket_path_max_len - 1;
        memcpy(bucket_path, config->bucket_dir_path, bucket_dir_path_len);
        char *s = bucket_path + bucket_dir_path_len;
        *s++ = '/';
        if(snprintf(s, end - bucket_path, "%05lx.blob", bucket_index) < 0){
            return 1;
        }
        *end = '\0';
    }
    int f = open(bucket_path, open_flags, 0644);
    if(f == -1){
        return 1;
    }
    return f;
}

int evr_free_glacier_write_ctx(evr_glacier_write_ctx *ctx){
    if(!ctx){
        return 0;
    }
    int ret = 1;
    if(close_current_bucket(ctx)){
        goto end;
    }
    if(sqlite3_finalize(ctx->insert_blob_stmt) != SQLITE_OK){
        goto end;
    }
    if(evr_close_index_db(ctx->config, ctx->db)){
        goto end;
    }
    if(unlink_lock_file(ctx)){
        goto end;
    }
    ret = 0;
 end:
    free(ctx);
    return ret;
}

int evr_open_index_db(evr_glacier_storage_configuration *config, int sqliteFlags, sqlite3 **db){
    size_t glacier_file_path_max_size = strlen(config->bucket_dir_path) + 10;
    char *glacier_file_path = alloca(glacier_file_path_max_size);
    build_glacier_file_path(glacier_file_path, glacier_file_path_max_size, config->bucket_dir_path, glacier_dir_index_db_path);
    int result = sqlite3_open_v2(glacier_file_path, db, sqliteFlags | SQLITE_OPEN_NOMUTEX, NULL);
    if(result != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(*db);
        log_error("glacier storage could not open %s sqlite database: %s\n", glacier_file_path, sqlite_error_msg);
        return 1;
    }
    return 0;
}

int evr_close_index_db(evr_glacier_storage_configuration *config, sqlite3 *db){
    int db_result = sqlite3_close(db);
    if(db_result != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("glacier storage %s could not close sqlite index database: %s\n", config->bucket_dir_path, sqlite_error_msg);
        return 1;
    }
    return 0;
}

int unlink_lock_file(evr_glacier_write_ctx *ctx){
    size_t bucket_dir_path_size = strlen(ctx->config->bucket_dir_path) + 10;
    char *lock_file_path = alloca(bucket_dir_path_size);
    build_glacier_file_path(lock_file_path, bucket_dir_path_size, ctx->config->bucket_dir_path, glacier_dir_lock_file_path);
    if(lock_file_path[0] != '\0'){
        if(unlink(lock_file_path)){
            log_error("Can not unlink lock file %s\n", lock_file_path);
            return 1;
        }
    }
    return 0;
}

void build_glacier_file_path(char *glacier_file_path, size_t glacier_file_path_size, const char *bucket_dir_path, const char* path_suffix){
    strncpy(glacier_file_path, bucket_dir_path, glacier_file_path_size);
    glacier_file_path[glacier_file_path_size-1] = '\0';
    char *end = &(glacier_file_path[glacier_file_path_size-1]);
    char *p = &glacier_file_path[strlen(glacier_file_path)];
    size_t path_suffix_len = strlen(path_suffix);
    if(end - p < path_suffix_len){
        // not enough space to create the path_suffix
        glacier_file_path[0] = '\0';
        return;
    }
    memcpy(p, path_suffix, path_suffix_len+1);
}

int evr_glacier_append_blob(evr_glacier_write_ctx *ctx, const evr_writing_blob_t *blob) {
    int ret = 1;
    size_t key_disk_size = sizeof(evr_hash_algorithm_t) + sizeof(evr_key_len_t) + blob->key.key_len;
    size_t blob_disk_size = sizeof(evr_blob_size_t) + blob->size;
    size_t disk_size = key_disk_size + blob_disk_size;
    if(disk_size > ctx->config->max_bucket_size){
        // TODO :hrkey: format key in human readable way
        log_error("Can't persist blob for key TODO in glacier directory %s with %ld bytes which is bigger than max bucket size %ld\n", ctx->config->bucket_dir_path, disk_size, ctx->config->max_bucket_size);
        goto fail;
    }
    if(ctx->current_bucket_pos + disk_size > ctx->config->max_bucket_size){
        if(create_next_bucket(ctx)){
            goto fail;
        }
    }
    if(lseek(ctx->current_bucket_f, ctx->current_bucket_pos, SEEK_SET) == -1){
        goto fail;
    }
    size_t header_buffer_len = sizeof(evr_hash_algorithm_t) + sizeof(evr_key_len_t) + blob->key.key_len + sizeof(evr_blob_size_t);
    void *header_buffer = alloca(header_buffer_len);
    void *header_buffer_key_p;
    {
        // fill header_buffer
        void *p = header_buffer;
        *((evr_hash_algorithm_t*)p) = blob->key.type;
        p = (evr_hash_algorithm_t*)p + 1;
        *((evr_key_len_t*)p) = blob->key.key_len;
        p = (evr_key_len_t*)p + 1;
        memcpy(p, blob->key.key, blob->key.key_len);
        // store header buffer key position for later insert into
        // index db. make sure that there is always enough space for
        // evr_hash_algorithm_t BEFORE header_buffer_key_p. don't judge
        // me.
        header_buffer_key_p = p;
        p = (uint8_t*)p + blob->key.key_len;
        *((evr_blob_size_t*)p) = evr_blob_size_to_be(blob->size);
    }
    if(write(ctx->current_bucket_f, header_buffer, header_buffer_len) != header_buffer_len){
        // TODO :hrkey: format key in human readable way
        log_error("Can't completely write blob header for key TODO in glacier directory %s.\n", ctx->config->bucket_dir_path);
        goto fail;
    }
    uint8_t **c = blob->chunks;
    for(evr_blob_size_t bytes_written = 0; bytes_written < blob->size;){
        evr_blob_size_t chunk_bytes_len = evr_chunk_size;
        evr_blob_size_t remaining_blob_bytes = blob->size - bytes_written;
        if(remaining_blob_bytes < chunk_bytes_len){
            chunk_bytes_len = remaining_blob_bytes;
        }
        ssize_t chunk_bytes_written = write(ctx->current_bucket_f, *c, chunk_bytes_len);
        if(chunk_bytes_written != chunk_bytes_len){
            // TODO :hrkey: format key in human readable way
            log_error("Can't completely write blob data for key TODO in glacier directory %s after %d bytes written.\n", ctx->config->bucket_dir_path, bytes_written);
            goto fail;
        }
        bytes_written += chunk_bytes_written;
        c++;
    }
    evr_bucket_pos_t blob_offset = ctx->current_bucket_pos + header_buffer_len;
    ctx->current_bucket_pos += header_buffer_len + blob->size;
    if(lseek(ctx->current_bucket_f, 0, SEEK_SET) == -1){
        goto fail;
    }
    evr_bucket_pos_t last_bucket_pos = evr_bucket_pos_to_be(ctx->current_bucket_pos);
    if(write(ctx->current_bucket_f, &last_bucket_pos, sizeof(evr_bucket_pos_t)) != sizeof(evr_bucket_pos_t)){
        log_error("Can't completely write bucket end pointer in glacier directory %s\n", ctx->config->bucket_dir_path);
        goto fail;
    }
    {
        // bind key into prepared insert_blob_stmt
        evr_hash_algorithm_t *key_type_p = ((evr_hash_algorithm_t*)header_buffer_key_p) - 1;
        *key_type_p = blob->key.type;
        if(sqlite3_bind_blob(ctx->insert_blob_stmt, 1, key_type_p, sizeof(evr_hash_algorithm_t) + blob->key.key_len, SQLITE_TRANSIENT) != SQLITE_OK){
            goto fail_with_insert_reset;
        }
    }
    if(sqlite3_bind_int64(ctx->insert_blob_stmt, 2, ctx->current_bucket_index) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 3, blob_offset) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 4, blob->size) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_step(ctx->insert_blob_stmt) != SQLITE_DONE){
        const char *sqlite_error_msg = sqlite3_errmsg(ctx->db);
        log_error("glacier storage %s failed to store blob index: %s\n", ctx->config->bucket_dir_path, sqlite_error_msg);
        goto fail_with_insert_reset;
    }
    ret = 0;
 fail_with_insert_reset:
    if(sqlite3_reset(ctx->insert_blob_stmt) != SQLITE_OK){
        return 1;
    }
 fail:
    return ret;
}

int create_next_bucket(evr_glacier_write_ctx *ctx){
    if(close_current_bucket(ctx)){
        return 1;
    }
    ctx->current_bucket_index++;
    if(open_current_bucket(ctx)){
        return 1;
    }
    ctx->current_bucket_pos = sizeof(evr_bucket_pos_t);
    evr_bucket_pos_t pos = evr_bucket_pos_to_be(ctx->current_bucket_pos);
    if(write(ctx->current_bucket_f, &pos, sizeof(evr_bucket_pos_t)) != sizeof(evr_bucket_pos_t)){
        log_error("Empty bucket file %05lx could not be created in glacier directory %s\n", ctx->current_bucket_index, ctx->config->bucket_dir_path);
        return 1;
    }
    return 0;
}

int close_current_bucket(evr_glacier_write_ctx *ctx){
    if(ctx->current_bucket_f != -1){
        if(close(ctx->current_bucket_f) == -1){
            return 1;
        }
        ctx->current_bucket_f = -1;
    }
    return 0;
}
