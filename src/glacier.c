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

#include "glacier.h"

#include <alloca.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include "logger.h"
#include "dyn-mem.h"
#include "db.h"
#include "files.h"

// TODO convert every variable here into a define in order to save binary space
const size_t evr_max_chunks_per_blob = evr_max_blob_data_size / evr_chunk_size + 1;
const char *glacier_dir_lock_file_path = "/lock";
const char *glacier_dir_index_db_path = "/index.db";
const size_t evr_read_buffer_size = 1*1024*1024;

void build_glacier_file_path(char *glacier_file_path, size_t glacier_file_path_size, const char *bucket_dir_path, const char* path_suffix);

int evr_open_index_db(struct evr_glacier_storage_cfg *config, int sqliteFlags, sqlite3 **db);

int evr_close_index_db(struct evr_glacier_storage_cfg *config, sqlite3 *db);

int unlink_lock_file(struct evr_glacier_write_ctx *ctx);

int evr_create_index_db(struct evr_glacier_write_ctx *ctx);

int move_to_last_bucket(struct evr_glacier_write_ctx *ctx);

int open_current_bucket(struct evr_glacier_write_ctx *ctx);

int evr_open_bucket(const struct evr_glacier_storage_cfg *config, unsigned long bucket_index, int open_flags);

int create_next_bucket(struct evr_glacier_write_ctx *ctx);

int close_current_bucket(struct evr_glacier_write_ctx *ctx);

struct evr_glacier_read_ctx *evr_create_glacier_read_ctx(struct evr_glacier_storage_cfg *config){
    struct evr_glacier_read_ctx *ctx = (struct evr_glacier_read_ctx*)malloc(sizeof(struct evr_glacier_read_ctx) + evr_read_buffer_size);
    if(!ctx){
        goto fail;
    }
    ctx->config = config;
    ctx->read_buffer = (char*)(ctx + 1);
    ctx->db = NULL;
    ctx->find_blob_stmt = NULL;
    ctx->list_blobs_stmt_order_last_modified = NULL;
    ctx->list_blobs_stmt_order_blob_ref = NULL;
    if(evr_open_index_db(config, SQLITE_OPEN_READONLY, &(ctx->db))){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "select flags, bucket_index, bucket_blob_offset, blob_size from blob_position where key = ?", &(ctx->find_blob_stmt))){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "select key, flags, last_modified from blob_position where last_modified >= ? order by last_modified", &(ctx->list_blobs_stmt_order_last_modified))){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "select key, flags, last_modified from blob_position where last_modified >= ? order by key", &(ctx->list_blobs_stmt_order_blob_ref))){
        goto fail_with_db;
    }
    return ctx;
 fail_with_db:
    sqlite3_finalize(ctx->list_blobs_stmt_order_blob_ref);
    sqlite3_finalize(ctx->list_blobs_stmt_order_last_modified);
    sqlite3_finalize(ctx->find_blob_stmt);
    sqlite3_close(ctx->db);
    free(ctx);
 fail:
    return NULL;
}

int evr_free_glacier_read_ctx(struct evr_glacier_read_ctx *ctx){
    if(!ctx){
        return evr_ok;
    }
    int ret = evr_ok; // BIG OTHER WAY ROUND WARNING!!!
    if(sqlite3_finalize(ctx->list_blobs_stmt_order_blob_ref) != SQLITE_OK){
        evr_panic("Unable to finalize list_blobs_stmt_order_blob_ref statement");
        ret = evr_error;
    }
    if(sqlite3_finalize(ctx->list_blobs_stmt_order_last_modified) != SQLITE_OK){
        evr_panic("Unable to finalize list_blobs_stmt_order_last_modified statement");
        ret = evr_error;
    }
    if(sqlite3_finalize(ctx->find_blob_stmt) != SQLITE_OK){
        evr_panic("Unable to finalize find_blob_stmt statement");
        ret = evr_error;
    }
    if(evr_close_index_db(ctx->config, ctx->db)){
        evr_panic("Unable to close index db");
        ret = evr_error;
    }
    free(ctx);
    return ret;
}

int evr_glacier_stat_blob(struct evr_glacier_read_ctx *ctx, const evr_blob_ref key, struct evr_glacier_blob_stat *stat){
    int ret = evr_error;
    if(sqlite3_bind_blob(ctx->find_blob_stmt, 1, key, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto end_with_find_reset;
    }
    int step_result = evr_step_stmt(ctx->db, ctx->find_blob_stmt);
    if(step_result == SQLITE_DONE){
        ret = evr_not_found;
        goto end_with_find_reset;
    }
    if(step_result != SQLITE_ROW){
        goto end_with_find_reset;
    }
    stat->flags = sqlite3_column_int(ctx->find_blob_stmt, 0);
    stat->blob_size = sqlite3_column_int(ctx->find_blob_stmt, 3);
    ret = evr_ok;
 end_with_find_reset:
    if(sqlite3_reset(ctx->find_blob_stmt) != SQLITE_OK){
        ret = evr_error;
    }
    return ret;
}

int evr_glacier_read_blob(struct evr_glacier_read_ctx *ctx, const evr_blob_ref key, int (*status)(void *arg, int exists, int flags, size_t blob_size), int (*on_data)(void *arg, const char *data, size_t data_size), void *arg){
    int ret = evr_error;
    if(sqlite3_bind_blob(ctx->find_blob_stmt, 1, key, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto end_with_find_reset;
    }
    int step_result = evr_step_stmt(ctx->db, ctx->find_blob_stmt);
    if(step_result == SQLITE_DONE){
        ret = evr_not_found;
        if(status(arg, 0, 0, 0) != evr_ok){
            ret = evr_error;
        }
        goto end_with_find_reset;
    }
    if(step_result != SQLITE_ROW){
        goto end_with_find_reset;
    }
    int flags = sqlite3_column_int(ctx->find_blob_stmt, 0);
    unsigned long bucket_index = sqlite3_column_int64(ctx->find_blob_stmt, 1);
    size_t bucket_blob_offset = sqlite3_column_int(ctx->find_blob_stmt, 2);
    size_t blob_size = sqlite3_column_int(ctx->find_blob_stmt, 3);
    int bucket_f = evr_open_bucket(ctx->config, bucket_index, O_RDONLY);
    if(bucket_f == -1){
        goto end_with_find_reset;
    }
    if(lseek(bucket_f, bucket_blob_offset, SEEK_SET) == -1){
        goto end_with_open_bucket;
    }
    if(status(arg, 1, flags, blob_size) != evr_ok){
        ret = evr_error;
        goto end_with_open_bucket;
    }
    for(ssize_t bytes_read = 0; bytes_read < blob_size;){
        ssize_t buffer_bytes_read = read(bucket_f, ctx->read_buffer, min(evr_read_buffer_size, blob_size - bytes_read));
        if(buffer_bytes_read == -1){
            goto end_with_open_bucket;
        }
        if(on_data(arg, ctx->read_buffer, buffer_bytes_read)){
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

int evr_glacier_list_blobs(struct evr_glacier_read_ctx *ctx, int (*visit)(void *vctx, const evr_blob_ref key, int flags, evr_time last_modified, int last_blob), struct evr_blob_filter *filter, void *vctx){
    int ret = evr_error;
    if(filter->last_modified_after > LLONG_MAX){
        // sqlite3 api only provides bind for signed int64. so we must
        // make sure that value does not overflow.
        goto out;
    }
    sqlite3_stmt *list_stmt;
    switch(filter->sort_order){
    default:
        log_error("Unknown sort-order 0x%02x requested", filter->sort_order);
        goto out;
    case evr_cmd_watch_sort_order_last_modified:
        list_stmt = ctx->list_blobs_stmt_order_last_modified;
        break;
    case evr_cmd_watch_sort_order_ref:
        list_stmt = ctx->list_blobs_stmt_order_blob_ref;
        break;
    }
    if(sqlite3_bind_int64(list_stmt, 1, filter->last_modified_after) != SQLITE_OK){
        goto out_with_reset_stmt;
    }
    int has_found_key = 0;
    evr_blob_ref found_key;
    int flags;
    evr_time last_modified;
    while(1){
        int step_ret = evr_step_stmt(ctx->db, list_stmt);
        if(step_ret == SQLITE_DONE){
            if(has_found_key){
                if(visit(vctx, found_key, flags, last_modified, 1) != evr_ok){
                    goto out_with_reset_stmt;
                }
            }
            break;
        }
        if(step_ret != SQLITE_ROW){
            goto out;
        }
        int new_flags = sqlite3_column_int(list_stmt, 1);
        if((new_flags & filter->flags_filter) != filter->flags_filter){
            continue;
        }
        if(has_found_key){
            if(visit(vctx, found_key, flags, last_modified, 0) != evr_ok){
                goto out_with_reset_stmt;
            }
        }
        int key_col_size = sqlite3_column_bytes(list_stmt, 0);
        if(key_col_size != evr_blob_ref_size){
            goto out_with_reset_stmt;
        }
        has_found_key = 1;
        flags = new_flags;
        const void *sqkey = sqlite3_column_blob(list_stmt, 0);
        memcpy(found_key, sqkey, evr_blob_ref_size);
        last_modified = sqlite3_column_int64(list_stmt, 2);
    }
    ret = evr_ok;
 out_with_reset_stmt:
    if(sqlite3_reset(list_stmt) != SQLITE_OK){
        evr_panic("Unable to reset list_stmt for sort-order 0x%02x", filter->sort_order);
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_read_bucket_end_offset(size_t *end_offset, int f);

struct evr_glacier_write_ctx *evr_create_glacier_write_ctx(struct evr_glacier_storage_cfg *config){
    struct evr_glacier_write_ctx *ctx = (struct evr_glacier_write_ctx*)malloc(sizeof(struct evr_glacier_write_ctx));
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
                log_error("glacier storage lock file %s already exists", glacier_file_path);
                goto fail_free;
            }
            log_error("glacier storage could not create lock file %s", glacier_file_path);
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
    if(evr_prepare_stmt(ctx->db, "insert into blob_position (key, flags, bucket_index, bucket_blob_offset, blob_size, last_modified) values (?, ?, ?, ?, ?, ?)", &(ctx->insert_blob_stmt))){
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
        if(evr_read_bucket_end_offset(&ctx->current_bucket_pos, ctx->current_bucket_f) != evr_ok){
            goto fail_with_open_bucket;
        }
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

int evr_create_index_db(struct evr_glacier_write_ctx *ctx){
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
    // - last_modified last modified timestamp in unix epoch format.
    const char *structure_sql =
        "create table if not exists blob_position "
        "(key blob primary key not null, flags integer not null, bucket_index integer not null, bucket_blob_offset integer not null, blob_size integer not null, last_modified integer not null)";
    char *error;
    if(sqlite3_exec(ctx->db, structure_sql, NULL, NULL, &error) != SQLITE_OK){
        log_error("Failed to create index db structure for glacier %s: %s", ctx->config->bucket_dir_path, error);
        sqlite3_free(error);
        return 1;
    }
    return 0;
}

int move_to_last_bucket(struct evr_glacier_write_ctx *ctx){
    int ret = 1;
    unsigned long max_bucket_index = 0;
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
        unsigned long index = 0;
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

int open_current_bucket(struct evr_glacier_write_ctx *ctx) {
    ctx->current_bucket_f = evr_open_bucket(ctx->config, ctx->current_bucket_index, O_RDWR | O_CREAT);
    if(ctx->current_bucket_f == -1){
        return 1;
    }
    return 0;
}

int evr_open_bucket(const struct evr_glacier_storage_cfg *config, unsigned long bucket_index, int open_flags){
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

int evr_free_glacier_write_ctx(struct evr_glacier_write_ctx *ctx){
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

int evr_open_index_db(struct evr_glacier_storage_cfg *config, int sqliteFlags, sqlite3 **db){
    int ret = evr_error;
    size_t glacier_file_path_max_size = strlen(config->bucket_dir_path) + 10;
    char *glacier_file_path = alloca(glacier_file_path_max_size);
    build_glacier_file_path(glacier_file_path, glacier_file_path_max_size, config->bucket_dir_path, glacier_dir_index_db_path);
    sqlite3 *_db;
    int result = sqlite3_open_v2(glacier_file_path, &_db, sqliteFlags | SQLITE_OPEN_NOMUTEX, NULL);
    if(result != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(*db);
        log_error("glacier storage could not open %s sqlite database: %s", glacier_file_path, sqlite_error_msg);
        goto out;
    }
    if(sqlite3_busy_timeout(_db, evr_sqlite3_busy_timeout) != SQLITE_OK){
        goto out_with_close_db;
    }
    if(sqlite3_exec(_db, "pragma journal_mode=WAL", NULL, NULL, NULL) != SQLITE_OK){
        goto out_with_close_db;
    }
    *db = _db;
    ret = evr_ok;
 out:
    return ret;
 out_with_close_db:
    if(sqlite3_close(_db) != SQLITE_OK){
        ret = evr_error;
    }
    return ret;
}

int evr_close_index_db(struct evr_glacier_storage_cfg *config, sqlite3 *db){
    int db_result = sqlite3_close(db);
    if(db_result != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("glacier storage %s could not close sqlite index database: %s", config->bucket_dir_path, sqlite_error_msg);
        return 1;
    }
    return 0;
}

int unlink_lock_file(struct evr_glacier_write_ctx *ctx){
    size_t bucket_dir_path_size = strlen(ctx->config->bucket_dir_path) + 10;
    char *lock_file_path = alloca(bucket_dir_path_size);
    build_glacier_file_path(lock_file_path, bucket_dir_path_size, ctx->config->bucket_dir_path, glacier_dir_lock_file_path);
    if(lock_file_path[0] != '\0'){
        if(unlink(lock_file_path)){
            log_error("Can not unlink lock file %s", lock_file_path);
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

int evr_glacier_append_blob(struct evr_glacier_write_ctx *ctx, const struct evr_writing_blob *blob, evr_time *last_modified) {
    int ret = evr_error;
    evr_now(last_modified);
    uint64_t t64 = (uint64_t)*last_modified;
    const size_t blob_size_size = 4;
    const size_t header_buf_size = evr_blob_ref_size + sizeof(uint8_t) + sizeof(uint64_t) + blob_size_size + sizeof(uint8_t);
    char header_buf[header_buf_size];
    const size_t disk_size = header_buf_size + blob->size;
    if(disk_size > ctx->config->max_bucket_size){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_error("Can't persist blob for key %s in glacier directory %s with %ld bytes which is bigger than max bucket size %ld", fmt_key, ctx->config->bucket_dir_path, disk_size, ctx->config->max_bucket_size);
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
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, header_buf);
    evr_push_n(&bp, blob->key, evr_blob_ref_size);
    evr_push_as(&bp, &blob->flags, uint8_t);
    evr_push_map(&bp, &t64, uint64_t, htobe64);
    evr_push_map(&bp, &blob->size, uint32_t, htobe32);
    evr_push_8bit_checksum(&bp);
    struct evr_file current_bucket_f;
    evr_file_bind_fd(&current_bucket_f, ctx->current_bucket_f);
    if(write_n(&current_bucket_f, header_buf, header_buf_size) != evr_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_error("Can't write blob header for key %s in glacier directory %s.", fmt_key, ctx->config->bucket_dir_path);
        goto fail;
    }
    char **c = blob->chunks;
    for(size_t bytes_written = 0; bytes_written < blob->size;){
        size_t chunk_bytes_len = evr_chunk_size;
        size_t remaining_blob_bytes = blob->size - bytes_written;
        if(remaining_blob_bytes < chunk_bytes_len){
            chunk_bytes_len = remaining_blob_bytes;
        }
        if(write_n(&current_bucket_f, *c, chunk_bytes_len) != evr_ok){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, blob->key);
            log_error("Can't write blob data for key %s in glacier directory %s.", fmt_key, ctx->config->bucket_dir_path);
            goto fail;
        }
        bytes_written += chunk_bytes_len;
        c++;
    }
    if(fdatasync(ctx->current_bucket_f) != 0){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_error("Can't fsync blob data for key %s in glacier directory %s.");
        goto fail;
    }
    size_t blob_offset = ctx->current_bucket_pos + header_buf_size;
    ctx->current_bucket_pos += header_buf_size + blob->size;
    if(lseek(ctx->current_bucket_f, 0, SEEK_SET) == -1){
        goto fail;
    }
    uint32_t last_bucket_pos = htobe32(ctx->current_bucket_pos);
    if(write_n(&current_bucket_f, &last_bucket_pos, sizeof(last_bucket_pos)) != evr_ok){
        log_error("Can't write bucket end pointer in glacier directory %s", ctx->config->bucket_dir_path);
        goto fail;
    }
    if(fdatasync(ctx->current_bucket_f) != 0){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_error("Can't fsync bucket end pointer for key %s in glacier directory %s.");
        goto fail;
    }
    if(sqlite3_bind_blob(ctx->insert_blob_stmt, 1, blob->key, sizeof(blob->key), SQLITE_TRANSIENT) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 2, blob->flags) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int64(ctx->insert_blob_stmt, 3, ctx->current_bucket_index) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 4, blob_offset) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 5, blob->size) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(sqlite3_bind_int64(ctx->insert_blob_stmt, 6, t64) != SQLITE_OK){
        goto fail_with_insert_reset;
    }
    if(evr_step_stmt(ctx->db, ctx->insert_blob_stmt) != SQLITE_DONE){
        int sql_error = sqlite3_extended_errcode(ctx->db);
        if(sql_error != SQLITE_CONSTRAINT_PRIMARYKEY){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, blob->key);
            const char *sqlite_error_msg = sqlite3_errmsg(ctx->db);
            log_error("glacier storage %s failed to store blob with key %s to index with offset %lu and size %lu: %s", ctx->config->bucket_dir_path, fmt_key, blob_offset, blob->size, sqlite_error_msg);
            goto fail_with_insert_reset;
        }
#ifdef EVR_LOG_DEBUG
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_debug("Detected blob with key %s got inserted more than one time into buckets", fmt_key);
#endif
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_debug("Wrote blob with key %s to glacier", fmt_key);
    }
#endif
    ret = evr_ok;
 fail_with_insert_reset:
    if(sqlite3_reset(ctx->insert_blob_stmt) != SQLITE_OK){
        int sql_error = sqlite3_extended_errcode(ctx->db);
        if(sql_error != SQLITE_CONSTRAINT_PRIMARYKEY){
            ret = evr_error;
        }
    }
 fail:
    return ret;
}

int create_next_bucket(struct evr_glacier_write_ctx *ctx){
    if(close_current_bucket(ctx)){
        return 1;
    }
    ctx->current_bucket_index++;
    if(open_current_bucket(ctx)){
        return 1;
    }
    ctx->current_bucket_pos = sizeof(uint32_t);
    uint32_t pos = htobe32(ctx->current_bucket_pos);
    // TODO switch to write_n
    if(write(ctx->current_bucket_f, &pos, sizeof(pos)) != sizeof(pos)){
        log_error("Empty bucket file %05lx could not be created in glacier directory %s", ctx->current_bucket_index, ctx->config->bucket_dir_path);
        return 1;
    }
    return 0;
}

int close_current_bucket(struct evr_glacier_write_ctx *ctx){
    if(ctx->current_bucket_f != -1){
        if(close(ctx->current_bucket_f) == -1){
            return 1;
        }
        ctx->current_bucket_f = -1;
    }
    return 0;
}

int evr_quick_check_glacier(struct evr_glacier_storage_cfg *config){
    int ret = evr_error;
    struct evr_glacier_write_ctx *ctx = evr_create_glacier_write_ctx(config);
    if(!ctx){
        goto out;
    }
    ret = evr_ok;
    if(evr_free_glacier_write_ctx(ctx) != evr_ok){
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_glacier_walk_bucket(char *bucket_path, int (*visit_bucket)(void *ctx, size_t end_offset), int (*visit_blob)(void *ctx, struct evr_glacier_bucket_blob_stat *stat), void *ctx){
    int ret = evr_error;
    int f = open(bucket_path, O_RDONLY);
    if(f < 0){
        return ret;
    }
    const size_t header_size = evr_blob_ref_size + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint8_t);
    char buf[header_size];
    size_t end_offset;
    if(evr_read_bucket_end_offset(&end_offset, f) != evr_ok){
        goto out_with_close_f;
    }
    if(visit_bucket(ctx, end_offset) != evr_ok){
        goto out_with_close_f;
    }
    struct evr_file fd;
    evr_file_bind_fd(&fd, f);
    struct evr_glacier_bucket_blob_stat stat;
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    size_t f_pos = sizeof(uint32_t);
    while(1){
        stat.offset = f_pos;
        int header_read_res = read_n(&fd, buf, header_size, NULL, NULL);
        if(header_read_res == evr_end){
            break;
        }
        if(header_read_res != evr_ok){
            goto out_with_close_f;
        }
        evr_reset_buf_pos(&bp);
        evr_pull_n(&bp, stat.ref, evr_blob_ref_size);
        evr_pull_as(&bp, &stat.flags, uint8_t);
        evr_pull_map(&bp, &stat.last_modified, uint64_t, be64toh);
        evr_pull_map(&bp, &stat.size, uint32_t, be32toh);
        evr_pull_as(&bp, &stat.checksum, uint8_t);
        f_pos += header_size + stat.size;
        if(visit_blob(ctx, &stat) != evr_ok){
            goto out_with_close_f;
        }
        if(lseek(f, f_pos, SEEK_SET) == -1){
            goto out_with_close_f;
        }
    }
    ret = evr_ok;
 out_with_close_f:
    if(close(f) != 0){
        evr_panic("Unable to close bucket file");
        ret = evr_error;
    }
    return ret;
}

int evr_read_bucket_end_offset(size_t *end_offset, int f){
    uint32_t buf;
    struct evr_file fd;
    evr_file_bind_fd(&fd, f);
    if(read_n(&fd, (char*)&buf, sizeof(buf), NULL, NULL) != evr_ok){
        log_error("Failed to read bucket end offset");
        return evr_error;
    }
    *end_offset = be32toh(buf);
    return evr_ok;
}
