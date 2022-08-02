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
#define evr_bucket_file_ext "evb"
#define evr_bucket_file_name_fmt "%05lx." evr_bucket_file_ext

void build_glacier_file_path(char *glacier_file_path, size_t glacier_file_path_size, const char *bucket_dir_path, const char* path_suffix);

int evr_open_index_db(struct evr_glacier_storage_cfg *config, int sqliteFlags, sqlite3 **db);

int evr_close_index_db(struct evr_glacier_storage_cfg *config, sqlite3 *db);

int unlink_lock_file(struct evr_glacier_write_ctx *ctx);

int evr_create_index_db(struct evr_glacier_write_ctx *ctx);

int move_to_last_bucket(struct evr_glacier_write_ctx *ctx);

int open_current_bucket(struct evr_glacier_write_ctx *ctx, int create);

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
    // TODO check sqlite3_* return values and panic if necessary
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
        int status_res = status(arg, 0, 0, 0);
        if(status_res == evr_end){
            ret = evr_end;
        } else if(status_res != evr_ok){
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
    int status_res = status(arg, 1, flags, blob_size);
    if(status_res == evr_end){
        ret = evr_end;
        goto end_with_open_bucket;
    } else if(status_res != evr_ok){
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

int evr_read_bucket_end_offset(int f, size_t *end_offset);
int evr_write_bucket_end_offset(int f, size_t end_offset);

int evr_create_glacier_write_ctx(struct evr_glacier_write_ctx **context, struct evr_glacier_storage_cfg *config){
    int ret = evr_error;
    if(!config){
        goto fail;
    }
    struct evr_glacier_write_ctx *ctx = malloc(sizeof(struct evr_glacier_write_ctx));
    if(!ctx){
        goto fail;
    }
    ctx->config = config;
    ctx->current_bucket_index = 0;
    ctx->current_bucket_f = -1;
    ctx->current_bucket_pos = 0;
    ctx->db = NULL;
    ctx->insert_blob_stmt = NULL;
    ctx->insert_bucket_stmt = NULL;
    ctx->update_bucket_end_offset_stmt = NULL;
    ctx->find_bucket_end_offset_stmt = NULL;
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
        if(lock_f < 0){
            if(EEXIST == errno){
                log_error("glacier storage lock file %s already exists", glacier_file_path);
                goto fail_free;
            }
            log_error("glacier storage could not create lock file %s", glacier_file_path);
            goto fail_free;
        }
        if(close(lock_f) != 0){
            evr_panic("Unable to close lock file");
            goto fail_free;
        }
    }
    if(evr_open_index_db(config, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, &(ctx->db))){
        ret = evr_glacier_index_db_corrupt;
        goto fail_with_db;
    }
    if(evr_create_index_db(ctx)){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "insert into blob_position (key, flags, bucket_index, bucket_blob_offset, blob_size, last_modified) values (?, ?, ?, ?, ?, ?)", &ctx->insert_blob_stmt) != evr_ok){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "insert into bucket (bucket_index) values (?)", &ctx->insert_bucket_stmt) != evr_ok){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "update bucket set end_offset = ? where bucket_index = ?", &ctx->update_bucket_end_offset_stmt) != evr_ok){
        goto fail_with_db;
    }
    if(evr_prepare_stmt(ctx->db, "select end_offset from bucket where bucket_index = ?", &ctx->find_bucket_end_offset_stmt) != evr_ok){
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
        if(open_current_bucket(ctx, 0)){
            goto fail_with_db;
        }
        if(evr_read_bucket_end_offset(ctx->current_bucket_f, &ctx->current_bucket_pos) != evr_ok){
            goto fail_with_open_bucket;
        }
        if(ctx->current_bucket_pos == evr_bucket_end_offset_corrupt){
            log_debug("Skipping bucket " evr_bucket_file_name_fmt " because end offset indicates corrupt bucket end", ctx->current_bucket_index);
            if(create_next_bucket(ctx)){
                goto fail_with_open_bucket;
            }
        }
    }
    ret = evr_ok;
    *context = ctx;
    return ret;
 fail_with_open_bucket:
    if(close(ctx->current_bucket_f) != 0){
        evr_panic("Unable to close current bucket file.");
    }
 fail_with_db:
    sqlite3_finalize(ctx->find_bucket_end_offset_stmt);
    sqlite3_finalize(ctx->update_bucket_end_offset_stmt);
    sqlite3_finalize(ctx->insert_bucket_stmt);
    sqlite3_finalize(ctx->insert_blob_stmt);
    sqlite3_close(ctx->db);
    unlink_lock_file(ctx);
 fail_free:
    free(ctx);
 fail:
    return ret;
}

int evr_create_index_db(struct evr_glacier_write_ctx *ctx){
    char *sql[] = {
        // the following structure_sql creates the structure of the
        // sqlite index db used to quickly lookup blob positions. the
        // db containst the following tables and columns:
        //
        // blob_position
        // - key is the blob's key including type and key data.
        // - bucket_index is the index of the bucket file which is part
        //   of the bucket file's file name.
        // - bucket_blob_offset is the offset within the bucket file at
        //   which the blob data begins.
        // - blob_size is the size of the blob in bytes
        // - last_modified last modified timestamp in unix epoch format.
        "create table if not exists blob_position (key blob primary key not null, flags integer not null, bucket_index integer not null, bucket_blob_offset integer not null, blob_size integer not null, last_modified integer not null)",
        "create table if not exists bucket (bucket_index integer primary key not null, end_offset integer not null default " to_string(evr_bucket_header_size)  ")",
        NULL,
    };
    char *error;
    for(char **s = sql; *s; ++s){
        if(sqlite3_exec(ctx->db, *s, NULL, NULL, &error) != SQLITE_OK){
            log_error("Failed to create index db structure using \"%s\"for glacier %s: %s", *s, ctx->config->bucket_dir_path, error);
            sqlite3_free(error);
            return evr_error;
        }
    }
    return evr_ok;
}

int evr_move_to_last_bucket_visitor(void *context, unsigned long bucket_index, char *bucket_file_name);

int evr_walk_buckets(struct evr_glacier_write_ctx *wctx, int (*visit)(void *ctx, unsigned long bucket_index, char *bucket_file_name), void *ctx);

int move_to_last_bucket(struct evr_glacier_write_ctx *ctx){
    ctx->current_bucket_index = 0;
    if(evr_walk_buckets(ctx, evr_move_to_last_bucket_visitor, ctx) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_move_to_last_bucket_visitor(void *context, unsigned long bucket_index, char *bucket_file_name){
    struct evr_glacier_write_ctx *ctx = context;
    if(bucket_index > ctx->current_bucket_index){
        ctx->current_bucket_index = bucket_index;
    }
    return evr_ok;
}

int evr_walk_buckets(struct evr_glacier_write_ctx *wctx, int (*visit)(void *ctx, unsigned long bucket_index, char *bucket_file_name), void *ctx){
    int ret = evr_error;
    DIR *dir = opendir(wctx->config->bucket_dir_path);
    if(!dir){
        goto out;
    }
    errno = 0;
    while(1){
        struct dirent *d = readdir(dir);
        if(!d){
            if(errno){
                goto out_with_close_dir;
            }
            break;
        }
        const size_t file_name_size = strlen(d->d_name) + 1;
        char file_name[file_name_size];
        memcpy(file_name, d->d_name, file_name_size);
        char *end = file_name;
        for(; isxdigit(*end); end++){}
        if(strcmp(end, "." evr_bucket_file_ext) != 0){
            continue;
        }
        *end = '\0';
        unsigned long index = 0;
        if(sscanf(file_name, "%lx", &index) != 1){
            continue;
        }
        if(visit(ctx, index, d->d_name) != evr_ok){
            goto out_with_close_dir;
        }
    }
    ret = evr_ok;
 out_with_close_dir:
    if(closedir(dir) != 0){
        evr_panic("Unable to close glacier directory");
        ret = evr_error;
    }
 out:
    return ret;
}

int open_current_bucket(struct evr_glacier_write_ctx *ctx, int create) {
    int open_flags = O_RDWR | (create ? (O_CREAT | O_EXCL) : 0);
    ctx->current_bucket_f = evr_open_bucket(ctx->config, ctx->current_bucket_index, open_flags);
    if(ctx->current_bucket_f == -1){
        return evr_error;
    }
    return evr_ok;
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
        if(snprintf(s, end - bucket_path, evr_bucket_file_name_fmt, bucket_index) < 0){
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
    if(sqlite3_finalize(ctx->find_bucket_end_offset_stmt) != SQLITE_OK){
        goto end;
    }
    if(sqlite3_finalize(ctx->update_bucket_end_offset_stmt) != SQLITE_OK){
        goto end;
    }
    if(sqlite3_finalize(ctx->insert_bucket_stmt) != SQLITE_OK){
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
    if(sqlite3_exec(_db, "pragma synchronous=off", NULL, NULL, NULL) != SQLITE_OK){
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

int evr_glacier_add_blob_to_index(struct evr_glacier_write_ctx *ctx, evr_blob_ref ref, int flags, size_t blob_offset, size_t blob_size, evr_time last_modified);

int evr_glacier_append_blob(struct evr_glacier_write_ctx *ctx, struct evr_writing_blob *blob, evr_time *last_modified) {
    int ret = evr_error;
    evr_now(last_modified);
    uint64_t t64 = (uint64_t)*last_modified;
    char header_buf[evr_bucket_blob_header_size];
    const size_t disk_size = evr_bucket_blob_header_size + blob->size;
    if(disk_size + evr_bucket_header_size > ctx->config->max_bucket_size){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_error("Can't persist blob for key %s in glacier directory %s with %ld bytes which is bigger than max bucket size %ld", fmt_key, ctx->config->bucket_dir_path, disk_size + evr_bucket_header_size, ctx->config->max_bucket_size);
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
    if(write_n(&current_bucket_f, header_buf, evr_bucket_blob_header_size) != evr_ok){
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
    size_t blob_offset = ctx->current_bucket_pos + evr_bucket_blob_header_size;
    ctx->current_bucket_pos += evr_bucket_blob_header_size + blob->size;
    const size_t end_offset = ctx->current_bucket_pos;
    if(evr_write_bucket_end_offset(ctx->current_bucket_f, ctx->current_bucket_pos) != evr_ok){
        goto fail;
    }
    if(evr_glacier_add_blob_to_index(ctx, blob->key, blob->flags, blob_offset, blob->size, *last_modified) != evr_ok){
        goto fail;
    }
    if(sqlite3_bind_int(ctx->update_bucket_end_offset_stmt, 1, end_offset) != SQLITE_OK){
        goto out_with_reset_update_bucket_end_offset_stmt;
    }
    if(sqlite3_bind_int(ctx->update_bucket_end_offset_stmt, 2, ctx->current_bucket_index) != SQLITE_OK){
        goto out_with_reset_update_bucket_end_offset_stmt;
    }
    if(evr_step_stmt(ctx->db, ctx->update_bucket_end_offset_stmt) != SQLITE_DONE){
        goto out_with_reset_update_bucket_end_offset_stmt;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, blob->key);
        log_debug("Wrote blob with key %s to glacier", fmt_key);
    }
#endif
    ret = evr_ok;
 out_with_reset_update_bucket_end_offset_stmt:
    if(sqlite3_reset(ctx->update_bucket_end_offset_stmt) != SQLITE_OK){
        evr_panic("Unable to reset update_bucket_end_offset_stmt");
        ret = evr_error;
    }
 fail:
    return ret;
}

int evr_glacier_add_blob_to_index(struct evr_glacier_write_ctx *ctx, evr_blob_ref ref, int flags, size_t blob_offset, size_t blob_size, evr_time last_modified){
    int ret = evr_error;
    if(sqlite3_bind_blob(ctx->insert_blob_stmt, 1, ref, evr_blob_ref_size, SQLITE_TRANSIENT) != SQLITE_OK){
        goto out_with_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 2, flags) != SQLITE_OK){
        goto out_with_reset;
    }
    if(sqlite3_bind_int64(ctx->insert_blob_stmt, 3, ctx->current_bucket_index) != SQLITE_OK){
        goto out_with_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 4, blob_offset) != SQLITE_OK){
        goto out_with_reset;
    }
    if(sqlite3_bind_int(ctx->insert_blob_stmt, 5, blob_size) != SQLITE_OK){
        goto out_with_reset;
    }
    if(sqlite3_bind_int64(ctx->insert_blob_stmt, 6, last_modified) != SQLITE_OK){
        goto out_with_reset;
    }
    if(evr_step_stmt(ctx->db, ctx->insert_blob_stmt) != SQLITE_DONE){
        int sql_error = sqlite3_extended_errcode(ctx->db);
        if(sql_error != SQLITE_CONSTRAINT_PRIMARYKEY){
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, ref);
            const char *sqlite_error_msg = sqlite3_errmsg(ctx->db);
            log_error("glacier storage %s failed to store blob with key %s to index with offset %lu and size %lu: %s", ctx->config->bucket_dir_path, fmt_key, blob_offset, blob_size, sqlite_error_msg);
            goto out_with_reset;
        }
#ifdef EVR_LOG_DEBUG
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, ref);
        log_debug("Detected blob with key %s got inserted more than one time into buckets", fmt_key);
#endif
    }
    ret = evr_ok;
 out_with_reset:
    if(sqlite3_reset(ctx->insert_blob_stmt) != SQLITE_OK){
        int sql_error = sqlite3_extended_errcode(ctx->db);
        if(sql_error != SQLITE_CONSTRAINT_PRIMARYKEY){
            evr_panic("Unable to reset insert_blob_stmt");
            ret = evr_error;
        }
    }
    return ret;
}

int create_next_bucket(struct evr_glacier_write_ctx *ctx){
    int ret = evr_error;
    if(close_current_bucket(ctx) != evr_ok){
        evr_panic("Unable to close current bucket");
        goto out;
    }
    ctx->current_bucket_index++;
    if(open_current_bucket(ctx, 1)){
        ctx->current_bucket_index--;
        goto out;
    }
    ctx->current_bucket_pos = evr_bucket_header_size;
    if(evr_write_bucket_end_offset(ctx->current_bucket_f, ctx->current_bucket_pos) != evr_ok){
        goto out;
    }
    if(sqlite3_bind_int(ctx->insert_bucket_stmt, 1, ctx->current_bucket_index) != SQLITE_OK){
        goto out_with_reset_insert_bucket_stmt;
    }
    if(evr_step_stmt(ctx->db, ctx->insert_bucket_stmt) != SQLITE_DONE){
        log_error("Unable to insert bucket " evr_bucket_file_name_fmt " metadata in index.db", ctx->current_bucket_index);
        goto out_with_reset_insert_bucket_stmt;
    }
    ret = evr_ok;
 out_with_reset_insert_bucket_stmt:
    if(sqlite3_reset(ctx->insert_bucket_stmt) != SQLITE_OK){
        evr_panic("Unable to reset insert_bucket_stmt");
        ret = evr_error;
    }
 out:
    return ret;
}

int close_current_bucket(struct evr_glacier_write_ctx *ctx){
    if(ctx->current_bucket_f != -1){
        if(close(ctx->current_bucket_f) != 0){
            return evr_error;
        }
        ctx->current_bucket_f = -1;
    }
    return evr_ok;
}

int evr_glacier_check_index_db(struct evr_glacier_write_ctx *ctx);

int evr_glacier_recreate_index_db(struct evr_glacier_storage_cfg *config);

int evr_quick_check_glacier(struct evr_glacier_storage_cfg *config){
    struct evr_glacier_write_ctx *ctx;
    int create_res = evr_create_glacier_write_ctx(&ctx, config);
    if(create_res == evr_ok){
        int check_res = evr_glacier_check_index_db(ctx);
        if(evr_free_glacier_write_ctx(ctx) != evr_ok){
            evr_panic("Quick check is unable to free glacier write context");
            return evr_error;
        }
        if(check_res == evr_glacier_index_db_corrupt){
            log_info("glacier index.db is inconsistent");
            if(evr_glacier_recreate_index_db(config) != evr_ok){
                evr_panic("Unable to recreate glacier index.db");
                return evr_error;
            }
        } else if(check_res != evr_ok){
            evr_panic("Unable to check for index.db consistency");
            return evr_error;
        }
        return evr_ok;
    } else if(create_res == evr_glacier_index_db_corrupt) {
        if(evr_glacier_recreate_index_db(config) != evr_ok){
            evr_panic("Unable to recreate glacier index.db");
            return evr_error;
        }
        return evr_ok;
    } else {
        return evr_error;
    }
}

int evr_glacier_check_random_blobs(struct evr_glacier_write_ctx *ctx);

int evr_glacier_check_index_db(struct evr_glacier_write_ctx *ctx){
    int ret = evr_error;
    int bucket_end_offset = lseek(ctx->current_bucket_f, 0, SEEK_END);
    if(bucket_end_offset == -1){
        goto out;
    }
    if(sqlite3_bind_int(ctx->find_bucket_end_offset_stmt, 1, ctx->current_bucket_index) != SQLITE_OK){
        goto out_with_reset_find_bucket_end_offset_stmt;
    }
    int find_offset_res = evr_step_stmt(ctx->db, ctx->find_bucket_end_offset_stmt);
    if(find_offset_res == SQLITE_DONE){
        // no end offset for the current bucket was found in the
        // index.db. that means the index.db is empty and must be
        // populated again.
        log_error("Missing bucket end offset in index.db for bucket " evr_bucket_file_name_fmt, ctx->current_bucket_index);
        ret = evr_glacier_index_db_corrupt;
        goto out_with_reset_find_bucket_end_offset_stmt;
    } else if(find_offset_res == SQLITE_ROW){
        int db_end_offset = sqlite3_column_int(ctx->find_bucket_end_offset_stmt, 0);
        if(db_end_offset != bucket_end_offset){
            log_error("End offset from bucket " evr_bucket_file_name_fmt " was %d and did not match end offset %d from index db", ctx->current_bucket_index, bucket_end_offset, db_end_offset);
            ret = evr_glacier_index_db_corrupt;
            goto out_with_reset_find_bucket_end_offset_stmt;
        }
    } else {
        log_error("Unable to lookup end offset for bucket " evr_bucket_file_name_fmt " in index db.", ctx->current_bucket_index);
        // treat this situation as corrupt index.db because it's the
        // first access to the index.db after opening it. so maybe
        // recreating the index.db will solve the issue.
        ret = evr_glacier_index_db_corrupt;
        goto out_with_reset_find_bucket_end_offset_stmt;
    }
    if(ctx->current_bucket_pos != bucket_end_offset){
        log_info("Bucket " evr_bucket_file_name_fmt "'s end pointer (%d) and file end offset (%ld) don't match in glacier directory %s. It looks like evr-glacier-storage terminated not gracafully while writing a blob.", ctx->current_bucket_index, ctx->current_bucket_pos, bucket_end_offset, ctx->config->bucket_dir_path);
    }
    int blobs_check_res = evr_glacier_check_random_blobs(ctx);
    if(blobs_check_res == evr_glacier_index_db_corrupt){
        ret = evr_glacier_index_db_corrupt;
        goto out_with_reset_find_bucket_end_offset_stmt;
    } else if(blobs_check_res != evr_ok){
        goto out_with_reset_find_bucket_end_offset_stmt;
    }
    ret = evr_ok;
 out_with_reset_find_bucket_end_offset_stmt:
    if(sqlite3_reset(ctx->find_bucket_end_offset_stmt) != SQLITE_OK){
        evr_panic("Unable to reset find_bucket_end_offset_stmt");
        ret = evr_error;
    }
 out:
    return ret;
}

struct evr_glacier_blob_check_ctx {
    evr_blob_ref ref;
    int flags;
    size_t blob_size;
    int ret;
    evr_blob_ref_hd blob_hd;
};

int evr_glacier_blob_check_status(void *ctx, int exists, int flags, size_t blob_size);

int evr_glacier_blob_check_data(void *ctx, const char *data, size_t data_size);

int evr_glacier_check_random_blobs(struct evr_glacier_write_ctx *wctx){
    int ret = evr_error;
    struct evr_glacier_read_ctx *rctx = evr_create_glacier_read_ctx(wctx->config);
    if(!rctx){
        goto out;
    }
    sqlite3_stmt *find_blobs_stmt;
    if(evr_prepare_stmt(wctx->db, "select key, flags, blob_size from blob_position", &find_blobs_stmt) != evr_ok){
        goto out_with_free_rctx;
    }
    struct evr_glacier_blob_check_ctx bctx;
    for(int i = 0; i < 1024; ++i){
        int step_res = evr_step_stmt(wctx->db, find_blobs_stmt);
        if(step_res == SQLITE_DONE){
            break;
        } else if(step_res != SQLITE_ROW){
            goto out_with_finalize_find_blobs_stmt;
        }
        int ref_col_size = sqlite3_column_bytes(find_blobs_stmt, 0);
        if(ref_col_size != evr_blob_ref_size){
            ret = evr_glacier_index_db_corrupt;
            goto out_with_finalize_find_blobs_stmt;
        }
        const void *sqref = sqlite3_column_blob(find_blobs_stmt, 0);
        memcpy(bctx.ref, sqref, evr_blob_ref_size);
        bctx.flags = sqlite3_column_int(find_blobs_stmt, 1);
        bctx.blob_size = sqlite3_column_int(find_blobs_stmt, 2);
#ifdef EVR_LOG_DEBUG
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, bctx.ref);
        log_debug("Checking blob %s", ref_str);
#endif
        bctx.ret = evr_error;
        if(evr_blob_ref_open(&bctx.blob_hd) != evr_ok){
            goto out_with_finalize_find_blobs_stmt;
        }
        if(evr_glacier_read_blob(rctx, bctx.ref, evr_glacier_blob_check_status, evr_glacier_blob_check_data, &bctx) != evr_ok){
            evr_blob_ref_close(bctx.blob_hd);
            goto out_with_finalize_find_blobs_stmt;
        }
        if(bctx.ret == evr_glacier_index_db_corrupt){
            ret = evr_glacier_index_db_corrupt;
            evr_blob_ref_close(bctx.blob_hd);
            goto out_with_finalize_find_blobs_stmt;
        } else if(bctx.ret != evr_ok){
            evr_blob_ref_close(bctx.blob_hd);
            goto out_with_finalize_find_blobs_stmt;
        }
        if(evr_blob_ref_hd_match(bctx.blob_hd, bctx.ref) != evr_ok){
            evr_blob_ref_str ref_str;
            evr_fmt_blob_ref(ref_str, bctx.ref);
            log_error("Blob hash does not match ref for blob with ref %s", ref_str);
            ret = evr_glacier_index_db_corrupt;
            evr_blob_ref_close(bctx.blob_hd);
            goto out_with_finalize_find_blobs_stmt;
        }
        evr_blob_ref_close(bctx.blob_hd);
    }
    ret = evr_ok;
 out_with_finalize_find_blobs_stmt:
    if(sqlite3_finalize(find_blobs_stmt) != SQLITE_OK){
        evr_panic("Unable to finalize find_blobs_stmt.");
        ret = evr_error;
    }
 out_with_free_rctx:
    if(evr_free_glacier_read_ctx(rctx) != evr_ok){
        evr_panic("Unable to close glacier read context for random blobs check.");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_glacier_blob_check_status(void *ctx, int exists, int flags, size_t blob_size){
    struct evr_glacier_blob_check_ctx *bctx = ctx;
    if(!exists){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, bctx->ref);
        log_error("Blob with ref %s no longer exists", ref_str);
        goto corrupt;
    }
    if(flags != bctx->flags || blob_size != bctx->blob_size){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, bctx->ref);
        log_error("Metadata for lob with ref %s no longer matches. Flags %d <=> %d. Blob size %lu <=> %lu", ref_str, flags, bctx->flags, (unsigned long)blob_size, (unsigned long)bctx->blob_size);
        goto corrupt;
    }
    bctx->ret = evr_ok;
    return evr_ok;
 corrupt:
    bctx->ret = evr_glacier_index_db_corrupt;
    return evr_end;
}

int evr_glacier_blob_check_data(void *ctx, const char *data, size_t data_size){
    struct evr_glacier_blob_check_ctx *bctx = ctx;
    evr_blob_ref_write(bctx->blob_hd, data, data_size);
    return evr_ok;
}

int evr_glacier_reindex(struct evr_glacier_write_ctx *ctx);

int evr_glacier_recreate_index_db(struct evr_glacier_storage_cfg *config){
    int ret = evr_error;
    log_info("Recreate glacier index.db");
    // delete index.db
    {
        const size_t bucket_dir_path_len = strlen(config->bucket_dir_path);
        const char index_file_name[] = "/index.db";
        const size_t index_file_name_len = strlen(index_file_name);
        char index_db_path[bucket_dir_path_len + index_file_name_len + 1];
        memcpy(index_db_path, config->bucket_dir_path, bucket_dir_path_len);
        memcpy(&index_db_path[bucket_dir_path_len], index_file_name, index_file_name_len);
        index_db_path[bucket_dir_path_len + index_file_name_len] = '\0';
        if(unlink(index_db_path) != 0){
            log_error("Unable to delete %s", index_db_path);
            goto out;
        }
    }
    struct evr_glacier_write_ctx *ctx;
    if(evr_create_glacier_write_ctx(&ctx, config) != evr_ok){
        goto out;
    }
    if(evr_glacier_reindex(ctx) != evr_ok){
        log_error("Unable to reindex glacier");
        goto out_with_free_ctx;
    }
    ret = evr_ok;
 out_with_free_ctx:
    if(evr_free_glacier_write_ctx(ctx) != evr_ok){
        evr_panic("Unable to free glacier write context after index recreate");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_glacier_reindex_bucket(void *context, unsigned long bucket_index, char *bucket_file_name);

int evr_glacier_reindex(struct evr_glacier_write_ctx *ctx){
    if(evr_walk_buckets(ctx, evr_glacier_reindex_bucket, ctx) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_glacier_reindex_visit_blob(void *context, struct evr_glacier_bucket_blob_stat *stat);

int evr_glacier_reindex_bucket(void *context, unsigned long bucket_index, char *bucket_file_name){
    int ret = evr_error;
    struct evr_glacier_write_ctx *ctx = context;
    log_debug("Reindexing bucket %s", bucket_file_name);
    const size_t bucket_dir_path_len = strlen(ctx->config->bucket_dir_path);
    const char sep[] = "/";
    const size_t bucket_file_name_len = strlen(bucket_file_name);
    char bucket_path[bucket_dir_path_len + sizeof(sep)-1 + bucket_file_name_len + 1];
    ctx->current_bucket_index = bucket_index;
    if(open_current_bucket(ctx, 0) != evr_ok){
        goto out;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, bucket_path);
    evr_push_n(&bp, ctx->config->bucket_dir_path, bucket_dir_path_len);
    evr_push_n(&bp, sep, sizeof(sep) - 1);
    evr_push_n(&bp, bucket_file_name, bucket_file_name_len);
    evr_push_eos(&bp);
    int walk_res = evr_glacier_walk_bucket(bucket_path, NULL, evr_glacier_reindex_visit_blob, ctx);
    int end_offset;
    if(walk_res == evr_end){
        log_info("Mark bucket " evr_bucket_file_name_fmt " with corrupt end offset", bucket_index);
        end_offset = evr_bucket_end_offset_corrupt;
        goto out_with_write_end_offset;
    } else if(walk_res != evr_ok){
        goto out;
    }
    end_offset = lseek(ctx->current_bucket_f, 0, SEEK_END);
    if(end_offset == -1){
        goto out;
    }
 out_with_write_end_offset:
    if(evr_write_bucket_end_offset(ctx->current_bucket_f, end_offset) != evr_ok){
        goto out;
    }
    if(sqlite3_bind_int(ctx->insert_bucket_stmt, 1, ctx->current_bucket_index) != SQLITE_OK){
        goto out_with_reset_insert_stmt;
    }
    if(evr_step_stmt(ctx->db, ctx->insert_bucket_stmt) != SQLITE_DONE){
        goto out_with_reset_insert_stmt;
    }
    if(sqlite3_bind_int(ctx->update_bucket_end_offset_stmt, 1, end_offset) != SQLITE_OK){
        goto out_with_reset_update_stmt;
    }
    if(sqlite3_bind_int(ctx->update_bucket_end_offset_stmt, 2, ctx->current_bucket_index) != SQLITE_OK){
        goto out_with_reset_update_stmt;
    }
    if(evr_step_stmt(ctx->db, ctx->update_bucket_end_offset_stmt) != SQLITE_DONE){
        goto out_with_reset_update_stmt;
    }
    ret = evr_ok;
 out_with_reset_update_stmt:
    if(sqlite3_reset(ctx->update_bucket_end_offset_stmt) != SQLITE_OK){
        evr_panic("Unable to reset update_bucket_end_offset_stmt");
        ret = evr_error;
    }
 out_with_reset_insert_stmt:
    if(sqlite3_reset(ctx->insert_bucket_stmt) != SQLITE_OK){
        evr_panic("Unable to reset insert_bucket_stmt");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_glacier_reindex_visit_blob(void *context, struct evr_glacier_bucket_blob_stat *stat){
    int ret = evr_error;
    struct evr_glacier_write_ctx *ctx = context;
    if(stat->checksum_valid != evr_ok){
        log_error("Blob header with invalid checksum detected. Abort reindexing bucket.");
        ret = evr_end;
        goto out;
    }
    if(lseek(ctx->current_bucket_f, stat->offset, SEEK_SET) == -1){
        goto out;
    }
    evr_blob_ref_hd hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto out;
    }
    struct evr_file f;
    evr_file_bind_fd(&f, ctx->current_bucket_f);
    if(dump_n(&f, stat->size, evr_blob_ref_write_se, hd) != evr_ok){
        goto out_with_close_hd;
    }
    if(evr_blob_ref_hd_match(hd, stat->ref) != evr_ok){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, stat->ref);
        log_error("Blob's body no longer matches ref %s. Skipping this blob.", ref_str);
        ret = evr_ok;
        goto out_with_close_hd;
    }
    if(evr_glacier_add_blob_to_index(ctx, stat->ref, stat->flags, stat->offset, stat->size, stat->last_modified) != evr_ok){
        goto out_with_close_hd;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, stat->ref);
        log_debug("Reindexed blob %s", ref_str);
    }
#endif
    ret = evr_ok;
 out_with_close_hd:
    evr_blob_ref_close(hd);
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
    if(evr_read_bucket_end_offset(f, &end_offset) != evr_ok){
        goto out_with_close_f;
    }
    if(visit_bucket){
        int visit_res = visit_bucket(ctx, end_offset);
        if(visit_res == evr_end){
            ret = evr_end;
            goto out_with_close_f;
        }
        if(visit_res != evr_ok){
            goto out_with_close_f;
        }
    }
    struct evr_file fd;
    evr_file_bind_fd(&fd, f);
    struct evr_glacier_bucket_blob_stat stat;
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    size_t f_pos = sizeof(uint32_t);
    while(1){
        stat.offset = f_pos + header_size;
        size_t visited_bytes = 0;
        int header_read_res = read_n(&fd, buf, header_size, visited_bytes_counter_se, &visited_bytes);
        if(header_read_res == evr_end){
            if(visited_bytes == 0){
                break;
            } else {
                ret = evr_end;
                goto out_with_close_f;
            }
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
        evr_inc_buf_pos(&bp, -1);
        stat.checksum_valid = evr_pull_8bit_checksum(&bp);
        f_pos += header_size + stat.size;
        int visit_res = visit_blob(ctx, &stat);
        if(visit_res == evr_end){
            ret = evr_end;
            goto out_with_close_f;
        } else if(visit_res != evr_ok){
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

int evr_read_bucket_end_offset(int f, size_t *end_offset){
    uint32_t buf;
    struct evr_file fd;
    evr_file_bind_fd(&fd, f);
    if(lseek(f, 0, SEEK_SET) != 0){
        return evr_error;
    }
    if(read_n(&fd, (char*)&buf, sizeof(buf), NULL, NULL) != evr_ok){
        log_error("Failed to read bucket end offset");
        return evr_error;
    }
    *end_offset = be32toh(buf);
    return evr_ok;
}

int evr_write_bucket_end_offset(int f, size_t end_offset){
    uint32_t buf = htobe32(end_offset);
    struct evr_file fd;
    evr_file_bind_fd(&fd, f);
    if(lseek(f, 0, SEEK_SET) != 0){
        return evr_error;
    }
    if(write_n(&fd, &buf, evr_bucket_header_size) != evr_ok){
        log_error("Can't write bucket end offset");
        return evr_error;
    }
    if(fdatasync(f) != 0){
        log_error("Can't fsync bucket end offset");
        return evr_error;
    }
    return evr_ok;
}
