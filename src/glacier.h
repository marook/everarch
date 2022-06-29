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

#ifndef __evr_glacier_h__
#define __evr_glacier_h__

#include "config.h"

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "glacier-storage-configuration.h"
#include "errors.h"
#include "keys.h"
#include "basics.h"

/**
 * evr bucket header contains the end offset (uint32_t).
 */
#define evr_bucket_header_size 4

#define evr_bucket_blob_header_size (evr_blob_ref_size + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint8_t))

/**
 * evr_bucket_end_offset_corrupt is a special bucket end offset which
 * indicates that the end offset must not be trusted because blobs in
 * the bucket are corrupt. Having a corrupt end offset prohibits
 * appending further blobs to this bucket.
 */
#define evr_bucket_end_offset_corrupt 0

extern const size_t evr_max_chunks_per_blob;

struct evr_writing_blob {
    evr_blob_ref key;
    int flags;
    size_t size;
    char **chunks;
};

struct evr_glacier_read_ctx {
    struct evr_glacier_storage_cfg *config;
    sqlite3 *db;
    sqlite3_stmt *find_blob_stmt;
    sqlite3_stmt *list_blobs_stmt_order_last_modified;
    sqlite3_stmt *list_blobs_stmt_order_blob_ref;
    char *read_buffer;
};

/**
 * evr_create_glacier_read_ctx creates a new struct
 * evr_glacier_read_ctx.
 *
 * config must not be modified or freed until
 * evr_free_glacier_read_ctx is called with the returned context.
 *
 * A read context can only be created after a
 * evr_create_glacier_write_ctx initalized the glacier on disk. This
 * initialization could also have happend in a past process.
 *
 * The returned context must be freed using evr_free_glacier_read_ctx.
 */
struct evr_glacier_read_ctx *evr_create_glacier_read_ctx(struct evr_glacier_storage_cfg *config);

int evr_free_glacier_read_ctx(struct evr_glacier_read_ctx *ctx);

struct evr_glacier_blob_stat {
    int flags;
    size_t blob_size;
};

/**
 * evr_glacier_stat_blob retieves metadata for a blob with a given
 * key.
 *
 * Returns evr_ok if the blob was found. Returns evr_not_found if no
 * blob with the given key exists. Otherwise evr_error.
 */
int evr_glacier_stat_blob(struct evr_glacier_read_ctx *ctx, const evr_blob_ref key, struct evr_glacier_blob_stat *stat);

/**
 * evr_glacier_read_blob reads a blob with the given key.
 *
 * The function returns evr_not_found if the key is not part of the
 * glacier.
 *
 * status is invoked before the first on_data call. exists 0 indicates
 * that the blob does not exist.
 *
 * on_data callback may be invoked multiple times. on_data must return
 * evr_ok on successful processing. on_data's data argument is only
 * allocated while on_data is executed.
 */
int evr_glacier_read_blob(struct evr_glacier_read_ctx *ctx, const evr_blob_ref key, int (*status)(void *arg, int exists, int flags, size_t blob_size), int (*on_data)(void *arg, const char *data, size_t data_size), void *arg);

/**
 * evr_cmd_watch_sort_order_last_modified indicates sort by last
 * modified ascending.
 */
#define evr_cmd_watch_sort_order_last_modified 0x01

/**
 * evr_cmd_watch_sort_order_ref indicates sort by blob ref ascending.
 */
#define evr_cmd_watch_sort_order_ref 0x02

struct evr_blob_filter {
    /**
     * sort_order must be one of evr_cmd_watch_sort_order_*.
     */
    int sort_order;
    
    /**
     * flags_filter is a set of bits which must be set at least so
     * that the blob is passed by the filter.
     */
    int flags_filter;

    /**
     * last_modified_after is the timestamp after which a blob must
     * have been modified in order to be passed by the filter.
     *
     * Future last_modified_after values will not report any
     * modifications already persisted into the glacier storage. But
     * live modifications on blobs will be reported even if they lie
     * behind last_modified_after.
     */
    evr_time last_modified_after;
};

int evr_glacier_list_blobs(struct evr_glacier_read_ctx *ctx, int (*visit)(void *vctx, const evr_blob_ref key, int flags, evr_time last_modified, int last_blob), struct evr_blob_filter *filter, void *vctx);

struct evr_glacier_write_ctx {
    struct evr_glacier_storage_cfg *config;
    unsigned long current_bucket_index;
    int current_bucket_f;
    size_t current_bucket_pos;
    sqlite3 *db;
    sqlite3_stmt *insert_blob_stmt;
    sqlite3_stmt *insert_bucket_stmt;
    sqlite3_stmt *update_bucket_end_offset_stmt;
    sqlite3_stmt *find_bucket_end_offset_stmt;
};

/**
 * evr_create_glacier_write_ctx creates a struct evr_glacier_write_ctx.
 *
 * config must not be modifier or freed until
 * evr_free_glacier_write_ctx is called with the returned context.
 *
 * The created context must be freed using evr_free_glacier_write_ctx.
 */
int evr_create_glacier_write_ctx(struct evr_glacier_write_ctx **ctx, struct evr_glacier_storage_cfg *config);

int evr_free_glacier_write_ctx(struct evr_glacier_write_ctx *ctx);

/**
 * evr_glacier_append_blob appends the given blob at the current
 * bucket.
 *
 * A new current bucket is created if the blob does not fit into the
 * current bucket anymore.
 *
 * The blob's position in the appended bucket is written into the
 * index db.
 *
 * last_modified is set to the blob's last modified timestamp after
 * the function returns.
 */
int evr_glacier_append_blob(struct evr_glacier_write_ctx *ctx, struct evr_writing_blob *blob, evr_time *last_modified);

/**
 * evr_glacier_add_watcher registers a callback which fires after a
 * blob got modified.
 *
 * Returns a negative value on error and a watch descriptor (wd) on
 * success.
 */
int evr_glacier_add_watcher(struct evr_glacier_write_ctx *ctx, void (*watcher)(void *wctx, int wd, evr_blob_ref key, int flags, evr_time last_modified), void *wctx);

/**
 * evr_glacier_rm_watcher unregisters a watch callback.
 *
 * Returns evr_ok on success. Otherwise evr_error.
 */
int evr_glacier_rm_watcher(struct evr_glacier_write_ctx *ctx, int wd);

/**
 * evr_quick_check_glacier performs a quick sanity check of the
 * persisted glacier and creates it if not existing.
 */
int evr_quick_check_glacier(struct evr_glacier_storage_cfg *config);

struct evr_glacier_bucket_blob_stat {
    evr_blob_ref ref;
    int flags;
    evr_time last_modified;
    size_t offset;
    size_t size;
    unsigned char checksum;
    int checksum_valid;
};

int evr_glacier_walk_bucket(char *bucket_path, int (*visit_bucket)(void *ctx, size_t end_offset), int (*visit_blob)(void *ctx, struct evr_glacier_bucket_blob_stat *stat), void *ctx);

#endif
