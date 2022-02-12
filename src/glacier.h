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

#include "configuration.h"
#include "errors.h"
#include "keys.h"

extern const size_t evr_max_chunks_per_blob;

/**
 * evr_blob_flag_claim indicates the blob may also be interpreted as
 * claim.
 */
#define evr_blob_flag_claim 0x01

struct evr_writing_blob {
    evr_blob_key_t key;
    int flags;
    size_t size;
    char **chunks;
};

struct evr_glacier_read_ctx {
    struct evr_glacier_storage_configuration *config;
    sqlite3 *db;
    sqlite3_stmt *find_blob_stmt;
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
struct evr_glacier_read_ctx *evr_create_glacier_read_ctx(struct evr_glacier_storage_configuration *config);

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
int evr_glacier_stat_blob(struct evr_glacier_read_ctx *ctx, const evr_blob_key_t key, struct evr_glacier_blob_stat *stat);

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
int evr_glacier_read_blob(struct evr_glacier_read_ctx *ctx, const evr_blob_key_t key, int (*status)(void *arg, int exists, int flags, size_t blob_size), int (*on_data)(void *arg, const char *data, size_t data_size), void *arg);

struct evr_glacier_write_ctx {
    struct evr_glacier_storage_configuration *config;
    unsigned long current_bucket_index;
    int current_bucket_f;
    size_t current_bucket_pos;
    sqlite3 *db;
    sqlite3_stmt *insert_blob_stmt;
};

/**
 * evr_create_glacier_write_ctx creates a struct evr_glacier_write_ctx.
 *
 * config must not be modifier or freed until
 * evr_free_glacier_write_ctx is called with the returned context.
 *
 * The returned context must be freed using evr_free_glacier_write_ctx.
 */
struct evr_glacier_write_ctx *evr_create_glacier_write_ctx(struct evr_glacier_storage_configuration *config);

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
 */
int evr_glacier_append_blob(struct evr_glacier_write_ctx *ctx, const struct evr_writing_blob *blob);

/**
 * evr_quick_check_glacier performs a quick sanity check of the
 * persisted glacier and creates it if not existing.
 */
int evr_quick_check_glacier(struct evr_glacier_storage_configuration *config);

#endif
