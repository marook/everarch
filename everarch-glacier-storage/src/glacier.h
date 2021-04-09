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

#ifndef __evr_glacier_h__
#define __evr_glacier_h__

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "configuration.h"

typedef uint8_t evr_hash_algorithm_t;

extern const evr_hash_algorithm_t evr_hash_algorithm_sha224;

typedef uint8_t evr_key_len_t;

typedef struct {
    /**
     * type indicates the kind of hashing algorithm used to produce key.
     */
    evr_hash_algorithm_t type;
    
    evr_key_len_t key_len;
    uint8_t *key;
} evr_blob_key_t;

/**
 * evr_chunk_size is the size of one chunk within the
 * evr_writing_blob_t struct in bytes.
 */
extern const size_t evr_chunk_size;
extern const size_t evr_max_blob_data_size;
extern const size_t evr_max_chunks_per_blob;

typedef uint32_t evr_blob_size_t;
#define evr_blob_size_to_be htobe32

typedef struct {
    evr_blob_key_t key;
    evr_blob_size_t size;
    uint8_t **chunks;
} evr_writing_blob_t;

typedef uint32_t evr_bucket_pos_t;
#define evr_bucket_pos_to_be htobe32
#define evr_be_to_bucket_pos be32toh

typedef unsigned long evr_bucket_index_t;

typedef struct {
    evr_glacier_storage_configuration *config;
    evr_bucket_index_t current_bucket_index;
    int current_bucket_f;
    evr_bucket_pos_t current_bucket_pos;
    sqlite3 *db;
    sqlite3_stmt *insert_blob_stmt;
} evr_glacier_ctx;

/**
 * evr_create_glacier_ctx creates a evr_glacier_ctx.
 *
 * config's ownership is given to the returned evr_glacier_ctx on
 * successful execution.
 *
 * The returned context must be freed using evr_free_glacier_ctx.
 */
evr_glacier_ctx *evr_create_glacier_ctx(evr_glacier_storage_configuration *config);

int evr_free_glacier_ctx(evr_glacier_ctx *ctx);

/**
 * evr_glacier_bucket_append appends the given blob at the current
 * bucket.
 *
 * A new current bucket is created if the blob does not fit into the
 * current bucket anymore.
 *
 * The blob's position in the appended bucket is written into the
 * index db.
 */
int evr_glacier_bucket_append(evr_glacier_ctx *ctx, const evr_writing_blob_t *blob);

#endif
