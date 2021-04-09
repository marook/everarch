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

#ifndef __glacier_h__
#define __glacier_h__

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "configuration.h"

typedef uint8_t hash_algorithm_t;

extern const hash_algorithm_t evr_hash_algorithm_sha224;

typedef uint8_t key_len_t;

typedef struct {
    /**
     * type indicates the kind of hashing algorithm used to produce key.
     */
    hash_algorithm_t type;
    
    key_len_t key_len;
    uint8_t *key;
} blob_key_t;

/**
 * chunk_size is the size of one chunk within the written_blob struct
 * in bytes.
 */
extern const size_t chunk_size;
extern const size_t max_blob_data_size;
extern const size_t max_chunks_per_blob;

typedef uint32_t blob_size_t;
#define blob_size_to_be htobe32

typedef struct {
    blob_key_t key;
    blob_size_t size;
    uint8_t **chunks;
} written_blob;

typedef uint32_t bucket_pos_t;
#define bucket_pos_to_be htobe32
#define be_to_bucket_pos be32toh

typedef unsigned long bucket_index_t;

typedef struct {
    evr_glacier_storage_configuration *config;
    bucket_index_t current_bucket_index;
    int current_bucket_f;
    bucket_pos_t current_bucket_pos;
    sqlite3 *db;
    sqlite3_stmt *insert_blob_stmt;
} evr_glacier_ctx;

/**
 * create_evr_glacier_ctx creates a evr_glacier_ctx.
 *
 * config's ownership is given to the returned evr_glacier_ctx on
 * successful execution.
 *
 * The returned context must be freed using free_evr_glacier_ctx.
 */
evr_glacier_ctx *create_evr_glacier_ctx(evr_glacier_storage_configuration *config);

int free_evr_glacier_ctx(evr_glacier_ctx *ctx);

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
int evr_glacier_bucket_append(evr_glacier_ctx *ctx, const written_blob *blob);

#endif
