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

#ifndef __evr_keys_h__
#define __evr_keys_h__

#include <stdint.h>

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
 * evr_formatted_key_size returns the number of bytes which would be
 * required to store a string formatted version of key.
 *
 * Returns 0 if an invalid key is supplied.
 */
size_t evr_fmt_key_size(const evr_blob_key_t *key);

/**
 * evr_format_key formats key in a human readable way into dest.
 *
 * Formatted keys may look like "sha224-deadbeef".
 *
 * max_size limits the bytes written.
 *
 * Return evr_ok on success. Otherwise evr_error may be returned if
 * space in dest is not enough.
 */
int evr_fmt_key(char *dest, size_t max_size, const evr_blob_key_t *key);

/**
 * evr_fmt_key_into is a shorthand for formatting a key into a string
 * on the stack.
 */
#define evr_fmt_key_into(var, key, fail) \
    size_t var ## _size = evr_fmt_key_size(key); \
    if(var ## _size == 0){ \
        goto fail; \
    } \
    char *var = alloca(var ## _size); \
    evr_fmt_key(var, var ## _size, key)

/**
 * evr_blob_key_sha224_size is the size required to fit in a
 * evr_blob_key_t which holds a key of type sha224.
 */
#define evr_blob_key_sha224_size (sizeof(evr_blob_key_t) + 224 / 8)

#endif
