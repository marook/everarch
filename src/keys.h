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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define evr_blob_key_bits 224
#define evr_blob_key_size (evr_blob_key_bits / 8)

typedef uint8_t evr_blob_key_t[evr_blob_key_size];

#define evr_fmt_blob_key_prefix "sha3-224-"
#define evr_fmt_blob_key_prefix_strlen 9

/**
 * evr_fmt_blob_key_size is the size required to store a human
 * readable formatted blob key in a string.
 *
 * The formular consists of: <prefix> <hex key> \0
 */
#define evr_fmt_blob_key_size (evr_fmt_blob_key_prefix_strlen + 2 * evr_blob_key_size + 1)

typedef char evr_fmt_blob_key_t[evr_fmt_blob_key_size];

/**
 * evr_format_blob_key formats key in a human readable way into dest.
 *
 * Formatted keys may look like "sha224-deadbeef".
 *
 * Make sure you have at least evr_fmt_blob_key_size bytes available.
 */
void evr_fmt_blob_key(char *dest, const evr_blob_key_t key);

/**
 * evr_parse_blob_key parses a key in a human readable way from
 * fmt_key.
 */
int evr_parse_blob_key(evr_blob_key_t key, const char *fmt_key);

// TODO change API from size+chunks to evr_chunk_set which now contains size_used
int evr_calc_blob_key(evr_blob_key_t key, size_t size, char **chunks);

#endif
