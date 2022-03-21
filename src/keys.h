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

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define evr_blob_ref_bit_size 224
#define evr_blob_ref_size (evr_blob_ref_bit_size / 8)
typedef uint8_t evr_blob_ref[evr_blob_ref_size];

#define evr_blob_ref_str_prefix "sha3-224-"
#define evr_blob_ref_str_prefix_len 9

/**
 * evr_blob_ref_str_size is the size required to store a human
 * readable formatted blob key in a string.
 *
 * The formular consists of: <prefix> <hex key> \0
 */
#define evr_blob_ref_str_size (evr_blob_ref_str_prefix_len + 2 * evr_blob_ref_size + 1)
typedef char evr_blob_ref_str[evr_blob_ref_str_size];

/**
 * evr_fmt_blob_ref formats key in a human readable way into dest.
 *
 * Formatted keys may look like "sha224-deadbeef".
 *
 * Make sure you have at least evr_blob_ref_str_size bytes available.
 */
void evr_fmt_blob_ref(char *dest, const evr_blob_ref key);

/**
 * evr_parse_blob_ref parses a key in a human readable way from
 * fmt_key.
 */
int evr_parse_blob_ref(evr_blob_ref key, const char *fmt_key);

// TODO change API from size+chunks to evr_chunk_set which now contains size_used
int evr_calc_blob_ref(evr_blob_ref key, size_t size, char **chunks);

#endif
