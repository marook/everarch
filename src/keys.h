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

/*
 * keys.h defines types for referencing blobs or claims together with
 * str formatting and parsing functions.
 *
 * The type evr_blob_ref is a reference to one blob.
 *
 * The type evr_claim_ref is a reference to one claim within a claim
 * set within one blob.
 */

#ifndef __evr_keys_h__
#define __evr_keys_h__

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <gcrypt.h>

#define evr_blob_ref_bit_size 224
#define evr_blob_ref_size (evr_blob_ref_bit_size / 8)
typedef uint8_t evr_blob_ref[evr_blob_ref_size];
#define evr_claim_ref_size (evr_blob_ref_size + sizeof(uint16_t))
typedef uint8_t evr_claim_ref[evr_claim_ref_size];

#define evr_blob_ref_str_prefix "sha3-224-"
#define evr_blob_ref_str_prefix_len 9
#define evr_claim_ref_str_separator "-"
#define evr_claim_ref_str_separator_len 1

/**
 * evr_blob_ref_str_size is the size required to store a human
 * readable formatted blob key in a string.
 *
 * The formular consists of: <prefix> <hex key> \0
 */
#define evr_blob_ref_str_size (evr_blob_ref_str_prefix_len + 2 * evr_blob_ref_size + 1)
typedef char evr_blob_ref_str[evr_blob_ref_str_size];
#define evr_claim_ref_str_size (evr_blob_ref_str_size + evr_claim_ref_str_separator_len + 4)
typedef char evr_claim_ref_str[evr_claim_ref_str_size];

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

/**
 * evr_blob_ref_hd is always a pointer to something.
 */
typedef gcry_md_hd_t evr_blob_ref_hd;

// TODO rename to evr_open_blob_ref_hd
#define evr_blob_ref_open(hd) \
    ((gcry_md_open(hd, GCRY_MD_SHA3_224, 0) != GPG_ERR_NO_ERROR) ? evr_error : evr_ok)

// TODO rename to evr_write_blob_ref_hd
#define evr_blob_ref_write gcry_md_write

// TODO rename to evr_write_se_blob_ref_hd
int evr_blob_ref_write_se(void *hd, char *buf, size_t size);

// TODO rename to evr_finalize_blob_ref_hd
/**
 * evr_blob_ref_final finalizes the hash digest and writes the hash
 * into ref.
 */
void evr_blob_ref_final(evr_blob_ref ref, evr_blob_ref_hd hd);

// TODO rename to evr_match_blob_ref_hd
int evr_blob_ref_hd_match(evr_blob_ref_hd hd, evr_blob_ref expected_ref);

// TODO rename to evr_close_blob_ref_hd
#define evr_blob_ref_close gcry_md_close

void evr_build_claim_ref(evr_claim_ref cref, evr_blob_ref bref, int claim);

void evr_split_claim_ref(evr_blob_ref bref, int *claim, evr_claim_ref cref);

void evr_fmt_claim_ref(char *dest, const evr_claim_ref cref);

int evr_parse_claim_ref(evr_claim_ref cref, const char *fmt_ref);

#endif
