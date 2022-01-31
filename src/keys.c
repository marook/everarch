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

#include "keys.h"

#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

#include "errors.h"

void evr_fmt_blob_key(char *dest, const evr_blob_key_t key) {
    char *p = dest;
    size_t prefix_len = strlen(evr_fmt_blob_key_prefix);
    memcpy(p, evr_fmt_blob_key_prefix, prefix_len);
    p += prefix_len;
    const uint8_t *end = &key[evr_blob_key_size];
    for(const uint8_t *k = key; k != end; k++){
        sprintf(p, "%02x", *k);
        p += 2;
    }
    *p++ = '\0';
}

int evr_calc_blob_key(evr_blob_key_t key, size_t size, const uint8_t **chunks){
    int result = evr_error;
    gcry_md_hd_t hash_ctx;
    if(gcry_md_open(&hash_ctx, GCRY_MD_SHA3_224, 0) != GPG_ERR_NO_ERROR){
        goto md_open_fail;
    }
    size_t bytes_remaining = size;
    const uint8_t **chunks_end = chunks + size / evr_chunk_size + 1;
    for(const uint8_t **c = chunks; c != chunks_end; c++){
        const uint8_t *current_chunk = *c;
        size_t current_chunk_size = bytes_remaining < evr_chunk_size ? bytes_remaining : evr_chunk_size;
        gcry_md_write(hash_ctx, current_chunk, current_chunk_size);
        bytes_remaining -= current_chunk_size;
    }
    gcry_md_final(hash_ctx);
    unsigned char *digest = gcry_md_read(hash_ctx, 0);
    memcpy(key, digest, evr_blob_key_size);
    result = evr_ok;
    gcry_md_close(hash_ctx);
 md_open_fail:
    return result;
    
}
