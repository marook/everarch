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
#include "dyn-mem.h"

void evr_fmt_blob_ref(char *dest, const evr_blob_ref key) {
    char *p = dest;
    size_t prefix_len = strlen(evr_blob_ref_str_prefix);
    memcpy(p, evr_blob_ref_str_prefix, prefix_len);
    p += prefix_len;
    const uint8_t *end = &key[evr_blob_ref_size];
    for(const uint8_t *k = key; k != end; k++){
        sprintf(p, "%02x", *k);
        p += 2;
    }
    *p++ = '\0';
}

int evr_parse_blob_ref(evr_blob_ref key, const char *fmt_key){
    const char *p = fmt_key;
    if(strncmp(evr_blob_ref_str_prefix, fmt_key, strlen(evr_blob_ref_str_prefix)) != 0){
        return evr_error;
    }
    p += strlen(evr_blob_ref_str_prefix);
    size_t hash_len = strlen(p);
    if(hash_len != 2 * evr_blob_ref_size){
        return evr_error;
    }
    char buffer[3];
    buffer[2] = '\0';
    int v;
    for(int i = 0; i < evr_blob_ref_size; ++i){
        buffer[0] = p[0];
        buffer[1] = p[1];
        if(sscanf(buffer, "%02x", &v) != 1){
            return evr_error;
        }
        if(v < 0 || v > 255){
            return evr_error;
        }
        key[i] = v;
        p += 2;
    }
    return evr_ok;
}

int evr_calc_blob_ref(evr_blob_ref key, size_t size, char **chunks){
    int result = evr_error;
    gcry_md_hd_t hash_ctx;
    if(gcry_md_open(&hash_ctx, GCRY_MD_SHA3_224, 0) != GPG_ERR_NO_ERROR){
        goto md_open_fail;
    }
    size_t bytes_remaining = size;
    char **chunks_end = chunks + size / evr_chunk_size + 1;
    for(char **c = chunks; c != chunks_end; c++){
        char *current_chunk = *c;
        size_t current_chunk_size = bytes_remaining < evr_chunk_size ? bytes_remaining : evr_chunk_size;
        gcry_md_write(hash_ctx, current_chunk, current_chunk_size);
        bytes_remaining -= current_chunk_size;
    }
    gcry_md_final(hash_ctx);
    unsigned char *digest = gcry_md_read(hash_ctx, 0);
    memcpy(key, digest, evr_blob_ref_size);
    result = evr_ok;
    gcry_md_close(hash_ctx);
 md_open_fail:
    return result;
    
}

void evr_build_claim_ref(evr_claim_ref cref, evr_blob_ref bref, int claim){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, (char*)cref);
    evr_push_n(&bp, bref, evr_blob_ref_size);
    evr_push_map(&bp, &claim, uint16_t, htobe16);
}

void evr_fmt_claim_ref(char *dest, const evr_claim_ref cref){
    evr_fmt_blob_ref(dest, cref);
    int claim = be16toh(*(uint16_t*)&cref[evr_blob_ref_size]);
    char *s = &dest[evr_blob_ref_str_size - 1];
    sprintf(s, evr_claim_ref_str_separator "%04x", claim);
}

int evr_parse_claim_ref(evr_claim_ref cref, const char *fmt_ref){
    int ret = evr_error;
    if(strlen(fmt_ref) != evr_claim_ref_str_size - 1){
        goto out;
    }
    evr_blob_ref_str bref_str;
    memcpy(bref_str, fmt_ref, evr_blob_ref_str_size - 1);
    bref_str[evr_blob_ref_str_size - 1] = '\0';
    evr_parse_blob_ref(cref, bref_str);
    const char *s = &fmt_ref[evr_blob_ref_str_size - 1];
    if(strncmp(evr_claim_ref_str_separator, s, evr_claim_ref_str_separator_len) != 0){
        goto out;
    }
    s += evr_claim_ref_str_separator_len;
    int claim_index;
    if(sscanf(s, "%04x", &claim_index) != 1){
        goto out;
    }
    *(uint16_t*)&cref[evr_blob_ref_size] = htobe16(claim_index);
    ret = evr_ok;
 out:
    return ret;
}
