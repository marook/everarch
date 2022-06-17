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

#include <stdio.h>
#include <string.h>

#include "errors.h"
#include "dyn-mem.h"
#include "logger.h"

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
    gcry_md_hd_t hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto out;
    }
    size_t bytes_remaining = size;
    char **chunks_end = chunks + size / evr_chunk_size + 1;
    for(char **c = chunks; c != chunks_end; c++){
        char *current_chunk = *c;
        size_t current_chunk_size = bytes_remaining < evr_chunk_size ? bytes_remaining : evr_chunk_size;
        gcry_md_write(hd, current_chunk, current_chunk_size);
        bytes_remaining -= current_chunk_size;
    }
    evr_blob_ref_final(key, hd);
    result = evr_ok;
    evr_blob_ref_close(hd);
 out:
    return result;
}

int evr_blob_ref_write_se(void *_hd, char *buf, size_t size){
    evr_blob_ref_hd hd = _hd;
    evr_blob_ref_write(hd, buf, size);
    return evr_ok;
}

void evr_blob_ref_final(evr_blob_ref ref, gcry_md_hd_t hd){
    gcry_md_final(hd);
    unsigned char *digest = gcry_md_read(hd, 0);
    memcpy(ref, digest, evr_blob_ref_size);
}

int evr_blob_ref_hd_match(evr_blob_ref_hd hd, evr_blob_ref expected_ref){
    evr_blob_ref actual_ref;
    evr_blob_ref_final(actual_ref, hd);
    if(memcmp(expected_ref, actual_ref, evr_blob_ref_size) != 0){
        evr_blob_ref_str expected_ref_str;
        evr_fmt_blob_ref(expected_ref_str, expected_ref);
        evr_blob_ref_str actual_ref_str;
        evr_fmt_blob_ref(actual_ref_str, actual_ref);
        log_error("Expected blob ref %s did not match actual blob ref %s calculated from blob's data", expected_ref_str, actual_ref_str);
        return evr_error;
    }
    return evr_ok;
}

void evr_build_claim_ref(evr_claim_ref cref, evr_blob_ref bref, int claim){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, (char*)cref);
    evr_push_n(&bp, bref, evr_blob_ref_size);
    evr_push_map(&bp, &claim, uint16_t, htobe16);
}

void evr_split_claim_ref(evr_blob_ref bref, int *claim, evr_claim_ref cref){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, (char*)cref);
    evr_pull_n(&bp, bref, evr_blob_ref_size);
    evr_pull_map(&bp, claim, uint16_t, be16toh);
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
    int index_ref;
    if(sscanf(s, "%04x", &index_ref) != 1){
        goto out;
    }
    *(uint16_t*)&cref[evr_blob_ref_size] = htobe16(index_ref);
    ret = evr_ok;
 out:
    return ret;
}
