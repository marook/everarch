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

#include <stdio.h>
#include <string.h>

#include "errors.h"
#include "keys.h"

const evr_hash_algorithm_t evr_hash_algorithm_sha224 = 1;

const char *evr_hash_algorithm_sha224_prefix = "sha224-";
#define evr_hash_algorithm_sha224_prefix_len strlen(evr_hash_algorithm_sha224_prefix)
#define evr_hash_algorithm_sha224_fmt_len evr_hash_algorithm_sha224_prefix_len + 2 * 224 / 8 + 1

size_t evr_fmt_key_size(const evr_blob_key_t *key){
    if(key->type == evr_hash_algorithm_sha224){
        return evr_hash_algorithm_sha224_fmt_len;
    } else {
        return 0;
    }
}

int evr_fmt_key(char *dest, size_t max_size, const evr_blob_key_t *key) {
    if(key->type == evr_hash_algorithm_sha224){
        if(max_size < evr_hash_algorithm_sha224_fmt_len || key->key_len != 224 / 8){
            return evr_error;
        }
        char *p = dest;
        memcpy(p, evr_hash_algorithm_sha224_prefix, evr_hash_algorithm_sha224_prefix_len);
        p += evr_hash_algorithm_sha224_prefix_len;
        uint8_t *end = &(key->key[28]);
        for(uint8_t *k = key->key; k != end; k++){
            sprintf(p, "%02x", *k);
            p += 2;
        }
        *p++ = '\0';
        return evr_ok;
    } else {
        return evr_error;
    }
}
