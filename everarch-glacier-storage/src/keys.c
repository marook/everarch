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

#include "keys.h"

const char *evr_fmt_blob_key_prefix = "sha224-";

void evr_fmt_blob_key(char *dest, const evr_blob_key_t key) {
    char *p = dest;
    memcpy(p, evr_fmt_blob_key_prefix, evr_fmt_blob_key_prefix_len);
    p += evr_fmt_blob_key_prefix_len;
    const uint8_t *end = &key[evr_blob_key_size];
    for(const uint8_t *k = key; k != end; k++){
        sprintf(p, "%02x", *k);
        p += 2;
    }
    *p++ = '\0';
}
