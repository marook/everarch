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

#ifndef __basics_h__
#define __basics_h__

#include "config.h"

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) < (b) ? (b) : (a))

#define ceil_div(dividend, divisor) ((dividend + (divisor - 1)) / divisor)

#define evr_glacier_storage_port 2361
#define evr_glacier_attr_index_port 2362

#define evr_max_blob_data_size (16*1024*1024)

/**
 * evr_blob_flag_claim indicates the blob may also be interpreted as
 * claim.
 */
#define evr_blob_flag_claim 0x01

/**
 * evr_blob_flag_index_rule_claim indicates the blob contains at least
 * one claim which defines how an index should interpret claims.
 */
#define evr_blob_flag_index_rule_claim 0x02

/**
 * evr_trim will make start and end point to a whitespace trimmed part
 * of s. end points to the character after the last non whitespace
 * character.
 *
 * On pure whitespace strings start and end will point to the same
 * address.
 */
void evr_trim(char **start, char **end, char *s);

struct evr_buf_pos {
    char *buf;
    char *pos;
};

#define evr_init_buf_pos(bp, buffer)            \
    do {                                        \
        (bp)->buf = (buffer);                   \
        (bp)->pos = (buffer);                   \
    } while(0)

#define evr_reset_buf_pos(bp)                   \
    do {                                        \
        (bp)->pos = (bp)->buf;                  \
    } while(0)

#define evr_malloc_buf_pos(bp, size)            \
    do {                                        \
        (bp)->buf = malloc(size);               \
        (bp)->pos = (bp)->buf;                  \
    } while(0)

#define evr_pull_as(bp, val, type)              \
    do {                                        \
        *(val) = *(type*)((bp)->pos);           \
        (bp)->pos += sizeof(type);              \
    } while(0)

#define evr_pull_n(bp, val, size)               \
    do {                                        \
        memcpy(val, (bp)->pos, size);           \
        (bp)->pos += size;                      \
    } while(0)

#define evr_pull_map(bp, val, type, map)        \
    do {                                        \
        evr_pull_as(bp, val, type);             \
        *(val) = map(*(val));                   \
    } while(0)

#define evr_push_as(bp, val, type)              \
    do {                                        \
        *(type*)((bp)->pos) = *val;             \
        (bp)->pos += sizeof(type);              \
    } while (0)

#define evr_push_n(bp, val, size)               \
    do {                                        \
        memcpy((bp)->pos, val, size);           \
        (bp)->pos += size;                      \
    } while (0)

#define evr_push_concat(bp, s)                  \
    do {                                        \
        size_t len = strlen(s);                 \
        evr_push_n(bp, s, len);                 \
    } while(0)

#define evr_push_eos(bp)                        \
    do {                                        \
        const char eos = '\0';                  \
        evr_push_as(bp, &eos, char);            \
    } while(0)

#define evr_push_map(bp, val, type, map)        \
    do {                                        \
        type tmp = map(*(val));                 \
        evr_push_as(bp, &tmp, type);            \
    } while (0)

#define evr_log_buf_pos(bp)                                             \
    do {                                                                \
        size_t size = (bp)->pos - (bp)->buf;                            \
        char dump[size * 3 + 1];                                        \
        char *s = dump;                                                 \
        for(char *it = (bp)->buf; it != (bp)->pos; ++it){               \
            s += snprintf(s, 4, "%02x ", (unsigned char)*it);           \
        }                                                               \
        if(s != dump){                                                  \
            *(s - 1) = '\0';                                            \
        } else {                                                        \
            *s = '\0';                                                  \
        }                                                               \
        log_debug("struct evr_buf_pos %p with len %lu dump: %s", bp, (bp)->pos - (bp)->buf, dump); \
    } while(0)

#endif
