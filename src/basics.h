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

#include <stdint.h>
#include <time.h>
#include <string.h>

/**
 * evr_page_size contains sysconf(_SC_PAGESIZE) or 4096 if no page
 * size can be determined.
 */
extern size_t evr_page_size;

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) < (b) ? (b) : (a))

#define ceil_div(dividend, divisor) ((dividend + (divisor - 1)) / divisor)

/*
 * in order to convert the numeric value of a define into a string
 * call to_string(n). _stringify(n) is just a helper function.
 */
#define _stringify(n) #n
#define to_string(n) _stringify(n)

#define evr_replace_str(s, arg)                 \
    do {                                        \
        if(s) {                                 \
            free(s);                            \
        }                                       \
        s = strdup(arg);                        \
    } while(0)

void evr_init_basics();

#define evr_glacier_storage_host "localhost"
#define evr_glacier_storage_port 2361
#define default_storage_ssl_cert_path EVR_PREFIX "/etc/everarch/evr-glacier-storage-cert.pem"

#define evr_attr_index_host "localhost"
#define evr_attr_index_port 2362
#define default_index_ssl_cert_path EVR_PREFIX "/etc/everarch/evr-attr-index-cert.pem"

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

#define evr_inc_buf_pos(bp, size)               \
    do {                                        \
        (bp)->pos += size;                      \
    } while(0)

#define evr_map_struct(bp, struct_ptr)                  \
    do {                                                \
        size_t size = sizeof(typeof(*struct_ptr));      \
        struct_ptr = (typeof(struct_ptr))(bp)->pos;     \
        evr_inc_buf_pos(bp, size);                      \
    } while(0)

#define evr_pull_as(bp, val, type)              \
    do {                                        \
        *(val) = *(type*)((bp)->pos);           \
        evr_inc_buf_pos(bp, sizeof(type));      \
    } while(0)

#define evr_pull_n(bp, val, size)               \
    do {                                        \
        memcpy(val, (bp)->pos, size);           \
        evr_inc_buf_pos(bp, size);              \
    } while(0)

#define evr_pull_map(bp, val, type, map)        \
    do {                                        \
        evr_pull_as(bp, val, type);             \
        *(val) = map(*(val));                   \
    } while(0)

#define evr_push_as(bp, val, type)              \
    do {                                        \
        *(type*)((bp)->pos) = *val;             \
        evr_inc_buf_pos(bp, sizeof(type));      \
    } while (0)

#define evr_push_n(bp, val, size)               \
    do {                                        \
        memcpy((bp)->pos, val, size);           \
        evr_inc_buf_pos(bp, size);              \
    } while (0)

#define evr_push_concat(bp, s)                  \
    do {                                        \
        const char *_s = s;                     \
        size_t len = strlen(_s);                \
        evr_push_n(bp, _s, len);                \
    } while(0)

#define evr_forward_to_eos(bp) \
    for(; *((bp)->pos); ++(bp)->pos){}

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

/**
 * Pushes a checksum for the data before the checksum.
 */
void evr_push_8bit_checksum(struct evr_buf_pos *bp);

/**
 * Returns evr_ok if the checksum for the data before the checksum
 * matches.
 */
int evr_pull_8bit_checksum(struct evr_buf_pos *bp);

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

/**
 * evr_time is the everarch time representation.
 *
 * You can assume the following:
 * - bigger values are later in time
 * - comparision operators =, < and > work
 */
typedef uint64_t evr_time;

#define evr_time_fmt "%lu"

void evr_now(evr_time *t);

#define evr_time_from_timespec(t, ts)                                   \
    do {                                                                \
        *(t) = ((evr_time)(ts)->tv_sec) * 1000 + (ts)->tv_nsec / 1000000; \
    } while(0)

#define evr_time_to_timespec(ts, t)                     \
    do {                                                \
        (ts)->tv_sec = *(t) / 1000;                     \
        (ts)->tv_nsec = (*(t) % 1000) * 1000000;        \
    } while(0)

/**
 * evr_max_time_iso8601_size is the maximum size of an ISO 8601
 * formatted string in bytes including \0 termination.
 */
#define evr_max_time_iso8601_size 30

// TODO allow further parse variants for dates here like "2021" or "-3d"
#define evr_time_from_anything(t, s) evr_time_from_iso8601(t, s)

int evr_time_from_iso8601(evr_time *t, const char *s);

void evr_time_to_iso8601(char *s, size_t sn, const evr_time *t);

#define evr_time_add_ms(t, ms)                  \
    do {                                        \
        *(t) += ms;                             \
    } while(0)

#endif

/**
 * evr_split_n will separate s into fragments by replacing sep in s
 * with '\0' and return pointers to each fragment.
 */
int evr_split_n(char **fragments, size_t fragments_len, char *s, char sep);

int evr_strpcmp(char **l, char **r);

#define evr_program_config_paths() {                       \
        program_name ".conf",                              \
        "~/.config/everarch/" program_name ".conf",        \
        EVR_PREFIX "/etc/everarch/" program_name ".conf",  \
        "/etc/everarch/" program_name ".conf",             \
        NULL,                                              \
}
