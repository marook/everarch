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
 * glacier-cmd.h defines the network protocol used to send commands to
 * a glacier server via a stream.
 *
 * Client sends a command to the server and retrieves back a response
 * from the server.
 *
 * Commands and responses consist of a header and a body. See
 * struct evr_cmd_header and struct evr_resp_header for the headers. Command and
 * response body types depend on the command type.
 */

#ifndef __evr_glacier_cmd_h__
#define __evr_glacier_cmd_h__

#include "config.h"

#include <stdint.h>
#include <endian.h>

#include "keys.h"

/**
 * evr_cmd_type_get_blob asks for a blob with a certain key.
 *
 * Expected cmd body is: <none>
 *
 * Expected response body is:
 * - uint8_t flags
 * - char *blob
 */
#define evr_cmd_type_get_blob 0x01

/**
 * evr_cmd_type_put_blob submits a blob with a certain key.
 *
 * Expected cmd body is:
 * - uint8_t flags
 * - evr_blob_key key
 * - char *blob
 *
 * Expected response body is: <none>
 */
#define evr_cmd_type_put_blob 0x02

/**
 * evr_cmd_type_stat_blob asks for metadata about a blob with a
 * certain key.
 *
 * Expected cmd body is:
 * - evr_blob_key key
 *
 * Expected response body is:
 * - struct evr_stat_blob_resp
 */
#define evr_cmd_type_stat_blob 0x03

/**
 * evr_cmd_type_watch_blobs requests notifications about created and
 * modified blobs.
 *
 * Expected cmd body is:
 * - uint8_t flags_filter
 * - uint64_t last_modified_after
 *
 * Expected response body is:
 * - struct evr_stat_blob_resp with body_size 0
 * - evr_blob_key_t key + uint64_t last_modified of modified blob in an
 *   endless stream
 */
#define evr_cmd_type_watch_blobs 0x04

struct evr_cmd_header {
    int type;
    size_t body_size;
};

/**
 * evr_cmd_header_n_size defines the serialized size of
 * struct evr_cmd_header in a network buffer.
 */
#define evr_cmd_header_n_size (sizeof(uint8_t) + sizeof(uint32_t))

int evr_parse_cmd_header(struct evr_cmd_header *header, char *buffer);
int evr_format_cmd_header(char *buffer, const struct evr_cmd_header *header);

#define evr_status_code_ok 0x20
#define evr_status_code_client_error 0x40
#define evr_status_code_unknown_cmd 0x44
#define evr_status_code_blob_not_found 0x45
#define evr_status_code_server_error 0x50

struct evr_resp_header {
    int status_code;
    size_t body_size;
};

/**
 * evr_resp_header_n_size defines the serialized size of
 * struct evr_resp_header in a network buffer.
 */
#define evr_resp_header_n_size (sizeof(uint8_t) + sizeof(uint32_t))

int evr_parse_resp_header(struct evr_resp_header *header, char *buffer);
int evr_format_resp_header(char *buffer, const struct evr_resp_header *header);

struct evr_stat_blob_resp {
    int flags;
    size_t blob_size;
};

#define evr_stat_blob_resp_n_size (sizeof(uint8_t) + sizeof(uint32_t))

int evr_parse_stat_blob_resp(struct evr_stat_blob_resp *resp, char *buf);
int evr_format_stat_blob_resp(char *buf, const struct evr_stat_blob_resp *resp);

struct evr_blob_filter {
    /**
     * flags_filter is a set of bits which must be set at least so
     * that the blob is passed by the filter.
     */
    int flags_filter;

    /**
     * last_modified_after is the unix epoch timestamp in seconds
     * after which a blob must have been modified in order to be
     * passed by the filter.
     *
     * Future last_modified_after values will not report any
     * modifications already persisted into the glacier storage. But
     * live modifications on blobs will be reported even if they lie
     * behind last_modified_after.
     */
    unsigned long long last_modified_after;
};

#define evr_blob_filter_n_size (sizeof(uint8_t) + sizeof(uint64_t))

int evr_parse_blob_filter(struct evr_blob_filter *f, char *buf);
int evr_format_blob_filter(char *buf, const struct evr_blob_filter *f);

#endif
