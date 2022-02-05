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
 * evr_cmd_header_t and evr_resp_header_t for the headers. Command and
 * response body types depend on the command type.
 */

#ifndef __evr_glacier_cmd_h__
#define __evr_glacier_cmd_h__

#include "config.h"

#include <stdint.h>
#include <endian.h>

#include "keys.h"

#define evr_cmd_type_get_blob 0x01
#define evr_cmd_type_put_blob 0x02

typedef uint32_t evr_cmd_size_t;
#define evr_cmd_size_to_n htobe32
#define evr_cmd_size_to_h be32toh

typedef struct {
    int type;
    evr_cmd_size_t body_size;
} evr_cmd_header_t;

/**
 * evr_cmd_header_t_n_size defines the serialized size of
 * evr_cmd_header_t in a network buffer.
 */
#define evr_cmd_header_t_n_size (sizeof(uint8_t) + sizeof(evr_cmd_size_t))

int evr_parse_cmd_header(evr_cmd_header_t *header, const char *buffer);
int evr_format_cmd_header(char *buffer, const evr_cmd_header_t *header);

typedef uint8_t evr_status_code_t;

#define evr_status_code_ok 0x20
#define evr_status_code_client_error 0x40
#define evr_status_code_unknown_cmd 0x44
#define evr_status_code_blob_not_found 0x45
#define evr_status_code_server_error 0x50

typedef struct {
    evr_status_code_t status_code;
    evr_cmd_size_t body_size;
} evr_resp_header_t;

/**
 * evr_resp_header_t_n_size defines the serialized size of
 * evr_resp_header_t in a network buffer.
 */
#define evr_resp_header_t_n_size (sizeof(evr_status_code_t) + sizeof(evr_cmd_size_t))

int evr_parse_resp_header(evr_resp_header_t *header, const char *buffer);
int evr_format_resp_header(char *buffer, const evr_resp_header_t *header);

#endif
