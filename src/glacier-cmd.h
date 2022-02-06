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

#define evr_cmd_type_get_blob 0x01
#define evr_cmd_type_put_blob 0x02

struct evr_cmd_header {
    int type;
    size_t body_size;
};

/**
 * evr_cmd_header_n_size defines the serialized size of
 * struct evr_cmd_header in a network buffer.
 */
#define evr_cmd_header_n_size (sizeof(uint8_t) + sizeof(uint32_t))

int evr_parse_cmd_header(struct evr_cmd_header *header, const char *buffer);
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

int evr_parse_resp_header(struct evr_resp_header *header, const char *buffer);
int evr_format_resp_header(char *buffer, const struct evr_resp_header *header);

#endif
