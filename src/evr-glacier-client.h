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
 * evr-glacier-client.h contains functions for reading and writing
 * sockets with commands for the glacier server.
 *
 * The functions for reading and writing commands implement the
 * following naming convention. evr_read_cmd_* and evr_write_cmd_*
 * just read or write the cmd header to the file
 * descriptor. evr_req_cmd_* writes the cmd to the file descriptor and
 * reads the evr_resp_reades after writing. evr_fetch_* writes a cmd
 * and reads the complete response before closing the connection
 * again.
 */

#ifndef __evr_glacier_client_h__
#define __evr_glacier_client_h__

#include "config.h"

#include <libxml/tree.h>

#include "glacier-cmd.h"

int evr_connect_to_storage();

xmlDocPtr evr_fetch_xml(int fd, evr_blob_ref key);

xmlDocPtr evr_fetch_signed_xml(int fd, evr_blob_ref key);

int evr_req_cmd_get_blob(int fd, evr_blob_ref key, struct evr_resp_header *resp);

int evr_write_cmd_get_blob(int fd, evr_blob_ref key);

int evr_req_cmd_watch_blobs(int fd, struct evr_blob_filter *filter);

int evr_write_cmd_watch_blobs(int fd, struct evr_blob_filter *filter);

int evr_read_resp_header(int fd, struct evr_resp_header *resp);

int evr_read_watch_blobs_body(int fd, struct evr_watch_blobs_body *body);

#endif