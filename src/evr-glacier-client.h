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
#include <libxslt/xsltInternals.h>

#include "glacier-cmd.h"
#include "files.h"
#include "auth.h"
#include "signatures.h"

int evr_write_auth_token(struct evr_file *f, evr_auth_token t);

int evr_fetch_xml(xmlDocPtr *doc, struct evr_file *f, evr_blob_ref key);

int evr_fetch_signed_xml(xmlDocPtr *doc, struct evr_verify_ctx *ctx, struct evr_file *f, evr_blob_ref key, struct evr_file *meta);

int evr_fetch_stylesheet(xsltStylesheetPtr *style, struct evr_file *f, evr_blob_ref ref);

/**
 * evr_stat_and_put checks if the given key exists and puts it if
 * not. Check and put are not one atomic operation.
 *
 * Returns evr_ok if blob did not exist and was put into
 * storage. Returns evr_exists if stat indicated that the blob already
 * exists.
 */
int evr_stat_and_put(struct evr_file *c, evr_blob_ref key, int flags, struct chunk_set *blob);

int evr_req_cmd_stat_blob(struct evr_file *f, evr_blob_ref key, struct evr_resp_header *resp);

int evr_write_cmd_stat_blob(struct evr_file *f, evr_blob_ref key);

int evr_req_cmd_get_blob(struct evr_file *f, evr_blob_ref key, struct evr_resp_header *resp);

int evr_write_cmd_get_blob(struct evr_file *f, evr_blob_ref key);

int evr_read_cmd_get_resp_blob(char **blob, struct evr_file *c, size_t resp_body_size, evr_blob_ref expected_ref);

int evr_pipe_cmd_get_resp_blob(struct evr_file *dst, struct evr_file *src, size_t resp_body_size, evr_blob_ref expected_ref);

int evr_write_cmd_put_blob(struct evr_file *f, evr_blob_ref key, int flags, size_t blob_size);

int evr_req_cmd_watch_blobs(struct evr_file *f, struct evr_blob_filter *filter);

int evr_write_cmd_watch_blobs(struct evr_file *f, struct evr_blob_filter *filter);

int evr_read_resp_header(struct evr_file *f, struct evr_resp_header *resp);

int evr_read_watch_blobs_body(struct evr_file *f, struct evr_watch_blobs_body *body);

#endif
