/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
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

#ifndef httpd_h
#define httpd_h

#include "config.h"

#include <microhttpd.h>

#include "auth.h"

int evr_httpd_check_authentication(struct MHD_Connection *c, evr_auth_token auth_token);

enum MHD_Result evr_httpd_respond_static_msg(struct MHD_Connection *c, unsigned int status_code, const char *msg, const char *server_name);

int evr_add_std_http_headers(struct MHD_Response *resp, const char *server_name, const char *content_type);

#endif
