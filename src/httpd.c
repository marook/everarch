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

#include "httpd.h"

#include <string.h>

#include "errors.h"
#include "logger.h"

static enum MHD_Result evr_httpd_authentication_header_it(void *ctx, enum MHD_ValueKind kind, const char *key, const char *value);

struct evr_httpd_check_auth_ctx {
    evr_auth_token auth_token;
    int res;
};

int evr_httpd_check_authentication(struct MHD_Connection *c, evr_auth_token auth_token){
    struct evr_httpd_check_auth_ctx ctx = { 0 };
    memcpy(ctx.auth_token, auth_token, sizeof(evr_auth_token));
    ctx.res = evr_user_data_invalid;
    MHD_get_connection_values(c, MHD_HEADER_KIND, evr_httpd_authentication_header_it, &ctx);
    return ctx.res;
}

// the 'AT' stands for authentication token. it defines the type of
// token. this way we can add different kinds of tokens in the future.
static const char evr_httpd_bearer[] = "Bearer AT";

static enum MHD_Result evr_httpd_authentication_header_it(void *_ctx, enum MHD_ValueKind kind, const char *key, const char *value){
    const char *token_str;
    evr_auth_token token;
    struct evr_httpd_check_auth_ctx *ctx = _ctx;
    if(strcmp(key, "Authorization") != 0){
        return MHD_YES;
    }
    if(strncmp(value, evr_httpd_bearer, sizeof(evr_httpd_bearer) - 1) != 0){
        log_debug("Retrieved http authorization header without bearer prefix: %s", value);
        return MHD_YES;
    }
    token_str = &value[sizeof(evr_httpd_bearer) - 1];
    if(evr_parse_auth_token(token, token_str) != evr_ok){
        log_debug("Retrieved syntactically invalid http authorization token: %s", token_str);
        return MHD_YES;
    }
    if(memcmp(ctx->auth_token, token, sizeof(evr_auth_token)) != 0){
        log_error("Invalid auth token provided to http server");
        return MHD_YES;
    }
    ctx->res = evr_ok;
    return MHD_NO;
}

enum MHD_Result evr_httpd_respond_static_msg(struct MHD_Connection *c, unsigned int status_code, const char *msg, const char *server_name){
    enum MHD_Result ret;
    struct MHD_Response *resp;
    size_t msg_len;
    msg_len = strlen(msg);
    resp = MHD_create_response_from_buffer(msg_len, (void*)msg, MHD_RESPMEM_PERSISTENT);
    if(evr_add_std_http_headers(resp, server_name, "text/plain") != evr_ok){
        evr_panic("Unable to add standard http headers");
    }
    ret = MHD_queue_response(c, status_code, resp);
    MHD_destroy_response(resp);
    return ret;
}

int evr_add_std_http_headers(struct MHD_Response *resp, const char *server_name, const char *content_type){
    if(MHD_add_response_header(resp, "Server", server_name) != MHD_YES){
        return evr_error;
    }
    if(content_type && MHD_add_response_header(resp, "Content-Type", content_type) != MHD_YES){
        return evr_error;
    }
    return evr_ok;
}
