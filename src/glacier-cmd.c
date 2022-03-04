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

#include "glacier-cmd.h"

#include "basics.h"
#include "errors.h"

int evr_parse_cmd_header(struct evr_cmd_header *header, char *buffer){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buffer);
    evr_pull_as(&bp, &header->type, uint8_t);
    evr_pull_map(&bp, &header->body_size, uint32_t, be32toh);
    return evr_ok;
}

int evr_format_cmd_header(char *buffer, const struct evr_cmd_header *header){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buffer);
    evr_push_as(&bp, &header->type, uint8_t);
    uint32_t tmp = htobe32(header->body_size);
    evr_push_as(&bp, &tmp, uint32_t);
    return evr_ok;
}

int evr_parse_resp_header(struct evr_resp_header *header, char *buffer){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buffer);
    evr_pull_as(&bp, &header->status_code, uint8_t);
    evr_pull_map(&bp, &header->body_size, uint32_t, be32toh);
    return evr_ok;
}

int evr_format_resp_header(char *buffer, const struct evr_resp_header *header){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buffer);
    evr_push_as(&bp, &header->status_code, uint8_t);
    evr_push_map(&bp, &header->body_size, uint32_t, htobe32);
    return evr_ok;
}

int evr_parse_stat_blob_resp(struct evr_stat_blob_resp *resp, char *buf){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_pull_as(&bp, &resp->flags, uint8_t);
    evr_pull_map(&bp, &resp->blob_size, uint32_t, be32toh);
    return evr_ok;
}

int evr_format_stat_blob_resp(char *buf, const struct evr_stat_blob_resp *resp){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_as(&bp, &resp->flags, uint8_t);
    evr_push_map(&bp, &resp->blob_size, uint32_t, htobe32);
    return evr_ok;
}

int evr_parse_blob_filter(struct evr_blob_filter *f, char *buf){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_pull_as(&bp, &f->flags_filter, uint8_t);
    evr_pull_map(&bp, &f->last_modified_after, uint64_t, be64toh);
    return evr_ok;
}

int evr_format_blob_filter(char *buf, const struct evr_blob_filter *f){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_as(&bp, &f->flags_filter, uint8_t);
    evr_push_map(&bp, &f->last_modified_after, uint64_t, htobe64);
    return evr_ok;
}

int evr_parse_watch_blobs_body(struct evr_watch_blobs_body *body, char *buf){
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_pull_n(&bp, body->key, evr_blob_key_size);
    evr_pull_map(&bp, &body->last_modified, uint64_t, be64toh);
    evr_pull_as(&bp, &body->flags, uint8_t);
    return evr_ok;
}
