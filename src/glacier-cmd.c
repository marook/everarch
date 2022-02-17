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

#include "errors.h"

#define pull_p(type)                       \
    *(type*)p;                             \
    p = (char*)&((type*)p)[1];

#define pull_p_map(type, map)                   \
    map(*(type*)p);                             \
    p = (char*)&((type*)p)[1];

#define push_p(type, target)                    \
    *(type*)p = target;                         \
    p = (char*)&((type*)p)[1];

int evr_parse_cmd_header(struct evr_cmd_header *header, const char *buffer){
    const char *p = buffer;
    header->type = pull_p(uint8_t);
    header->body_size = pull_p_map(uint32_t, be32toh);
    return evr_ok;
}

int evr_format_cmd_header(char *buffer, const struct evr_cmd_header *header){
    char *p = buffer;
    push_p(uint8_t, header->type);
    push_p(uint32_t, htobe32(header->body_size));
    return evr_ok;
}

int evr_parse_resp_header(struct evr_resp_header *header, const char *buffer){
    const char *p = buffer;
    header->status_code = pull_p(uint8_t);
    header->body_size = pull_p_map(uint32_t, be32toh);
    return evr_ok;
}

int evr_format_resp_header(char *buffer, const struct evr_resp_header *header){
    char *p = buffer;
    push_p(uint8_t, header->status_code);
    push_p(uint32_t, htobe32(header->body_size));
    return evr_ok;
}

int evr_parse_stat_blob_resp(struct evr_stat_blob_resp *resp, const char *buf){
    const char *p = buf;
    resp->flags = pull_p(uint8_t);
    resp->blob_size = pull_p_map(uint32_t, be32toh);
    return evr_ok;
}

int evr_format_stat_blob_resp(char *buf, const struct evr_stat_blob_resp *resp){
    char *p = buf;
    push_p(uint8_t, resp->flags);
    push_p(uint32_t, resp->blob_size);
    return evr_ok;
}

int evr_parse_blob_filter(struct evr_blob_filter *f, const char *buf){
    const char *p = buf;
    f->flags_filter = pull_p(uint8_t);
    f->last_modified_after = pull_p_map(uint64_t, be64toh);
    return evr_ok;
}

int evr_format_blob_filter(char *buf, const struct evr_blob_filter *f){
    char *p = buf;
    push_p(uint8_t, f->flags_filter);
    push_p(uint64_t, htobe64(f->last_modified_after));
    return evr_ok;
}
