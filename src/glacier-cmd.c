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

int evr_parse_cmd_header(evr_cmd_header_t *header, const char *buffer){
    const char *p = buffer;
    header->type = *(evr_cmd_type_t*)p;
    p = (char*)&((evr_cmd_type_t*)p)[1];
    header->body_size = evr_cmd_size_to_h(*(evr_cmd_size_t*)p);
    return evr_ok;
}

int evr_format_cmd_header(char *buffer, const evr_cmd_header_t *header){
    char *p = buffer;
    *(evr_cmd_type_t*)p = header->type;
    p = (char*)&((evr_cmd_type_t*)p)[1];
    *(evr_cmd_size_t*)p = evr_cmd_size_to_n(header->body_size);
    return evr_ok;
}

int evr_parse_resp_header(evr_resp_header_t *header, const char *buffer){
    const char *p = buffer;
    header->status_code = *(evr_status_code_t*)p;
    p = (char*)&((evr_status_code_t*)p)[1];
    header->body_size = evr_cmd_size_to_h(*(evr_cmd_size_t*)p);
    return evr_ok;
}

int evr_format_resp_header(char *buffer, const evr_resp_header_t *header){
    char *p = buffer;
    *(evr_status_code_t*)p = header->status_code;
    p = (char*)&((evr_status_code_t*)p)[1];
    *(evr_cmd_size_t*)p = evr_cmd_size_to_n(header->body_size);
    return evr_ok;
}
