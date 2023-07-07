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

#ifndef auth_h
#define auth_h

#include "config.h"

#define evr_auth_type_token 1

typedef char evr_auth_token[32];
typedef char evr_auth_token_str[2 * sizeof(evr_auth_token) + 1];

int evr_parse_auth_token(evr_auth_token t, char *s);

void evr_fmt_auth_token(char *s, evr_auth_token t);

struct evr_auth_token_cfg {
    char *host;
    char *port;
    evr_auth_token token;
    struct evr_auth_token_cfg *next;
};

int evr_parse_and_push_auth_token(struct evr_auth_token_cfg **cfg, char *token_spec);

/**
 * evr_find_auth_token returns evr_not_found if no matching token was
 * found.
 */
int evr_find_auth_token(struct evr_auth_token_cfg **found, struct evr_auth_token_cfg *chain, char *host, char *port);

void evr_free_auth_token_chain(struct evr_auth_token_cfg *cfg);

#endif
