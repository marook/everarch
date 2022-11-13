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

#include "auth.h"

#include <string.h>
#include <stdio.h>

#include "errors.h"
#include "basics.h"
#include "logger.h"

int evr_parse_auth_token(evr_auth_token t, evr_auth_token_str s){
    if(strlen(s) != sizeof(evr_auth_token_str) - 1){
        return evr_error;
    }
    char buf[3];
    buf[2] = '\0';
    unsigned int v;
    for(size_t i = 0; i < sizeof(evr_auth_token); ++i){
        buf[0] = s[2 * i];
        buf[1] = s[2 * i + 1];
        if(sscanf(buf, "%02x", &v) != 1){
            return evr_error;
        }
        t[i] = v;
    }
    return evr_ok;
}

void evr_fmt_auth_token(char *s, evr_auth_token t){
    for(size_t i = 0; i < sizeof(evr_auth_token); ++i){
        sprintf(s, "%02x", (unsigned char)t[i]);
        s += 2;
    }
    *s = '\0';
}

int evr_push_auth_token(struct evr_auth_token_cfg **cfg, char *host, char *port, char *token);

int evr_parse_and_push_auth_token(struct evr_auth_token_cfg **cfg, char *token_spec){
    char buf[strlen(token_spec) + 1];
    memcpy(buf, token_spec, sizeof(buf));
    const size_t fragments_len = 3;
    char *fragments[fragments_len];
    if(evr_split_n(fragments, fragments_len, buf, ':') != evr_ok){
        log_debug("Auth-token spec with illegal syntaxt detected: %s", token_spec);
        return evr_error;
    }
    return evr_push_auth_token(cfg, fragments[0], fragments[1], fragments[2]);
}

int evr_push_auth_token(struct evr_auth_token_cfg **cfg, char *host, char *port, char *token_str){
    evr_auth_token token;
    if(evr_parse_auth_token(token, token_str) != evr_ok){
        return evr_error;
    }
    const size_t host_size = strlen(host) + 1;
    const size_t port_size = strlen(port) + 1;
    char *buf = malloc(sizeof(struct evr_auth_token_cfg) + host_size + port_size);
    if(!buf){
        return evr_error;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_auth_token_cfg *new_cfg;
    evr_map_struct(&bp, new_cfg);
    memcpy(new_cfg->token, token, sizeof(evr_auth_token));
    new_cfg->host = bp.pos;
    evr_push_n(&bp, host, host_size);
    new_cfg->port = bp.pos;
    evr_push_n(&bp, port, port_size);
    new_cfg->next = *cfg;
    *cfg = new_cfg;
    return evr_ok;
}

int evr_find_auth_token(struct evr_auth_token_cfg **found, struct evr_auth_token_cfg *chain, char *host, char *port){
    for(; chain; chain = chain->next) {
        if(strcmp(port, chain->port) != 0){
            continue;
        }
        if(strcmp(host, chain->host) != 0){
            continue;
        }
        *found = chain;
        return evr_ok;
    }
    return evr_not_found;
}

void evr_free_auth_token_chain(struct evr_auth_token_cfg *cfg){
    struct evr_auth_token_cfg *c;
    while(cfg){
        c = cfg;
        cfg = cfg->next;
        free(c);
    }
}
