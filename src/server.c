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

#include "server.h"

#include <unistd.h>
#include <netdb.h>
#include <string.h>

#include "logger.h"

int evr_make_tcp_socket(char *host, char *port){
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    struct addrinfo *result;
    int res = getaddrinfo(host, port, &hints, &result);
    if(res != 0){
        log_error("Unable to resolve bind service %s:%s: %s", host, port, gai_strerror(res));
        return -1;
    }
    for(struct addrinfo *p = result; p != NULL; p = p->ai_next){
        int s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s == -1){
            continue;
        }
        int enable = 1;
        if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
            close(s);
            return -1;
        }
        if(bind(s, p->ai_addr, p->ai_addrlen) < 0){
            close(s);
            continue;
        }
        freeaddrinfo(result);
        return s;
    }
    freeaddrinfo(result);
    log_error("Unable to bind to %s:%s", host, port);
    return -1;
}
