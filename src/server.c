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

static struct addrinfo hints_init = { 0 };

int evr_make_tcp_socket(char *host, char *port){
    struct addrinfo hints;
    hints = hints_init;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
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
#ifdef EVR_LOG_DEBUG
    char num_addr[128];
    char num_port[16];
    for(struct addrinfo *p = result; p != NULL; p = p->ai_next){
        if(getnameinfo(p->ai_addr, p->ai_addrlen, num_addr, sizeof(num_addr), num_port, sizeof(num_port), NI_NUMERICHOST | NI_NUMERICSERV) != 0){
            evr_panic("Unable to format numeric address for %s", host);
            freeaddrinfo(result);
            return -1;
        }
        log_debug("Potential address %s with port %s for server detected", num_addr, num_port);
    }
#endif
    for(struct addrinfo *p = result; p != NULL; p = p->ai_next){
#ifdef EVR_LOG_DEBUG
        if(getnameinfo(p->ai_addr, p->ai_addrlen, num_addr, sizeof(num_addr), num_port, sizeof(num_port), NI_NUMERICHOST | NI_NUMERICSERV) != 0){
            evr_panic("Unable to format numeric address for %s", host);
            freeaddrinfo(result);
            return -1;
        }
        log_debug("Try taking address %s with port %s for server", num_addr, num_port);
#endif
        int s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s == -1){
            continue;
        }
        if(p->ai_family == AF_INET6){
            log_debug("Make the IPv6 a dual-stack socket which also binds to IPv4.");
            int mode = 0;
            if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &mode, sizeof(mode)) != 0){
                goto fail_with_free_addrinfo;
            }
        }
        int enable = 1;
        if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
            goto fail_with_free_addrinfo;
        }
        if(bind(s, p->ai_addr, p->ai_addrlen) < 0){
            close(s);
            continue;
        }
        freeaddrinfo(result);
        return s;
    fail_with_free_addrinfo:
        close(s);
        freeaddrinfo(result);
        return -1;
    }
    freeaddrinfo(result);
    log_error("Unable to bind to %s:%s", host, port);
    return -1;
}
