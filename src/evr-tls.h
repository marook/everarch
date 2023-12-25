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

#ifndef evr_tls_h
#define evr_tls_h

#include "config.h"

#include <openssl/ssl.h>

#include "files.h"

void evr_tls_init(void);

void evr_tls_free(void);

struct evr_cert_cfg {
    char *host;
    char *port;
    char *cert_path;
    struct evr_cert_cfg *next;
};

/**
 * evr_parse_and_push_cert adds a struct evr_cert_cfg to cfg just like
 * evr_push_cert. The config is parsed from cert_spec which must have
 * the form HOST:PORT:CERT_FILE.
 */
int evr_parse_and_push_cert(struct evr_cert_cfg **cfg, char *cert_spec);

int evr_push_cert(struct evr_cert_cfg **cfg, char *host, char *port, char *cert_path);

/**
 * evr_find_cert returns evr_not_found if no matching cert was found.
 */
int evr_find_cert(struct evr_cert_cfg **found, struct evr_cert_cfg *chain, char *host, char *port);

void evr_free_cert_chain(struct evr_cert_cfg *cfg);

/**
 * evr_create_ssl_server_ctx creates an SSL_CTX with everarch defaults
 * applied.
 *
 * cert_path must point to your pem file which contains the public SSL
 * certificate.
 *
 * key_path must point to your pem file which contains the private SSL
 * key.
 *
 * The returned SSL_CTX instance must be freed using SSL_CTX_free.
 */
SSL_CTX *evr_create_ssl_server_ctx(char *cert_path, char *key_path);

/**
 * evr_create_ssl_client_ctx creates an SSL_CTX with everarch defaults
 * applied.
 *
 * The returned SSL_CTX instance must be freed using SSL_CTX_free.
 */
SSL_CTX *evr_create_ssl_client_ctx(char *host, char *port, struct evr_cert_cfg *cert_cfg);

int evr_tls_accept(struct evr_file *f, int s, SSL_CTX *ssl_ctx);

/**
 * evr_tls_connect_once does the same thing as
 * evr_tls_connect. evr_tls_connect_once just creates a new SSL_CTX
 * with every call for one shot convenience. You must use
 * evr_tls_connect if you need more than one connection to the same
 * server.
 */
int evr_tls_connect_once(struct evr_file *f, char *host, char *port, struct evr_cert_cfg *cert_cfg);

int evr_tls_connect(struct evr_file *f, char *host, char *port, SSL_CTX *ssl_ctx);

#endif
