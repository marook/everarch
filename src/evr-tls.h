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

void evr_tls_init();

void evr_tls_free();

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
 * cert_path must point to your pem file which contains the public SSL
 * certificate.
 *
 * The returned SSL_CTX instance must be freed using SSL_CTX_free.
 */
SSL_CTX *evr_create_ssl_client_ctx(char *cert_path);

void evr_file_bind_ssl(struct evr_file *f, SSL *s);

int evr_tls_accept(struct evr_file *f, int s, SSL_CTX *ssl_ctx);

#endif
