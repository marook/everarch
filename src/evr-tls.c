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

#include "evr-tls.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/err.h>

#include "logger.h"
#include "errors.h"

void evr_tls_log_ssl_errors(struct evr_file *f, char *log_level);

#define evr_tls_log_global_ssl_errors(log_level)        \
    do {                                                \
        struct evr_file f;                              \
        evr_file_bind_fd(&f, -1);                       \
        evr_tls_log_ssl_errors(&f, log_level);          \
    } while(0)

void evr_tls_init(){
    SSL_load_error_strings();
}

void evr_tls_free(){
    ERR_free_strings();
}

SSL_CTX *evr_create_ssl_ctx();

SSL_CTX *evr_create_ssl_server_ctx(char *cert_path, char *key_path){
    SSL_CTX *ctx = evr_create_ssl_ctx();
    if(!ctx){
        return NULL;
    }
    if(SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        log_error("Unable to use SSL certificate file %s", cert_path);
        evr_tls_log_global_ssl_errors(evr_log_level_error);
        goto out_with_free_ctx;
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        log_error("Unable to use SSL certificate key %s", cert_path);
        evr_tls_log_global_ssl_errors(evr_log_level_error);
        goto out_with_free_ctx;
    }
    return ctx;
 out_with_free_ctx:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL_CTX *evr_create_ssl_client_ctx(char *cert_path){
    SSL_CTX *ctx = evr_create_ssl_ctx();
    if(!ctx){
        return NULL;
    }
    if(SSL_CTX_load_verify_locations(ctx, cert_path, NULL) != 1){
        goto out_with_free_ctx;
    }
    return ctx;
 out_with_free_ctx:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL_CTX *evr_create_ssl_ctx(){
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if(!ctx){
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_clear_options(ctx, SSL_OP_LEGACY_SERVER_CONNECT);
    return ctx;
}

int evr_file_ssl_get_fd(struct evr_file *f);
ssize_t evr_file_ssl_read(struct evr_file *f, void *buf, size_t count);
ssize_t evr_file_ssl_write(struct evr_file *f, const void *buf, size_t count);
int evr_file_ssl_close(struct evr_file *f);

void evr_file_bind_ssl(struct evr_file *f, SSL *s){
    f->ctx.p = s;
    f->get_fd = evr_file_ssl_get_fd;
    f->read = evr_file_ssl_read;
    f->write = evr_file_ssl_write;
    f->close = evr_file_ssl_close;
}

#define evr_file_get_ssl(f) ((SSL*)(f)->ctx.p)

int evr_file_ssl_get_fd(struct evr_file *f){
    return SSL_get_fd(evr_file_get_ssl(f));
}

ssize_t evr_file_ssl_read(struct evr_file *f, void *buf, size_t count){
    return SSL_read(evr_file_get_ssl(f), buf, count);
}

ssize_t evr_file_ssl_write(struct evr_file *f, const void *buf, size_t count){
    return SSL_write(evr_file_get_ssl(f), buf, count);
}

int evr_file_ssl_close(struct evr_file *f){
    SSL *ssl = evr_file_get_ssl(f);
    if(!ssl){
        return evr_ok;
    }
    int fd = evr_file_ssl_get_fd(f);
    int shutdown_res = SSL_shutdown(ssl);
    if(shutdown_res < 0){
        log_debug("SSL shutdown of socket %d failed with SSL error", fd);
#ifdef EVR_LOG_DEBUG
        evr_tls_log_ssl_errors(f, evr_log_level_debug);
#endif
    }
    SSL_free(ssl);
    return close(fd);
}

int evr_tls_accept(struct evr_file *f, int s, SSL_CTX *ssl_ctx){
    evr_file_bind_ssl(f, NULL);
    struct sockaddr_in client_addr;
    socklen_t size = sizeof(client_addr);
    int fd = accept(s, (struct sockaddr*)&client_addr, &size);
    if(fd < 0){
        evr_panic("Unable to accept connection from socket %d", s);
        return evr_error;
    }
    log_debug("Connection from %s:%d accepted (will be worker %d)", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), fd);
    SSL *ssl = SSL_new(ssl_ctx);
    if(!ssl){
        goto out_with_close_fd;
    }
    if(SSL_set_fd(ssl, fd) != 1){
        goto out_with_free_ssl;
    }
    int accept_res = SSL_accept(ssl);
    if(accept_res <= 0){
        log_debug("Unable to accept SSL connection for socket %d", fd);
        struct evr_file err;
        evr_file_bind_ssl(&err, ssl);
#ifdef EVR_LOG_DEBUG
        evr_tls_log_ssl_errors(&err, evr_log_level_debug);
#endif
        goto out_with_free_ssl;
    }
    evr_file_bind_ssl(f, ssl);
    return evr_ok;
 out_with_free_ssl:
    SSL_free(ssl);
 out_with_close_fd:
    if(close(fd) != 0){
        evr_panic("Unable to close client connection");
    }
    return evr_error;
}

void evr_tls_log_ssl_errors(struct evr_file *f, char *log_level){
    int fd = f->get_fd(f);
    char buf[256];
    while(1){
        unsigned long err = ERR_get_error();
        if(err == 0){
            break;
        }
        ERR_error_string(err, buf);
        evr_log(log_level, "TLS error with socket %d: %s", fd, buf);
    }
}
