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
#include <netdb.h>
#include <string.h>

#include "basics.h"
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

int evr_parse_and_push_cert(struct evr_cert_cfg **cfg, char *cert_spec){
    char buf[strlen(cert_spec) + 1];
    memcpy(buf, cert_spec, sizeof(buf));
    const size_t fragments_len = 3;
    char *fragments[fragments_len];
    if(evr_split_n(fragments, fragments_len, buf, ':') != evr_ok){
        log_debug("Cert spec with illegal syntax detected: %s", cert_spec);
        return evr_error;
    }
    return evr_push_cert(cfg, fragments[0], fragments[1], fragments[2]);
}

int evr_push_cert(struct evr_cert_cfg **cfg, char *host, char *port, char *cert_path){
    const size_t host_size = strlen(host) + 1;
    const size_t port_size = strlen(port) + 1;
    const size_t cert_path_size = strlen(cert_path) + 1;
    char *buf = malloc(sizeof(struct evr_cert_cfg) + host_size + port_size + cert_path_size);
    if(!buf){
        return evr_error;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_cert_cfg *new_cfg;
    evr_map_struct(&bp, new_cfg);
    new_cfg->host = bp.pos;
    evr_push_n(&bp, host, host_size);
    new_cfg->port = bp.pos;
    evr_push_n(&bp, port, port_size);
    new_cfg->cert_path = bp.pos;
    evr_push_n(&bp, cert_path, cert_path_size);
    new_cfg->next = *cfg;
    *cfg = new_cfg;
    return evr_ok;
}

int evr_find_cert(struct evr_cert_cfg **found, struct evr_cert_cfg *chain, char *host, char *port){
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

void evr_free_cert_chain(struct evr_cert_cfg *cfg){
    struct evr_cert_cfg *c;
    while(cfg){
        c = cfg;
        cfg = c->next;
        free(c);
    }
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

SSL_CTX *evr_create_ssl_client_ctx(char *host, char *port, struct evr_cert_cfg *cert_cfg){
    struct evr_cert_cfg *cfg;
    if(evr_find_cert(&cfg, cert_cfg, host, port) != evr_ok){
        log_error("Unable to connect to %s:%s because trusted SSL certificate of server is unknown.", host, port);
        return NULL;
    }
    log_debug("Use SSL cert %s for %s:%s", cfg->cert_path, host, port);
    SSL_CTX *ctx = evr_create_ssl_ctx();
    if(!ctx){
        return NULL;
    }
    if(SSL_CTX_load_verify_locations(ctx, cfg->cert_path, NULL) != 1){
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

void evr_file_bind_ssl(struct evr_file *f, SSL *s);

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
    if(SSL_accept(ssl) != 1){
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

int evr_tls_connect_once(struct evr_file *f, char *host, char *port, struct evr_cert_cfg *cert_cfg){
    SSL_CTX *ssl_ctx = evr_create_ssl_client_ctx(host, port, cert_cfg);
    if(!ssl_ctx){
        return evr_error;
    }
    if(evr_tls_connect(f, host, port, ssl_ctx) != evr_ok){
        SSL_CTX_free(ssl_ctx);
        return evr_error;
    }
    // ref counting will keep ssl_ctx alive as long as f is
    SSL_CTX_free(ssl_ctx);
    return evr_ok;
}

int evr_connect(char *host, char *port);

int evr_tls_connect(struct evr_file *f, char *host, char *port, SSL_CTX *ssl_ctx){
    int c = evr_connect(host, port);
    if(c < 0){
        return evr_error;
    }
    SSL *ssl = SSL_new(ssl_ctx);
    if(!ssl){
        goto out_with_close_c;
    }
    if(SSL_set_fd(ssl, c) != 1){
        goto out_with_free_ssl;
    }
    if(SSL_connect(ssl) != 1){
        log_debug("Unable to establish SSL connection for socket %d", c);
        goto out_with_free_ssl;
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert){
        X509_free(cert);
    }
    if(cert == NULL){
        log_error("Server %s:%s did not provide SSL certificate", host, port);
        goto out_with_free_ssl;
    }
    int verify_res = SSL_get_verify_result(ssl);
    if(verify_res != X509_V_OK){
        // the verify result constants are defined in
        // /usr/include/openssl/x509_vfy.h.
        log_error("Server %s:%s certificate was not verified successfully. Verify result %d.", host, port, verify_res);
        struct evr_file lf;
        evr_file_bind_ssl(&lf, ssl);
        evr_tls_log_ssl_errors(&lf, evr_log_level_error);
        goto out_with_free_ssl;
    }
    evr_file_bind_ssl(f, ssl);
    return evr_ok;
 out_with_free_ssl:
    SSL_free(ssl);
 out_with_close_c:
    if(close(c) != 0){
        evr_panic("Unable to close connection");
    }
    return evr_error;
}

int evr_connect(char *host, char *port){
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    struct addrinfo *result;
    int res = getaddrinfo(host, port, &hints, &result);
    if(res != 0){
        log_error("Failed to resolve %s:%s: %s", host, port, gai_strerror(res));
        return -1;
    }
    for(struct addrinfo *p = result; p != NULL; p = p->ai_next){
        int s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s == -1){
            continue;
        }
        if(connect(s, p->ai_addr, p->ai_addrlen) != 0){
            close(s);
            continue;
        }
        freeaddrinfo(result);
        return s;
    }
    freeaddrinfo(result);
    log_error("Unable to connect to %s:%s", host, port);
    return -1;
}

int evr_file_ssl_get_fd(struct evr_file *f);
int evr_file_ssl_wait_for_data(struct evr_file *f, int timeout);
size_t evr_file_ssl_pending(struct evr_file *f);
int evr_file_ssl_received_shutdown(struct evr_file *f);
ssize_t evr_file_ssl_read(struct evr_file *f, void *buf, size_t count);
ssize_t evr_file_ssl_write(struct evr_file *f, const void *buf, size_t count);
int evr_file_ssl_close(struct evr_file *f);

void evr_file_bind_ssl(struct evr_file *f, SSL *s){
    f->ctx.p = s;
    f->get_fd = evr_file_ssl_get_fd;
    f->wait_for_data = evr_file_ssl_wait_for_data;
    f->pending = evr_file_ssl_pending;
    f->received_shutdown = evr_file_ssl_received_shutdown;
    f->read = evr_file_ssl_read;
    f->write = evr_file_ssl_write;
    f->close = evr_file_ssl_close;
}

#define evr_file_get_ssl(f) ((SSL*)(f)->ctx.p)

int evr_file_ssl_get_fd(struct evr_file *f){
    return SSL_get_fd(evr_file_get_ssl(f));
}

int evr_file_ssl_wait_for_data(struct evr_file *f, int timeout){
    if(evr_file_ssl_pending(f) > 0){
        return evr_ok;
    }
    return evr_file_select(f, timeout);
}

size_t evr_file_ssl_pending(struct evr_file *f){
    // man SSL_pending does not define return values less than zero.
    return (size_t)SSL_pending(evr_file_get_ssl(f));
}

int evr_file_ssl_received_shutdown(struct evr_file *f){
    SSL *ssl = evr_file_get_ssl(f);
    // the following SSL_peek_ex reads pending SSL signals buffered in
    // OS.
    if(evr_file_select(f, 0) == evr_ok){
        size_t bytesread;
        SSL_peek_ex(ssl, NULL, 0, &bytesread);
    }
    return SSL_get_shutdown(ssl) == SSL_RECEIVED_SHUTDOWN;
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
    if(shutdown_res == 0){
        if(SSL_shutdown(ssl) != 1){
            log_debug("Second SSL shutdown of socket %d failed with SSL error", fd);
#ifdef EVR_LOG_DEBUG
            evr_tls_log_ssl_errors(f, evr_log_level_debug);
#endif
        }
    } else if(shutdown_res != 1){
        log_debug("First SSL shutdown of socket %d failed with SSL error %d", fd, shutdown_res);
#ifdef EVR_LOG_DEBUG
        evr_tls_log_ssl_errors(f, evr_log_level_debug);
#endif
    }
    SSL_free(ssl);
    return close(fd);
}
