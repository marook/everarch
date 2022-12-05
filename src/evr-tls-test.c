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

#include "config.h"

#include <threads.h>
#include <string.h>
#include <unistd.h>

#include "evr-tls.h"
#include "files.h"
#include "assert.h"
#include "server.h"
#include "errors.h"
#include "test.h"
#include "logger.h"

#define tls_test_port "38563"
#define test_payload_a "hello"
#define test_payload_b "world!"

struct client_server_ctx {
    mtx_t server_ready;
};

int client_worker(void *context);
int server_worker(void *context);

void test_tls_accept_connect(){
    struct client_server_ctx ctx;
    assert(mtx_init(&ctx.server_ready, mtx_plain) == thrd_success);
    assert(mtx_lock(&ctx.server_ready) == thrd_success);
    thrd_t server;
    assert(thrd_create(&server, server_worker, &ctx) == thrd_success);
    thrd_t client;
    assert(thrd_create(&client, client_worker, &ctx) == thrd_success);
    assert(thrd_join(client, NULL) == thrd_success);
    assert(thrd_join(server, NULL) == thrd_success);
    mtx_destroy(&ctx.server_ready);
}

int server_worker(void *context){
    struct client_server_ctx *ctx = context;
    int s = evr_make_tcp_socket("localhost", tls_test_port);
    assert(s >= 0);
    assert(listen(s, 1) == 0);
    log_debug("tls server listening");
    assert(mtx_unlock(&ctx->server_ready) == thrd_success);
    SSL_CTX *ssl_ctx = evr_create_ssl_server_ctx("../testing/tls/glacier-cert.pem", "../testing/tls/glacier-key.pem");
    assert(ssl_ctx);
    struct evr_file c;
    for(int i = 0; i < 2; ++i){
        assert(is_ok(evr_tls_accept(&c, s, ssl_ctx)));
        char buf[strlen(test_payload_a)];
        log_debug("tls server reading");
        assert(is_ok(read_n(&c, buf, strlen(test_payload_a), NULL, NULL)));
        assert(memcmp(buf, test_payload_a, strlen(test_payload_a)) == 0);
        log_debug("tls server writing");
        assert(is_ok(write_n(&c, test_payload_b, strlen(test_payload_b))));
        log_debug("tls server closing");
        assert(c.close(&c) == 0);
    }
    SSL_CTX_free(ssl_ctx);
    assert(close(s) == 0);
    return evr_ok;
}

void client_worker_tls_connect(struct evr_cert_cfg *ssl_cfg);
void client_worker_tls_connect_once(struct evr_cert_cfg *ssl_cfg);

int client_worker(void *context){
    struct client_server_ctx *ctx = context;
    struct evr_cert_cfg *ssl_cfg = NULL;
    assert(is_ok(evr_push_cert(&ssl_cfg, "localhost", tls_test_port, "../testing/tls/glacier-cert.pem")));
    assert(mtx_lock(&ctx->server_ready) == thrd_success);
    client_worker_tls_connect(ssl_cfg);
    client_worker_tls_connect_once(ssl_cfg);
    evr_free_cert_chain(ssl_cfg);
    assert(mtx_unlock(&ctx->server_ready) == thrd_success);
    return evr_ok;
}

void client_worker_tls_connect(struct evr_cert_cfg *ssl_cfg){
    SSL_CTX *ssl_ctx = evr_create_ssl_client_ctx("localhost", tls_test_port, ssl_cfg);
    assert(ssl_ctx);
    struct evr_file c;
    log_debug("tls client connecting");
    assert(is_ok(evr_tls_connect(&c, "localhost", tls_test_port, ssl_ctx)));
    log_debug("tls client writing");
    assert(is_ok(write_n(&c, test_payload_a, strlen(test_payload_a))));
    log_debug("tls client reading");
    char buf[strlen(test_payload_b)];
    assert(is_ok(read_n(&c, buf, strlen(test_payload_b), NULL, NULL)));
    assert(memcmp(buf, test_payload_b, strlen(test_payload_b)) == 0);
    log_debug("tls client closing");
    assert(c.close(&c) == 0);
    SSL_CTX_free(ssl_ctx);
}

void client_worker_tls_connect_once(struct evr_cert_cfg *cert_cfg){
    struct evr_file c;
    assert(is_ok(evr_tls_connect_once(&c, "localhost", tls_test_port, cert_cfg)));
    log_debug("tls client writing");
    assert(is_ok(write_n(&c, test_payload_a, strlen(test_payload_a))));
    log_debug("tls client reading");
    char buf[strlen(test_payload_b)];
    assert(is_ok(read_n(&c, buf, strlen(test_payload_b), NULL, NULL)));
    assert(memcmp(buf, test_payload_b, strlen(test_payload_b)) == 0);
    log_debug("tls client closing");
    assert(c.close(&c) == 0);
}

void test_evr_cert_cfg(){
    struct evr_cert_cfg *cfg = NULL;
    assert(is_ok(evr_parse_and_push_cert(&cfg, "localhost:1234:/ye/path/to/cert.pem")));
    struct evr_cert_cfg *found_cfg = NULL;
    assert(is_ok(evr_find_cert(&found_cfg, cfg, "localhost", "1234")));
    assert(found_cfg);
    assert(is_str_eq(found_cfg->cert_path, "/ye/path/to/cert.pem"));
    assert(evr_find_cert(&found_cfg, cfg, "localhost", "0") == evr_not_found);
    assert(evr_find_cert(&found_cfg, cfg, "acme.org", "1234") == evr_not_found);
    evr_free_cert_chain(cfg);
}

int main(){
    evr_init_basics();
    evr_tls_init();
    run_test(test_tls_accept_connect);
    run_test(test_evr_cert_cfg);
    evr_tls_free();
    return 0;
}
