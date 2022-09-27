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

#include <stdlib.h>
#include <stdio.h>
#include <threads.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "basics.h"
#include "configp.h"
#include "auth.h"
#include "errors.h"
#include "evr-tls.h"
#include "logger.h"
#include "keys.h"
#include "evr-glacier-client.h"

#define program_name "glacier-benchmark"

const char *argp_program_version = program_name " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " generates load on an evr glacier storage server.";

static char args_doc[] = "";

#define arg_storage_host 256
#define arg_storage_port 257
#define arg_ssl_cert 258
#define arg_blobs_sort_order 259
#define arg_auth_token 260

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glalier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of the server. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"auth-token", arg_auth_token, "HOST:PORT:TOKEN", 0, "A hostname, port and authorization token which is presented to the server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {0}
};

struct benchmark_cfg {
    char *storage_host;
    char *storage_port;
    struct evr_auth_token_cfg *auth_tokens;
    struct evr_cert_cfg *ssl_certs;
    struct evr_auth_token_cfg *storage_auth_token;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct benchmark_cfg *cfg = (struct benchmark_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case arg_storage_host:
        evr_replace_str(cfg->storage_host, arg);
        break;
    case arg_storage_port:
        evr_replace_str(cfg->storage_port, arg);
        break;
    case arg_auth_token:
        if(evr_parse_and_push_auth_token(&cfg->auth_tokens, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case arg_ssl_cert:
        if(evr_parse_and_push_cert(&cfg->ssl_certs, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case ARGP_KEY_END:
        break;
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

static int running = 1;

struct benchmark_stats {
    unsigned int read_attempts;
    unsigned int read_blobs;
    unsigned long read_blob_bytes;
    unsigned int not_found_blobs;

    unsigned int write_attempts;
    unsigned int written_existing_blobs;
    unsigned int written_blobs;
    unsigned long written_blob_bytes;
};

static struct benchmark_cfg cfg;

void reset_n_benchmark_stats(struct benchmark_stats *stats, size_t len);
void reset_benchmark_stats(struct benchmark_stats *stats);
void aggregate_n_stats(struct benchmark_stats *agg, struct benchmark_stats *stats, size_t len);
void print_stats(int nprocs, struct benchmark_stats *stats, struct timespec *dt);
void delta_time(struct timespec *dt, struct timespec *t0, struct timespec *t1);
int create_n_workers(thrd_t *thrds, size_t thrds_len, int (*worker)(void *stats), struct benchmark_stats *stats);
int join_n_workers(thrd_t *thrds, size_t thrds_len);
int glacier_read_worker(void *context);
int glacier_write_worker(void *context);

int main(int argc, char **argv){
    int ret = 1;
    evr_log_fd = STDERR_FILENO;
    evr_init_basics();
    evr_tls_init();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    int nprocs = get_nprocs();
    log_info("Detected %d cores", nprocs);
    const int read_worker_count = nprocs;
    struct benchmark_stats read_stats[read_worker_count];
    thrd_t read_thrds[read_worker_count];
    const int write_worker_count = nprocs;
    struct benchmark_stats write_stats[write_worker_count];
    thrd_t write_thrds[write_worker_count];
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.auth_tokens = NULL;
    cfg.ssl_certs = NULL;
    if(evr_push_cert(&cfg.ssl_certs, evr_glacier_storage_host, to_string(evr_glacier_storage_port), default_storage_ssl_cert_path) != evr_ok){
        goto out_with_free_cfg;
    }
    char *config_paths[] = evr_program_config_paths();
    struct configp configp = { options, parse_opt, args_doc, doc };
    if(configp_parse(&configp, config_paths, &cfg) != 0){
        goto out_with_free_cfg;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    if(evr_find_auth_token(&cfg.storage_auth_token, cfg.auth_tokens, cfg.storage_host, cfg.storage_port) != evr_ok){
        log_error("No auth token found for server %s:%s", cfg.storage_host, cfg.storage_port);
        goto out_with_free_cfg;
    }
    reset_n_benchmark_stats(read_stats, read_worker_count);
    reset_n_benchmark_stats(write_stats, write_worker_count);
    struct timespec t_start;
    if(clock_gettime(CLOCK_MONOTONIC, &t_start) != 0){
        goto out_with_free_cfg;
    }
    if(create_n_workers(read_thrds, read_worker_count, glacier_read_worker, read_stats) != evr_ok){
        goto out_with_free_cfg;
    }
    if(create_n_workers(write_thrds, write_worker_count, glacier_write_worker, write_stats) != evr_ok){
        running = 0;
        goto out_with_join_read_workers;
    }
    log_info("Running benchmark...");
    struct timespec sleep_duration = {
        10,
        0
    };
    if(thrd_sleep(&sleep_duration, NULL) != 0){
        goto out_with_free_cfg;
    }
    running = 0;
    struct timespec t_end;
    if(clock_gettime(CLOCK_MONOTONIC, &t_end) != 0){
        goto out_with_join_read_workers;
    }
    if(join_n_workers(write_thrds, write_worker_count) != evr_ok){
        goto out_with_join_read_workers;
    }
    ret = 0;
 out_with_join_read_workers:
    if(join_n_workers(read_thrds, read_worker_count) != evr_ok){
        ret = 1;
        goto out_with_free_cfg;
    }
    struct benchmark_stats aggregated_stats;
    reset_benchmark_stats(&aggregated_stats);
    aggregate_n_stats(&aggregated_stats, read_stats, read_worker_count);
    aggregate_n_stats(&aggregated_stats, write_stats, write_worker_count);
    struct timespec dt;
    delta_time(&dt, &t_start, &t_end);
    print_stats(nprocs, &aggregated_stats, &dt);
 out_with_free_cfg:
    if(cfg.storage_host){
        free(cfg.storage_host);
    }
    if(cfg.storage_port){
        free(cfg.storage_port);
    }
    evr_free_auth_token_chain(cfg.auth_tokens);
    evr_free_cert_chain(cfg.ssl_certs);    
    return ret;
}

void reset_n_benchmark_stats(struct benchmark_stats *stats, size_t len){
    for(struct benchmark_stats *end = &stats[len]; stats != end; ++stats){
        reset_benchmark_stats(stats);
    }
}

void reset_benchmark_stats(struct benchmark_stats *stats){
    stats->read_attempts = 0;
    stats->read_blobs = 0;
    stats->read_blob_bytes = 0;
    stats->not_found_blobs = 0;
    stats->write_attempts = 0;
    stats->written_existing_blobs = 0;
    stats->written_blobs = 0;
    stats->written_blob_bytes = 0;
}

void aggregate_stats(struct benchmark_stats *agg, struct benchmark_stats *stats);

void aggregate_n_stats(struct benchmark_stats *agg, struct benchmark_stats *stats, size_t len){
    for(struct benchmark_stats *end = &stats[len]; stats != end; ++stats){
        aggregate_stats(agg, stats);
    }
}

void aggregate_stats(struct benchmark_stats *agg, struct benchmark_stats *stats){
    agg->read_attempts += stats->read_attempts;
    agg->read_blobs += stats->read_blobs;
    agg->read_blob_bytes += stats->read_blob_bytes;
    agg->not_found_blobs += stats->not_found_blobs;
    agg->write_attempts += stats->write_attempts;
    agg->written_existing_blobs += stats->written_existing_blobs;
    agg->written_blobs += stats->written_blobs;
    agg->written_blob_bytes += stats->written_blob_bytes;
}

void print_stats(int nprocs, struct benchmark_stats *stats, struct timespec *dt){
    unsigned long runtime = dt->tv_sec + (dt->tv_nsec < 500000 ? 0 : 1);
    unsigned long read_blob_kbytes_s = stats->read_blob_bytes / runtime / 1024;
    unsigned long written_blob_kbytes_s = stats->written_blob_bytes / runtime / 1024;
    printf("nprocs\t%d\n"
           "runtime_s\t%lu\n"
           "read_attempts\t%u\n"
           "read_blobs\t%u\n"
           "read_blob_bytes\t%lu\n"
           "read_blob_kbytes/s\t%lu\n"
           "not_found_blobs\t%u\n"
           "write_attempts\t%u\n"
           "written_existing_blobs\t%u\n"
           "written_blobs\t%u\n"
           "written_blob_bytes\t%lu\n"
           "written_blob_kbytes/s\t%lu\n",
           nprocs, runtime, stats->read_attempts, stats->read_blobs, stats->read_blob_bytes, read_blob_kbytes_s, stats->not_found_blobs, stats->write_attempts, stats->written_existing_blobs, stats->written_blobs, stats->written_blob_bytes, written_blob_kbytes_s);
}

void delta_time(struct timespec *dt, struct timespec *t0, struct timespec *t1){
    if(t1->tv_nsec > t0->tv_nsec){
        dt->tv_sec = t1->tv_sec - t0->tv_sec - 1;
        dt->tv_nsec = (1000000 + t1->tv_nsec) - t0->tv_nsec;
    } else {
        dt->tv_sec = t1->tv_sec - t0->tv_sec;
        dt->tv_nsec = t1->tv_nsec - t0->tv_nsec;
    }
}

int create_n_workers(thrd_t *thrds, size_t thrds_len, int (*worker)(void *stats), struct benchmark_stats *stats){
    for(size_t i = 0; i < thrds_len; ++i){
        if(thrd_create(&thrds[i], worker, &stats[i]) != thrd_success){
            // panic because we don't cleanup thread 0 if creation of
            // thread 1 fails.
            evr_panic("Unable to create worker thread");
            return evr_error;
        }
    }
    return evr_ok;
}

int join_n_workers(thrd_t *thrds, size_t thrds_len){
    int res;
    for(size_t i = 0; i < thrds_len; ++i){
        if(thrd_join(thrds[i], &res) != thrd_success){
            evr_panic("Unable to join all workers");
            return evr_error;
        }
        if(res != evr_ok){
            evr_panic("Failed to join worker %zu", i);
            return evr_error;
        }
    }
    return evr_ok;
}

struct glacier_worker_ctx {
    struct evr_file c;
    struct benchmark_stats *stats;
};

#define small_blob_content "hello world!"

struct ready_made_blob {
    evr_blob_ref ref;
    struct chunk_set blob;
    void *heap_data;
};

int make_blob_from_str(struct ready_made_blob *rmb, char *s);
int glacier_read_blob(struct glacier_worker_ctx *stats, evr_blob_ref ref);

int glacier_read_worker(void *context){
    int ret = evr_error;
    struct glacier_worker_ctx ctx;
    evr_file_bind_fd(&ctx.c, -1);
    ctx.stats = context;
    evr_blob_ref not_existing_ref;
    if(evr_parse_blob_ref(not_existing_ref, "sha3-224-ffffffffffffffffffffffffffffffffffffffffffffffffffffffff") != evr_ok){
        goto out;
    }
    struct ready_made_blob small_blob;
    if(make_blob_from_str(&small_blob, small_blob_content) != evr_ok){
        goto out;
    }
    int state = 0;
    while(running){
        switch(state++ % 2){
        default:
            evr_panic("Unknown glacier_read_worker state %d", state);
            break;
        case 0:
            // read not existing blob
            if(glacier_read_blob(&ctx, not_existing_ref) != evr_ok){
                goto out_with_close_c;
            }
            break;
        case 1:
            // read most likely existing blob
            if(glacier_read_blob(&ctx, small_blob.ref) != evr_ok){
                goto out_with_close_c;
            }
            break;
        }
    }
    ret = evr_ok;
 out_with_close_c:
    if(ctx.c.get_fd(&ctx.c) != -1){
        if(ctx.c.close(&ctx.c) != 0){
            evr_panic("Unable to close glacier connection");
            goto out;
        }
    }
 out:
    running = 0;
    return ret;
}

int ensure_glacier_connected(struct evr_file *c);

int glacier_read_blob(struct glacier_worker_ctx *ctx, evr_blob_ref ref){
    if(ensure_glacier_connected(&ctx->c) != evr_ok){
        return evr_error;
    }
    if(running){
        ctx->stats->read_attempts += 1;
    }
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(&ctx->c, ref, &resp) != evr_ok){
        return evr_error;
    }
    if(resp.status_code == evr_status_code_blob_not_found){
        if(running){
            ctx->stats->not_found_blobs += 1;
        }
        return evr_ok;
    } else if(resp.status_code != evr_status_code_ok){
        return evr_error;
    }
    if(dump_n(&ctx->c, resp.body_size, NULL, NULL) != evr_ok){
        return evr_error;
    }
    if(running){
        ctx->stats->read_blobs += 1;
        ctx->stats->read_blob_bytes += resp.body_size;
    }
    return evr_ok;
}

int glacier_put_ready_made_blob(struct glacier_worker_ctx *ctx, struct ready_made_blob *blob);
int put_random_blob(struct glacier_worker_ctx *ctx, size_t size);
int make_blob_from_rand(struct ready_made_blob *rmb, size_t size);

int glacier_write_worker(void *context){
    int ret = evr_error;
    struct glacier_worker_ctx ctx;
    evr_file_bind_fd(&ctx.c, -1);
    ctx.stats = context;
    struct ready_made_blob small_blob;
    if(make_blob_from_str(&small_blob, small_blob_content) != evr_ok){
        goto out;
    }
    int state = 0;
    while(running){
        switch(state++ % 6){
        default:
            evr_panic("Unknown glacier_write_worker state %d", state);
            break;
        case 0:
            // put most likely existing blob
            if(glacier_put_ready_made_blob(&ctx, &small_blob) != evr_ok){
                goto out_with_close_c;
            }
            break;
        case 1:
            if(put_random_blob(&ctx, 1000) != evr_ok){
                goto out_with_close_c;
            }
            break;
        case 2:
            if(put_random_blob(&ctx, 5000) != evr_ok){
                goto out_with_close_c;
            }
            break;
        case 3:
        case 4:
        case 5:
           if(put_random_blob(&ctx, 200*1024) != evr_ok){
                goto out_with_close_c;
            }
            break;
        }
    }
    ret = evr_ok;
 out_with_close_c:
    if(ctx.c.get_fd(&ctx.c) != -1){
        if(ctx.c.close(&ctx.c) != 0){
            evr_panic("Unable to close glacier connection");
            goto out;
        }
    }
 out:
    running = 0;
    return ret;
}

int put_random_blob(struct glacier_worker_ctx *ctx, size_t size){
    int ret = evr_error;
    struct ready_made_blob blob;
    if(make_blob_from_rand(&blob, size) != evr_ok){
        goto out;
    }
    if(glacier_put_ready_made_blob(ctx, &blob) != evr_ok){
        goto out_with_free_heap_data;
    }
    ret = evr_ok;
 out_with_free_heap_data:
    free(blob.heap_data);
 out:
    return ret;
}

int make_blob_from_str(struct ready_made_blob *rmb, char *s){
    rmb->heap_data = NULL;
    size_t s_size = strlen(s);
    if(evr_chunk_setify(&rmb->blob, s, s_size) != evr_ok){
        return evr_error;
    }
    if(evr_calc_blob_ref(rmb->ref, rmb->blob.size_used, rmb->blob.chunks) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int make_blob_from_rand(struct ready_made_blob *rmb, size_t size){
    char *buf = malloc(size);
    if(!buf){
        return evr_error;
    }
    rmb->heap_data = buf;
    for(size_t i = 0; i < size; ++i){
        buf[i] = (char)rand();
    }
    if(evr_chunk_setify(&rmb->blob, buf, size) != evr_ok){
        return evr_error;
    }
    if(evr_calc_blob_ref(rmb->ref, rmb->blob.size_used, rmb->blob.chunks) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int glacier_put_ready_made_blob(struct glacier_worker_ctx *ctx, struct ready_made_blob *blob){
    if(ensure_glacier_connected(&ctx->c) != evr_ok){
        return evr_error;
    }
    if(running){
        ctx->stats->write_attempts += 1;
    }
    int put_res = evr_stat_and_put(&ctx->c, blob->ref, 0, &blob->blob);
    if(put_res == evr_ok){
        if(running){
            ctx->stats->written_blobs += 1;
            ctx->stats->written_blob_bytes += blob->blob.size_used;
        }
    } else if(put_res == evr_exists) {
        if(running){
            ctx->stats->written_existing_blobs += 1;
        }
    } else {
        return evr_error;
    }
    return evr_ok;
}

int ensure_glacier_connected(struct evr_file *c){
    if(c->get_fd(c) != -1){
        return evr_ok;
    }
    if(evr_tls_connect_once(c, cfg.storage_host, cfg.storage_port, cfg.ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server %s:%s", cfg.storage_host, cfg.storage_port);
        return evr_error;
    }
    if(evr_write_auth_token(c, cfg.storage_auth_token->token) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}
