/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
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

#include <signal.h>
#include <threads.h>
#include <microhttpd.h>
#include <sys/wait.h>

#include "basics.h"
#include "errors.h"
#include "logger.h"
#include "configp.h"
#include "daemon.h"
#include "auth.h"
#include "httpd.h"
#include "subprocess.h"
#include "files.h"

#define program_name "evr-upload-httpd"
#define server_name program_name "/" VERSION

const char *argp_program_version = program_name " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " provides an http endpoint for uploading files as file claims.";

static char args_doc[] = "";

#define arg_host 256
#define arg_http_port 257
#define arg_auth_token 258
#define arg_log_path 259
#define arg_pid_path 260

static struct argp_option options[] = {
    {"host", arg_host, "HOST", 0, "The network interface at which the upload server will listen on. The default is " evr_upload_httpd_host "."},
    {"http-port", arg_http_port, "PORT", 0, "The tcp port at which the upload server will listen for http connections. The default port is " to_string(evr_upload_httpd_http_port) "."},
    {"auth-token", arg_auth_token, "TOKEN", 0, "An authorization token which must be presented by clients so their requests are accepted. Must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret. You can call 'openssl rand -hex 32' to generate a good token."},
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"log", arg_log_path, "FILE", 0, "A file to which log output messages will be appended. By default logs are written to stdout."},
    {"pid", arg_pid_path, "FILE", 0, "A file to which the daemon's pid is written."},
    {0},
};

struct evr_upload_httpd_cfg {
    char *host;
    char *http_port;

    /**
     * foreground's indicates if the process should stay in the
     * started process or fork into a daemon.
     */
    int foreground;

    int auth_token_set;
    evr_auth_token auth_token;

    char *log_path;
    char *pid_path;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_upload_httpd_cfg *cfg = (struct evr_upload_httpd_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case arg_host:
        evr_replace_str(cfg->host, arg);
        break;
    case arg_http_port:
        evr_replace_str(cfg->http_port, arg);
        break;
    case 'f':
        cfg->foreground = 1;
        break;
    case arg_log_path:
        evr_replace_str(cfg->log_path, arg);
        break;
    case arg_pid_path:
        evr_replace_str(cfg->pid_path, arg);
        break;
    case arg_auth_token:
        if(evr_parse_auth_token(cfg->auth_token, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->auth_token_set = 1;
        break;
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

static sig_atomic_t running = 1;
static mtx_t stop_lock;
static cnd_t stop_signal;

struct evr_upload_httpd_cfg cfg;

static int evr_load_upload_httpd_cfg(struct evr_upload_httpd_cfg *cfg, int argc, char **argv);
static void evr_unload_upload_httpd_cfg(struct evr_upload_httpd_cfg *cfg);

void handle_sigterm(int signum);

static enum MHD_Result evr_http_upload_handle_request(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);

int main(int argc, char **argv){
    int ret = evr_error;
    struct MHD_Daemon *httpd;
    long http_port;
    char *http_port_end;
    evr_log_app = "u";
    evr_init_basics();
    if(evr_load_upload_httpd_cfg(&cfg, argc, argv) != evr_ok){
        goto out;
    }
    {
        struct sigaction action = { 0 };
        action.sa_handler = handle_sigterm;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    if(mtx_init(&stop_lock, mtx_plain) != thrd_success){
        goto out_with_free_cfg;
    }
    if(cnd_init(&stop_signal) != thrd_success){
        goto out_with_free_stop_lock;
    }
    if(!cfg.foreground){
        if(evr_daemonize(cfg.pid_path) != evr_ok){
            goto out_with_free_stop_signal;
        }
    }
    http_port = strtol(cfg.http_port, &http_port_end, 10);
    if(*http_port_end != '\0'){
        log_error("Expected a number as http port but got: %s", cfg.http_port);
        goto out_with_free_stop_signal;
    }
    if(http_port < 0 || http_port > 65535){
        log_error("http port must be greater equal 0 and smaller equal 65535");
        goto out_with_free_stop_signal;
    }
    // TODO use a thread pool
    httpd = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, (uint16_t)http_port, NULL, NULL, &evr_http_upload_handle_request, NULL, MHD_OPTION_END);
    if(!httpd){
        log_error("Unable to start http daemon");
        goto out_with_free_stop_signal;
    }
    log_info("http server listening on %s", cfg.http_port);
    if(mtx_lock(&stop_lock) != thrd_success){
        evr_panic("Failed to lock stop lock");
    }
    while(running){
        if(cnd_wait(&stop_signal, &stop_lock) != thrd_success){
            log_error("Failed to wait for stop signal");
            goto out_with_stop_httpd;
        }
    }
    if(mtx_unlock(&stop_lock) != thrd_success){
        evr_panic("Failed to unlock stop lock");
    }
    ret = evr_ok;
 out_with_stop_httpd:
    if(httpd){
        MHD_stop_daemon(httpd);
    }
 out_with_free_stop_signal:
    cnd_destroy(&stop_signal);
 out_with_free_stop_lock:
    mtx_destroy(&stop_lock);
 out_with_free_cfg:
    evr_unload_upload_httpd_cfg(&cfg);
 out:
    return ret;
}


static int evr_load_upload_httpd_cfg(struct evr_upload_httpd_cfg *cfg, int argc, char **argv){
    cfg->host = strdup(evr_upload_httpd_host);
    cfg->http_port = strdup(to_string(evr_upload_httpd_http_port));
    cfg->auth_token_set = 0;
    cfg->foreground = 0;
    cfg->log_path = NULL;
    cfg->pid_path = NULL;
    if(!cfg->host || !cfg->http_port){
        evr_panic("Unable to allocate memory for configuration.");
    }
    struct configp configp = {
        options, parse_opt, args_doc, doc
    };
    char *config_paths[] = evr_program_config_paths();
    if(configp_parse(&configp, config_paths, cfg) != 0){
        log_error("Unable to parse config files");
        goto free_and_fail;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, cfg);
    if(evr_setup_log(cfg->log_path) != evr_ok){
        goto free_and_fail;
    }
    if(cfg->auth_token_set == 0){
        log_error("Setting an auth-token is mandatory. Call " program_name " --help for details how to set the auth-token.");
        goto free_and_fail;
    }
    return evr_ok;
 free_and_fail:
    evr_unload_upload_httpd_cfg(cfg);
    return evr_error;
}

static void evr_unload_upload_httpd_cfg(struct evr_upload_httpd_cfg *cfg){
    char *str_options[] = {
        cfg->host,
        cfg->http_port,
        cfg->log_path,
        cfg->pid_path,
    };
    char **str_options_end = &str_options[static_len(str_options)];
    for(char **it = str_options; it != str_options_end; ++it){
        if(*it){
            free(*it);
        }
    }
}

void handle_sigterm(int signum){
    if(mtx_lock(&stop_lock) != thrd_success){
        evr_panic("Failed to lock stop lock");
    }
    if(running){
        log_info("Shutting down");
        running = 0;
        if(cnd_signal(&stop_signal) != thrd_success){
            evr_panic("Failed to send stop signal");
        }
    }
    if(mtx_unlock(&stop_lock) != thrd_success){
        evr_panic("Failed to unlock stop lock");
    }
}

static const char evr_httpd_unauthorized[] = "No Bearer Authorization header with valid auth-token provided";
static const char evr_httpd_server_error[] = "Internal server error";
static const char evr_httpd_not_found[] = "Endpoint not found";

static const char evr_files_url_prefix[] = "/files/";

static enum MHD_Result evr_http_upload_handle_file_upload(struct MHD_Connection *c, const char *file_name, const char *upload_data, size_t *upload_data_size, void **con_cls);

static enum MHD_Result evr_http_upload_handle_request(void *cls, struct MHD_Connection *c, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls){
    int res;
    const char *file_name;
#ifdef EVR_LOG_DEBUG
    if(!*con_cls){
        log_debug("http request %s %s", method, url);
    }
#endif
    res = evr_httpd_check_authentication(c, cfg.auth_token);
    if(res == evr_user_data_invalid) {
        return evr_httpd_respond_static_msg(c, 401, evr_httpd_unauthorized, server_name);
    } else if(res != evr_ok) {
        return evr_httpd_respond_static_msg(c, 500, evr_httpd_server_error, server_name);
    }
    // after this point the request is authenticated
    if(strcmp(method, "POST") == 0 && strncmp(url, evr_files_url_prefix, sizeof(evr_files_url_prefix) - 1) == 0){
        file_name = &url[sizeof(evr_files_url_prefix) - 1];
        return evr_http_upload_handle_file_upload(c, file_name, upload_data, upload_data_size, con_cls);
    }
    return evr_httpd_respond_static_msg(c, 404, evr_httpd_not_found, server_name);
}

struct evr_file_upload_ctx {
    struct evr_subprocess evr_cli;
    struct evr_file evr_cli_stdin;
};

static enum MHD_Result evr_http_upload_handle_file_upload(struct MHD_Connection *c, const char *file_name, const char *upload_data, size_t *upload_data_size, void **con_cls){
    struct evr_file_upload_ctx *ctx;
    const char *evr_cli_argv[] = {
        "evr",
        "post-file",
        "-t",
        file_name,
        NULL,
    };
    int res;
    struct dynamic_array *buf, *err_buf;
    char *resp_body;
    size_t resp_body_size;
    struct MHD_Response *resp;
    enum MHD_Result mhd_ret;
    char chr;
    if(*con_cls){
        // continuation of existing request
        ctx = *con_cls;
    } else {
        // brand new request
        ctx = malloc(sizeof(struct evr_file_upload_ctx));
        if(!ctx){
            goto fail;
        }
        if(evr_spawn(&ctx->evr_cli, evr_cli_argv, NULL) != evr_ok){
            log_error("Unable to spawn evr cli for post-file");
            goto fail_with_free_ctx;
        }
        evr_file_bind_fd(&ctx->evr_cli_stdin, ctx->evr_cli.in);
        *con_cls = ctx;
        return MHD_YES;
    }
    if(*upload_data_size){
        res = write_n(&ctx->evr_cli_stdin, upload_data, *upload_data_size);
        if(res != evr_ok){
            log_error("Unable to write http body chunk of %zu bytes to evr cli", *upload_data_size);
            goto fail_with_close_evr_cli;
        }
        *upload_data_size = 0;
        return MHD_YES;
    }
    // request body was completely streamed
    if(ctx->evr_cli_stdin.close(&ctx->evr_cli_stdin)){
        goto fail_with_close_evr_cli;
    }
    static const int closed_fd = -1;
    ctx->evr_cli.in = closed_fd;
    buf = alloc_dynamic_array(0);
    if(!buf){
        goto fail_with_close_evr_cli;
    }
    res = read_fd(&buf, ctx->evr_cli.out, max(256, buf->size_allocated));
    if(res != evr_end){
        log_error("Unable to read file-ref from evr cli. Error code %d", res);
        goto fail_with_free_buf;
    }
    if(waitpid(ctx->evr_cli.pid, &res, WUNTRACED) < 0){
        goto fail_with_free_buf;
    }
    if(res != 0){
        log_error("evr cli post-file ended with an error: %d", res);
        goto fail_with_free_buf;
    }
    if(buf->size_used == 0){
        log_error("No seed reported by evr cli post-file");
        goto fail_with_free_buf;
    }
    resp_body_size = buf->size_used;
    resp_body = malloc(resp_body_size);
    if(!resp_body){
        goto fail_with_free_buf;
    }
    memcpy(resp_body, buf->data, resp_body_size);
    free(buf);
    while(resp_body_size > 0){
        chr = resp_body[resp_body_size-1];
        if(isspace(chr)){
            --resp_body_size;
        } else {
            break;
        }
    }
    if(resp_body_size == 0){
        log_error("Seed reported by evr cli post-file was just whitespace");
        goto fail_with_free_buf;
    }
    buf = NULL;
    resp = MHD_create_response_from_buffer(resp_body_size, resp_body, MHD_RESPMEM_MUST_FREE);
    if(!resp){
        free(resp_body);
        goto fail_with_free_buf;
    }
    if(evr_add_std_http_headers(resp, server_name, "text/plain") != evr_ok){
        goto fail_with_destroy_resp;
    }
    mhd_ret = MHD_queue_response(c, 200, resp);
    MHD_destroy_response(resp);
    if(ctx->evr_cli.in != closed_fd){
        close(ctx->evr_cli.in);
    }
    close(ctx->evr_cli.out);
    close(ctx->evr_cli.err);
    free(ctx);
    return mhd_ret;
 fail_with_destroy_resp:
    MHD_destroy_response(resp);
 fail_with_free_buf:
    free(buf);
 fail_with_close_evr_cli:
    err_buf = alloc_dynamic_array(64*1024);
    if(err_buf) {
        res = read_fd(&err_buf, ctx->evr_cli.err, 64*1024);
        if((res == evr_ok || res == evr_end) && err_buf){
            err_buf->data[min(err_buf->size_used, err_buf->size_allocated - 1)] = '\0';
            log_error("evr cli post file failed with stderr: %s", err_buf->data);
        }
        free(err_buf);
    }
    if(ctx->evr_cli.in != closed_fd){
        close(ctx->evr_cli.in);
    }
    close(ctx->evr_cli.out);
    close(ctx->evr_cli.err);
 fail_with_free_ctx:
    free(ctx);
 fail:
     return evr_httpd_respond_static_msg(c, 500, evr_httpd_server_error, server_name);
}
