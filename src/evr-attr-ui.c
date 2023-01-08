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

#include <argp.h>
#include <gtk/gtk.h>
#include <libxml/parser.h>
#include <libxslt/xsltInternals.h>

#include "basics.h"
#include "configp.h"
#include "auth.h"
#include "errors.h"
#include "evr-tls.h"
#include "logger.h"
#include "evr-glacier-client.h"

#define program_name "evr-attr-ui"

const char *argp_program_version = " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " is a GUI application to view and edit evr-attr-index attributes.\n\n"
    "UI_SPEC references the attr-ui-spec specification used to generate a user interface for attributes. UI_SPEC must use the prefix xml:blob: followed by the blob ref which points to the attr-ui-spec XML.";

static char args_doc[] = "UI_SPEC";

#define arg_ssl_cert 256
#define arg_auth_token 257
#define arg_index_host 258
#define arg_index_port 259
#define arg_storage_host 260
#define arg_storage_port 261

struct evr_attr_ui_cfg {
    char *storage_host;
    char *storage_port;
    char *index_host;
    char *index_port;
    struct evr_auth_token_cfg *auth_tokens;
    struct evr_cert_cfg *ssl_certs;
    char *ui_spec;
};

struct evr_attr_ui_cfg cfg;

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glacier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"index-host", arg_index_host, "HOST", 0, "The hostname of the evr-attr-index server to connect to. Default hostname is " evr_attr_index_host "."},
    {"index-port", arg_index_port, "PORT", 0, "The port of the evr-attr-index server to connect to. Default port is " to_string(evr_attr_index_port) "."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of the server. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"auth-token", arg_auth_token, "HOST:PORT:TOKEN", 0, "A hostname, port and authorization token which is presented to the server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_attr_ui_cfg *cfg = (struct evr_attr_ui_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case arg_storage_host:
        evr_replace_str(cfg->storage_host, arg);
        break;
    case arg_storage_port:
        evr_replace_str(cfg->storage_port, arg);
        break;
    case arg_index_host:
        evr_replace_str(cfg->index_host, arg);
        break;
    case arg_index_port:
        evr_replace_str(cfg->index_port, arg);
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
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            evr_replace_str(cfg->ui_spec, arg);
            break;
        }
        break;
    case ARGP_KEY_END:
        if(state->arg_num != 1){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

static int evr_fetch_ui_spec(xmlDoc **doc);

static void activate_main_widget(GApplication * app);

int main(int argc, char *argv[]){
    int ret = 1;
    evr_log_app = "u";
    evr_init_basics();
    evr_tls_init();
    xmlInitParser();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    evr_init_signatures();
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.index_host = strdup(evr_attr_index_host);
    cfg.index_port = strdup(to_string(evr_attr_index_port));
    cfg.auth_tokens = NULL;
    cfg.ssl_certs = NULL;
    cfg.ui_spec = NULL;
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
    xmlDoc *ui_spec = NULL;
    if(evr_fetch_ui_spec(&ui_spec) != evr_ok){
        goto out_with_free_cfg;
    }
    GtkApplication *app =
        gtk_application_new("de.ma300k.evr.evr-attr-ui", G_APPLICATION_NON_UNIQUE | G_APPLICATION_HANDLES_OPEN);
    if(!app){
        goto out_with_free_ui_spec;
    }
    gulong activate_signal = g_signal_connect(G_APPLICATION(app), "activate", G_CALLBACK(activate_main_widget), NULL);
    if(activate_signal <= 0){
        goto out_with_free_app;
    }
    ret = g_application_run(G_APPLICATION(app), 0, NULL);
    g_clear_signal_handler(&activate_signal, G_APPLICATION(app));
 out_with_free_app:
    g_object_unref(app);
 out_with_free_ui_spec:
    xmlFreeDoc(ui_spec);
 out_with_free_cfg:
    do {
        void *tbfree[] = {
            cfg.storage_host,
            cfg.storage_port,
            cfg.index_host,
            cfg.index_port,
            cfg.ui_spec,
        };
        void **tbfree_end = &tbfree[static_len(tbfree)];
        for(void **it = tbfree; it != tbfree_end; ++it){
            free(*it);
        }
    } while(0);
    evr_free_auth_token_chain(cfg.auth_tokens);
    evr_free_cert_chain(cfg.ssl_certs);
    xsltCleanupGlobals();
    xmlCleanupParser();
    evr_tls_free();
    return ret;
}

static int evr_connect_to_storage(struct evr_file *c);

static int evr_fetch_ui_spec(xmlDoc **doc){
    int ret = evr_error;
    const char prefix[] = "xml:blob:";
    if(strncmp(prefix, cfg.ui_spec, sizeof(prefix) - 1) != 0){
        log_error("UI spec argument is missing prefix %s", prefix);
        goto out;
    }
    char *blob_ref_str = &cfg.ui_spec[sizeof(prefix) - 1];
    evr_blob_ref blob_ref;
    if(evr_parse_blob_ref(blob_ref, blob_ref_str) != evr_ok){
        log_error("Syntax error in UI spec's blob ref: %s", blob_ref_str);
        goto out;
    }
    struct evr_file c;
    if(evr_connect_to_storage(&c) != evr_ok){
        goto out;
    }
    if(evr_fetch_xml(doc, &c, blob_ref) != evr_ok){
        goto out_with_close_c;
    }
    ret = evr_ok;
 out_with_close_c:
    if(c.close(&c) != 0){
        evr_panic("Unable to close evr-glacier-storage connection");
        ret = evr_error;
    }
 out:
    return ret;
}

static int evr_connect_to_storage(struct evr_file *c){
    struct evr_auth_token_cfg *t_cfg;
    if(evr_find_auth_token(&t_cfg, cfg.auth_tokens, cfg.storage_host, cfg.storage_port) != evr_ok){
        log_error("No auth token found for server %s:%s", cfg.storage_host, cfg.storage_port);
        return evr_error;
    }
    if(evr_tls_connect_once(c, cfg.storage_host, cfg.storage_port, cfg.ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server %s:%s", cfg.storage_host, cfg.storage_port);
        return evr_error;
    }
    if(evr_write_auth_token(c, t_cfg->token) != evr_ok){
        if(c->close(c) != 0){
            evr_panic("Unable to close evr-glacier-storage connection");
        }
        return evr_error;
    }
    return evr_ok;
}

static void activate_main_widget(GApplication *app){
    GtkWidget *main_win = gtk_application_window_new(GTK_APPLICATION(app));
    // TODO
    gtk_widget_show_all(main_win);
}
