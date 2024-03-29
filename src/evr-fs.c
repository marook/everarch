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
#include <argp.h>
#include <string.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/extra.h>
#include <unistd.h>

#include "basics.h"
#include "configp.h"
#include "fs-inode.h"
#include "errors.h"
#include "logger.h"
#include "files.h"
#include "evr-glacier-client.h"
#include "evr-tls.h"
#include "evr-attr-index-client.h"
#include "seed-desc.h"
#include "claims.h"
#include "open-files.h"
#include "evr-fuse.h"

#define program_name "evr-fs"

const char *argp_program_version = " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " is a virtual file system to access evr files.\n\n"
    "TRANSFORMATION defines the transformation used to convert seed-description XML documents into a description of the virtual file system. TRANSFORMATION must use the prefix xslt:blob: followed by the blob ref which points to the XSLT transformation.";

static char args_doc[] = "TRANSFORMATION MOUNT_POINT";

#define arg_storage_host 256
#define arg_storage_port 257
#define arg_ssl_cert 258
#define arg_auth_token 259
#define arg_index_host 260
#define arg_index_port 261
#define arg_accepted_gpg_key 262
#define arg_allow_other 263
#define arg_log_path 264
#define arg_pid_path 265

#define max_traces_len 64

struct evr_fs_cfg {
    char *storage_host;
    char *storage_port;
    char *index_host;
    char *index_port;
    struct evr_auth_token_cfg *auth_tokens;
    struct evr_cert_cfg *ssl_certs;
    size_t traces_len;
    char *traces[max_traces_len];
    char *transformation;
    struct evr_fuse_cfg fuse;
    struct evr_verify_cfg verify;

    /**
     * uid of the owner of the virtual files and directories.
     */
    uid_t uid;

    /**
     * gid of the owner of the virtual files and directories.
     */
    gid_t gid;

    char *log_path;
};

struct evr_fs_cfg cfg;

static int running = 1;
static int online = 0;

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glacier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"index-host", arg_index_host, "HOST", 0, "The hostname of the evr-attr-index server to connect to. Default hostname is " evr_attr_index_host "."},
    {"index-port", arg_index_port, "PORT", 0, "The port of the evr-attr-index server to connect to. Default port is " to_string(evr_attr_index_port) "."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of the server. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"auth-token", arg_auth_token, "HOST:PORT:TOKEN", 0, "A hostname, port and authorization token which is presented to the server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {"trace", 'T', "T", 0, "Trace of the produced seed-description set. May be specified multiple times for multiple traces. No more than " to_string(max_traces_len) " traces are allowed right now."},
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"single-thread", 's', NULL, 0, "The fuse layer will be single threaded."},
    {"oallow-other", arg_allow_other, NULL, 0, "The file system will be accessible by other users. Requires the user_allow_other option to be set in the global fuse configuration."},
    {"accepted-gpg-key", arg_accepted_gpg_key, "FINGERPRINT", 0, "A GPG key fingerprint of claim signatures which will be accepted as valid. Can be specified multiple times to accept multiple keys. You can call 'gpg --list-public-keys' to see your known keys."},
    {"log", arg_log_path, "FILE", 0, "A file to which log output messages will be appended. By default logs are written to stdout."},
    {"pid", arg_pid_path, "FILE", 0, "A file to which the daemon's pid is written."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_fs_cfg *cfg = (struct evr_fs_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'T':
        if(cfg->traces_len == static_len(cfg->traces)){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->traces[cfg->traces_len] = strdup(arg);
        if(!cfg->traces[cfg->traces_len]){
            return ARGP_ERR_UNKNOWN;
        }
        cfg->traces_len += 1;
        break;
    case 'f':
        cfg->fuse.foreground = 1;
        break;
    case 's':
        cfg->fuse.single_thread = 1;
        break;
    case arg_allow_other:
        cfg->fuse.allow_other = 1;
        break;
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
    case arg_accepted_gpg_key: {
        if(evr_verify_add_gpg_fpr(&cfg->verify, arg) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    }
    case arg_log_path:
        evr_replace_str(cfg->log_path, arg);
        break;
    case arg_pid_path:
        evr_replace_str(cfg->fuse.pid_path, arg);
        break;
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            evr_replace_str(cfg->transformation, arg);
            break;
        case 1:
            evr_replace_str(cfg->fuse.mount_point, arg);
            break;
        }
        break;
    case ARGP_KEY_END:
        if(state->arg_num != 2){
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

static xsltStylesheet *transformation;
static mtx_t inode_set_lock;
static struct evr_inode_set inode_set;
static struct evr_open_file_set open_files;

struct evr_index_watch_ctx {
    struct evr_file c;
    struct evr_buf_read *r;
    thrd_t worker;
};

int evr_connect_to_storage(struct evr_file *c, struct evr_fs_cfg *cfg, char *host, char *port);
int evr_connect_to_index(struct evr_file *c, struct evr_buf_read **r, struct evr_fs_cfg *cfg, char *host, char *port);
xsltStylesheet *load_transformation(struct evr_fs_cfg *cfg, struct evr_file *gc);
int evr_start_index_watch(void **arg);
int evr_free_index_watch(void *arg);
int evr_add_status_dir_inode(struct evr_inode_set *inode_set);
int evr_populate_inode_set(struct evr_buf_read *ir, struct evr_fs_cfg *cfg);

static void evr_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
static void evr_fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
static void evr_fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);

int main(int argc, char *argv[]) {
    int ret = 1;
    evr_log_app = "f";
    evr_init_basics();
    evr_tls_init();
    xmlInitParser();
    xsltRegisterAllExtras();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    evr_init_signatures();
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.index_host = strdup(evr_attr_index_host);
    cfg.index_port = strdup(to_string(evr_attr_index_port));
    cfg.auth_tokens = NULL;
    cfg.ssl_certs = NULL;
    cfg.traces_len = 0;
    cfg.fuse.foreground = 0;
    cfg.fuse.single_thread = 0;
    cfg.fuse.allow_other = 0;
    cfg.transformation = NULL;
    cfg.fuse.mount_point = NULL;
    cfg.uid = getuid();
    cfg.gid = getgid();
    cfg.log_path = NULL;
    cfg.fuse.pid_path = NULL;
    evr_init_verify_cfg(&cfg.verify);
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
    if(evr_setup_log(cfg.log_path) != evr_ok){
        goto out_with_free_cfg;
    }
    if(evr_verify_cfg_parse(&cfg.verify) != evr_ok){
        goto out_with_free_cfg;
    }
    {
        struct evr_file gc;
        if(evr_connect_to_storage(&gc, &cfg, cfg.storage_host, cfg.storage_port) != evr_ok){
            goto out_with_free_cfg;
        }
        transformation = load_transformation(&cfg, &gc);
        if(gc.close(&gc) != 0){
            evr_panic("Unable to close connection to evr-glacier-storage");
            goto out_with_free_transformation;
        }
    }
    if(!transformation){
        goto out_with_free_cfg;
    }
    if(mtx_init(&inode_set_lock, mtx_recursive) != thrd_success){
        goto out_with_free_transformation;
    }
    if(evr_init_inode_set(&inode_set) != evr_ok){
        goto out_with_destroy_inode_set_lock;
    }
    if(evr_add_status_dir_inode(&inode_set) != evr_ok){
        goto out_with_empty_inode_set;
    }
    {
        struct evr_file ic;
        struct evr_buf_read *ir = NULL;
        if(evr_connect_to_index(&ic, &ir, &cfg, cfg.index_host, cfg.index_port) != evr_ok){
            goto out_with_empty_inode_set;
        }
        int populate_res = evr_populate_inode_set(ir, &cfg);
        if(ir){
            evr_free_buf_read(ir);
            if(ic.close(&ic) != 0){
                evr_panic("Unable to close evr-attr-index connection");
                goto out_with_empty_inode_set;
            }
        }
        if(populate_res != evr_ok){
            goto out_with_empty_inode_set;
        }
    }
    if(evr_init_open_file_set(&open_files) != evr_ok){
        goto out_with_empty_inode_set;
    }
    cfg.fuse.ops.lookup = evr_fs_lookup;
    cfg.fuse.ops.getattr = evr_fs_getattr;
    cfg.fuse.ops.readdir = evr_fs_readdir;
    cfg.fuse.ops.open = evr_fs_open;
    cfg.fuse.ops.release = evr_fs_release;
    cfg.fuse.ops.read = evr_fs_read;
    cfg.fuse.setup = evr_start_index_watch;
    cfg.fuse.teardown = evr_free_index_watch;
    if(evr_run_fuse(argv[0], &cfg.fuse) != evr_ok){
        goto out_with_empty_open_file_set;
    }
    ret = 0;
 out_with_empty_open_file_set:
    if(evr_empty_open_file_set(&open_files) != evr_ok){
        ret = 1;
    }
 out_with_empty_inode_set:
    evr_empty_inode_set(&inode_set);
 out_with_destroy_inode_set_lock:
    mtx_destroy(&inode_set_lock);
 out_with_free_transformation:
    if(transformation){
        xsltFreeStylesheet(transformation);
    }
 out_with_free_cfg:
    do {
        void *tbfree[] = {
            cfg.storage_host,
            cfg.storage_port,
            cfg.index_host,
            cfg.index_port,
            cfg.transformation,
            cfg.fuse.mount_point,
            cfg.log_path,
            cfg.fuse.pid_path,
        };
        void **tbfree_end = &tbfree[static_len(tbfree)];
        for(void **it = tbfree; it != tbfree_end; ++it){
            free(*it);
        }
    } while(0);
    for(size_t i = 0; i < cfg.traces_len; ++i){
        free(cfg.traces[i]);
    }
    evr_free_auth_token_chain(cfg.auth_tokens);
    evr_free_cert_chain(cfg.ssl_certs);
    evr_free_verify_cfg(&cfg.verify);
    xsltCleanupGlobals();
    xmlCleanupParser();
    evr_tls_free();
    if(evr_teardown_log() != evr_ok){
        ret = 1;
    }
    return ret;
}

int evr_connect_to_storage(struct evr_file *c, struct evr_fs_cfg *cfg, char *host, char *port){
    struct evr_auth_token_cfg *t_cfg;
    if(evr_find_auth_token(&t_cfg, cfg->auth_tokens, host, port) != evr_ok){
        log_error("No auth token found for server %s:%s", host, port);
        return evr_error;
    }
    if(evr_tls_connect_once(c, host, port, cfg->ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-glacier-storage server %s:%s", host, port);
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

int evr_connect_to_index(struct evr_file *c, struct evr_buf_read **r, struct evr_fs_cfg *cfg, char *host, char *port){
    struct evr_auth_token_cfg *t_cfg;
    if(evr_find_auth_token(&t_cfg, cfg->auth_tokens, host, port) != evr_ok){
        log_error("No auth token found for server %s:%s", host, port);
        goto fail;
    }
    if(evr_tls_connect_once(c, host, port, cfg->ssl_certs) != evr_ok){
        log_error("Failed to connect to evr-attr-index server %s:%s", host, port);
        goto fail;
    }
    *r = evr_create_buf_read(c, 12);
    if(!*r){
        goto fail_with_close_c;
    }
    if(evr_attri_write_auth_token(c, t_cfg->token) != evr_ok){
        goto fail_with_free_r;
    }
    return evr_ok;
 fail_with_free_r:
    evr_free_buf_read(*r);
 fail_with_close_c:
    if(c->close(c) != 0){
        evr_panic("Unable to close evr-attr-index connection");
    }
 fail:
    return evr_error;
}

xsltStylesheet *load_transformation(struct evr_fs_cfg *cfg, struct evr_file *gc){
    log_debug("Loading transformation %s", cfg->transformation);
    const char prefix[] = "xslt:blob:";
    if(strncmp(prefix, cfg->transformation, sizeof(prefix) - 1) != 0){
        log_error("Transformation argument is missing prefix %s", prefix);
        return NULL;
    }
    char *blob_ref_str = &cfg->transformation[sizeof(prefix) - 1];
    evr_blob_ref blob_ref;
    if(evr_parse_blob_ref(blob_ref, blob_ref_str) != evr_ok){
        log_error("Syntax error in transformation's blob ref: %s", blob_ref_str);
        return NULL;
    }
    xsltStylesheet *style;
    if(evr_fetch_stylesheet(&style, gc, blob_ref) != evr_ok){
        return NULL;
    }
    return style;
}

int evr_add_status_dir_inode(struct evr_inode_set *inode_set){
    char online_path[] = ".evr/online";
    fuse_ino_t online_ino = evr_inode_set_create_file(inode_set, online_path);
    if(online_ino == 0){
        return evr_error;
    }
    struct evr_inode *online_nd = &inode_set->inodes[online_ino];
    online_nd->type = evr_inode_type_status_online;
    return evr_ok;
}

struct evr_populate_inode_set_ctx {
    struct evr_file ic;
    struct evr_buf_read *ir;
};

// TODO adjust name so that it better represents the fact that is is called from two different places
int evr_populate_inode_set_visit_seed(void *ctx, evr_claim_ref seed);

int evr_populate_inode_set(struct evr_buf_read *ir, struct evr_fs_cfg *cfg){
    int ret = evr_error;
    struct evr_populate_inode_set_ctx ctx;
    ctx.ir = NULL;
    if(evr_connect_to_index(&ctx.ic, &ctx.ir, cfg, cfg->index_host, cfg->index_port) != evr_ok){
        goto out;
    }
    // TODO add 'at' timestamp
    if(evr_attri_search(ir, "", evr_populate_inode_set_visit_seed, NULL, &ctx) != evr_ok){
        goto out_with_close_ctx_ic;
    }
    ret = evr_ok;
 out_with_close_ctx_ic:
    if(ctx.ir){
        evr_free_buf_read(ctx.ir);
        if(ctx.ic.close(&ctx.ic) != 0){
            evr_panic("Unable to close evr-attr-index connection");
            ret = evr_error;
        }
    }
 out:
    return ret;
}

xmlDoc *evr_seed_desc_to_file_set(xmlDoc *doc, evr_claim_ref seed);

int evr_collect_dependent_seeds(xmlDoc *doc, size_t *dependent_seeds_len, evr_claim_ref **dependent_seeds, evr_claim_ref seed);

int evr_populate_inode_set_visit_seed(void *_ctx, evr_claim_ref seed){
    int ret = evr_error;
    struct evr_populate_inode_set_ctx *ctx = _ctx;
#ifdef EVR_LOG_DEBUG
    {
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_debug("Populating inodes with seed %s", seed_str);
    }
#endif
    xmlDoc *desc_doc;
    if(evr_seed_desc_build(&desc_doc, ctx->ir, seed, cfg.traces_len, cfg.traces) != evr_ok){
        goto out;
    }
    xmlDoc *files_doc = evr_seed_desc_to_file_set(desc_doc, seed);
    if(!files_doc){
        goto out_with_free_desc_doc;
    }
    xmlNode *file_set = evr_get_root_file_set(files_doc);
    if(!file_set){
#ifdef EVR_LOG_DEBUG
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_debug("Transformation of seed %s did not produce file-set. Skipping the seed.", seed_str);
#endif
        ret = evr_ok;
        goto out_with_free_files_doc;
    }
    size_t dependent_seeds_len = 0;
    evr_claim_ref *dependent_seeds = NULL;
    if(evr_collect_dependent_seeds(desc_doc, &dependent_seeds_len, &dependent_seeds, seed) != evr_ok){
        goto out_with_free_files_doc;
    }
    if(mtx_lock(&inode_set_lock) != thrd_success){
        goto out_with_free_dependent_seeds;
    }
    evr_inode_remove_by_seed(inode_set.inodes, inode_set.inodes_len, seed);
    evr_claim_ref *ds = NULL;
    for(xmlNode *fn = evr_first_file_node(file_set); fn; fn = evr_next_file_node(fn)){
        struct evr_fs_file *f = evr_parse_fs_file(fn);
        if(!f){
            evr_claim_ref_str seed_str;
            evr_fmt_claim_ref(seed_str, seed);
            char *fn_str = evr_format_xml_node(fn);
            log_error("Ignoring unable to parse XML file node based on seed %s: %s", seed_str, fn_str);
            free(fn_str);
	    continue;
        }
        if(dependent_seeds_len > 0){
            size_t size = evr_claim_ref_size * dependent_seeds_len;
            ds = malloc(size);
            if(!ds){
                evr_free_fs_file(f);
                goto out_with_unlock_inode_set_lock;
            }
            memcpy(ds, dependent_seeds, size);
        }
#ifdef EVR_LOG_DEBUG
        {
            evr_claim_ref_str seed_str;
            evr_fmt_claim_ref(seed_str, seed);
            evr_claim_ref_str file_ref_str;
            evr_fmt_claim_ref(file_ref_str, f->file_ref);
            log_debug("Adding file \"%s\" with size %zu and content %s for seed %s", f->path, f->size, file_ref_str, seed_str);
        }
#endif
        fuse_ino_t ino = evr_inode_set_create_file(&inode_set, f->path);
        if(ino == 0){
            evr_free_fs_file(f);
            free(ds);
            goto out_with_unlock_inode_set_lock;
        }
        struct evr_inode *nd = &inode_set.inodes[ino];
        nd->created = f->created;
        nd->last_modified = f->last_modified;
        nd->data.file.file_size = f->size;
        memcpy(nd->data.file.file_ref, f->file_ref, evr_claim_ref_size);
        memcpy(nd->data.file.seed, seed, evr_claim_ref_size);
        nd->data.file.dependent_seeds_len = dependent_seeds_len;
        nd->data.file.dependent_seeds = ds;
        evr_free_fs_file(f);
    }
    ret = evr_ok;
 out_with_unlock_inode_set_lock:
    if(mtx_unlock(&inode_set_lock) != thrd_success){
        evr_panic("Unable to unlock inode_set_lock");
        ret = evr_error;
    }
 out_with_free_dependent_seeds:
    free(dependent_seeds);
 out_with_free_files_doc:
    xmlFreeDoc(files_doc);
 out_with_free_desc_doc:
    xmlFreeDoc(desc_doc);
 out:
    {
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_debug("Populated inodes with seed %s and result %d", seed_str, ret);
    }
    return ret;
}

int evr_collect_dependent_seeds(xmlDoc *doc, size_t *_dependent_seeds_len, evr_claim_ref **_dependent_seeds, evr_claim_ref seed){
    xmlNode *sds = xmlDocGetRootElement(doc);
    if(!evr_is_evr_element(sds, "seed-description-set", evr_seed_desc_ns)){
        goto fail;
    }
    size_t dependent_seeds_len = 0;
    xmlNode *sd = sds->children;
    while(1){
        sd = evr_find_next_element(sd, "seed-description", evr_seed_desc_ns);
        if(!sd){
            break;
        }
        char *seed_val = (char*)xmlGetProp(sd, BAD_CAST "seed");
        if(!seed_val){
            goto fail;
        }
        evr_claim_ref sd_seed;
        int parse_res = evr_parse_claim_ref(sd_seed, seed_val);
        xmlFree(seed_val);
        if(parse_res != evr_ok){
            goto fail;
        }
        if(evr_cmp_claim_ref(seed, sd_seed) != 0){
            ++dependent_seeds_len;
        }
        sd = sd->next;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_debug("Found %zu dependent seeds for seed %s", dependent_seeds_len, seed_str);
    }
#endif
    size_t next_dependent_seed_index = 0;
    evr_claim_ref *dependent_seeds = malloc(evr_claim_ref_size * dependent_seeds_len);
    if(!dependent_seeds){
        goto fail;
    }
    sd = sds->children;
    while(1){
        sd = evr_find_next_element(sd, "seed-description", evr_seed_desc_ns);
        if(!sd){
            break;
        }
        char *seed_val = (char*)xmlGetProp(sd, BAD_CAST "seed");
        if(!seed_val){
            goto fail_with_free_dependent_seeds;
        }
        evr_claim_ref sd_seed;
        int parse_res = evr_parse_claim_ref(sd_seed, seed_val);
        xmlFree(seed_val);
        if(parse_res != evr_ok){
            goto fail_with_free_dependent_seeds;
        }
        if(evr_cmp_claim_ref(seed, sd_seed) != 0){
            memcpy(&dependent_seeds[next_dependent_seed_index++], sd_seed, evr_claim_ref_size);
        }
        sd = sd->next;
    }
    *_dependent_seeds_len = dependent_seeds_len;
    *_dependent_seeds = dependent_seeds;
    return evr_ok;
 fail_with_free_dependent_seeds:
    free(dependent_seeds);
 fail:
    return evr_error;
}

xmlDoc *evr_seed_desc_to_file_set(xmlDoc *seed_desc_doc, evr_claim_ref seed){
    const char *xslt_params[] = {
        NULL
    };
    xmlDoc *file_set_doc = xsltApplyStylesheet(transformation, seed_desc_doc, xslt_params);
    if(!file_set_doc){
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_error("Unable to transform seed-description XML to file-set XML for seed %s", seed_str);
        return NULL;
    }
    return file_set_doc;
}

void evr_lock_inode_set_or_panic(void);
void evr_unlock_inode_set_or_panic(void);
struct evr_inode *evr_get_inode(fuse_req_t req, fuse_ino_t ino);
int evr_fs_stat(fuse_req_t req, struct stat *st, fuse_ino_t ino);

static void evr_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name){
    log_debug("fuse request %p lookup with parent inode %d the name %s", req, (int)parent, name);
    evr_lock_inode_set_or_panic();
    struct evr_inode *pnd = evr_get_inode(req, parent);
    if(!pnd){
        if(fuse_reply_err(req, ENOENT) != 0){
            evr_panic("fuse request %p unable to report error on get inode %d", req, (int)parent);
        }
        goto out_with_unlock_inode_set;
    }
    if(pnd->type != evr_inode_type_dir){
        log_error("fuse request %p detected inode %d is not a directory", req, (int)parent);
        if(fuse_reply_err(req, ENOTDIR) != 0){
            evr_panic("fuse request %p unable to report lookup ENOTDIR error for name %s", req, name);
        }
        goto out_with_unlock_inode_set;
    }
    struct evr_inode_dir *dir = &pnd->data.dir;
    fuse_ino_t *c_end = &dir->children[dir->children_len];
    for(fuse_ino_t *c = dir->children; c != c_end; ++c){
        struct evr_inode *cnd = &inode_set.inodes[*c];
        if(strcmp(name, cnd->name) != 0){
            continue;
        }
        struct fuse_entry_param e = { 0 };
        e.ino = *c;
        e.attr_timeout = 1.0;
        e.entry_timeout = 1.0;
        // TODO we should call a version of evr_fs_stat here which
        // does not lock inode_set_lock itself. inode_set_lock is
        // already locked by us. if we achieve this we may make the
        // inode_set_lock mtx_plain again instead of mtx_recursive.
        if(evr_fs_stat(req, &e.attr, *c) != evr_ok){
            // error has been reported by evr_fs_stat
            goto out_with_unlock_inode_set;
        }
        log_debug("fuse request %p responds child inode %d", req, (int)*c);
        if(fuse_reply_entry(req, &e) != 0){
            evr_panic("fuse request %p unable to reply entry", req);
        }
        goto out_with_unlock_inode_set;
    }
    log_debug("fuse request %p did not find matching child", req);
    if(fuse_reply_err(req, ENOENT) != 0){
        evr_panic("fuse request %p unable to report lookup ENOENT error for name %s", req, name);
    }
 out_with_unlock_inode_set:
    evr_unlock_inode_set_or_panic();
}

static void evr_fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    log_debug("fuse getattr with inode %d", (int)ino);
    evr_lock_inode_set_or_panic();
    struct stat st;
    if(evr_fs_stat(req, &st, ino) != evr_ok){
        // error has been reported by evr_fs_stat
        goto out_with_unlock_inode_set;
    }
    if(fuse_reply_attr(req, &st, 1.0) != 0){
        evr_panic("Unable to report reply for attr with inode %d", (int)ino);
    }
 out_with_unlock_inode_set:
    evr_unlock_inode_set_or_panic();
}

static struct stat stat_init = { 0 };

int evr_fs_stat(fuse_req_t req, struct stat *st, fuse_ino_t ino){
    struct evr_inode *nd = evr_get_inode(req, ino);
    if(!nd){
        if(fuse_reply_err(req, ENOENT) != 0){
            evr_panic("Unable to report error on get inode %d", (int)ino);
        }
        return evr_error;
    }
    *st = stat_init;
    switch(nd->type){
    default:
        evr_panic("Unknown node type %d", nd->type);
        return evr_error;
    case evr_inode_type_dir:
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 1;
        break;
    case evr_inode_type_file:
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = nd->data.file.file_size;
        break;
    case evr_inode_type_status_online:
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = 1;
        break;
    }
    st->st_ino = ino;
    st->st_uid = cfg.uid;
    st->st_gid = cfg.gid;
    evr_time_to_timespec(&st->st_mtim, &nd->last_modified);
    evr_time_to_timespec(&st->st_ctim, &nd->created);
    return evr_ok;
}

#define evr_add_direntry(name, child_ino)                               \
    do {                                                                \
        st.st_ino = child_ino;                                          \
        size_t entry_size = fuse_add_direntry(req, NULL, 0, name, &st, 0); \
        size_t min_buf_size = buf->size_used + entry_size;              \
        if(min_buf_size > buf->size_allocated){                         \
            buf = grow_dynamic_array_at_least(buf, min_buf_size);       \
            if(!buf){                                                   \
                goto fail;                                              \
            }                                                           \
        }                                                               \
        buf->size_used += fuse_add_direntry(req, &buf->data[buf->size_used], buf->size_allocated - buf->size_used, name, &st, buf->size_used + entry_size); \
    } while(0)

static void evr_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    int err = EINVAL;
    log_debug("fuse readdir with inode %d (size %zu, off %zu)", (int)ino, size, off);
    evr_lock_inode_set_or_panic();
    struct evr_inode *nd = evr_get_inode(req, ino);
    if(nd->type != evr_inode_type_dir){
        log_error("Inode %d is not a directory", (int)ino);
        err = ENOTDIR;
        goto fail;
    }
    struct dynamic_array *buf = alloc_dynamic_array(0);
    if(!buf){
        goto fail;
    }
    struct stat st = { 0 };
    evr_add_direntry(".", ino);
    evr_add_direntry("..", nd->parent);
    struct evr_inode_dir *dir = &nd->data.dir;
    fuse_ino_t *c_end = &dir->children[dir->children_len];
    for(fuse_ino_t *c = dir->children; c != c_end; ++c){
        struct evr_inode *cnd = &inode_set.inodes[*c];
        evr_add_direntry(cnd->name, *c);
    }
    if((size_t)off >= buf->size_used){
        if(fuse_reply_buf(req, NULL, 0) != 0){
            goto failed_reply;
        }
    } else {
        if(fuse_reply_buf(req, &buf->data[off], min(buf->size_used - off, size)) != 0){
            goto failed_reply;
        }
    }
    free(buf);
    evr_unlock_inode_set_or_panic();
    return;
 fail:
    if(fuse_reply_err(req, err) != 0){
        evr_panic("Unable to report error %d on readdir", err);
    }
    evr_unlock_inode_set_or_panic();
    return;
 failed_reply:
    free(buf);
    evr_unlock_inode_set_or_panic();
    evr_panic("Failed to reply readdir for inode %d", (int)ino);
}

#undef evr_add_direntry

static int evr_fs_open_file(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, evr_claim_ref file_ref);

static void evr_fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    int err = EINVAL;
    log_debug("fuse open inode %d", (int)ino);
    evr_lock_inode_set_or_panic();
    struct evr_inode *nd = evr_get_inode(req, ino);
    switch(nd->type){
    default:
        log_error("Inode %d is not a file", (int)ino);
        err = EISDIR;
        evr_unlock_inode_set_or_panic();
        goto fail;
    case evr_inode_type_file: {
        evr_claim_ref file_ref;
        memcpy(file_ref, nd->data.file.file_ref, evr_claim_ref_size);
        evr_unlock_inode_set_or_panic();
        if(evr_fs_open_file(req, ino, fi, file_ref) != evr_ok){
            goto fail;
        }
        break;
    }
    case evr_inode_type_status_online:
        evr_unlock_inode_set_or_panic();
        if(fuse_reply_open(req, fi) != 0){
            goto fail;
        }
        break;
    }
    return;
 fail:
    if(fuse_reply_err(req, err) != 0){
        evr_panic("Unable to report error %d on open", err);
    }
    log_debug("fuse open inode %d failed with error %d", err);
}

static int evr_fs_open_file(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, evr_claim_ref file_ref){
    int res, ret = evr_error;
    if(evr_allocate_open_file(&open_files, &fi->fh) != evr_ok){
        log_error("Unable to allocate file handle for inode %d", (int)ino);
        goto fail;
    }
    struct evr_open_file *of = &open_files.files[fi->fh];
    if(evr_connect_to_storage(&of->gc, &cfg, cfg.storage_host, cfg.storage_port) != evr_ok){
        log_error("Unable to connect to glacier when opening file with inode %d", (int)ino);
        goto fail_with_close_open_file;
    }
    res = evr_fetch_file_claim(&of->claim, &of->gc, file_ref, cfg.verify.ctx, NULL);
    if(res == evr_not_found || res == evr_user_data_invalid){
        ret = res;
        goto fail_with_close_open_file;
    } else if(res != evr_ok){
        log_error("Unable to fetch file claim for inode %d", (int)ino);
        goto fail_with_close_open_file;
    }
    if(fuse_reply_open(req, fi) != 0){
        goto fail_with_close_open_file;
    }
    ret = evr_ok;
    log_debug("opened file handle %u for inode %d", (unsigned int)fi->fh, (int)ino);
    return ret;
 fail_with_close_open_file:
    if(evr_close_open_file(&open_files, fi->fh) != evr_ok){
        evr_panic("Unable to close file with inode %d on failed open", (int)ino);
    }
 fail:
    return ret;
}

void evr_lock_inode_set_or_panic(void){
    if(mtx_lock(&inode_set_lock) != thrd_success){
        evr_panic("Unable to lock inode set");
    }
}

void evr_unlock_inode_set_or_panic(void){
    if(mtx_unlock(&inode_set_lock) != thrd_success){
        evr_panic("Unable to unlock inode set.");
    }
}

static int evr_fs_release_file(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);

static void evr_fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    log_debug("fuse release file handle %u for inode %d", (unsigned int)fi->fh, (int)ino);
    evr_lock_inode_set_or_panic();
    struct evr_inode *nd = evr_get_inode(req, ino);
    switch(nd->type){
    default:
        evr_unlock_inode_set_or_panic();
        evr_panic("Unexpected inode type %d on release", nd->type);
        goto fail;
    case evr_inode_type_file:
        evr_unlock_inode_set_or_panic();
        if(evr_fs_release_file(req, ino, fi) != evr_ok){
            goto fail;
        }
        break;
    case evr_inode_type_status_online:
        evr_unlock_inode_set_or_panic();
        if(fuse_reply_err(req, 0) != 0){
            goto fail;
        }
        break;
    }
    log_debug("fuse file handle %u released", (unsigned int)fi->fh);
    return;
 fail:
    if(fuse_reply_err(req, EINVAL) != 0){
        evr_panic("Unable to report error on release");
    }
    log_debug("fuse release file handle %u failed", (unsigned int)fi->fh);
}

static int evr_fs_release_file(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    if(evr_close_open_file(&open_files, fi->fh) != evr_ok){
        return evr_error;
    }
    if(fuse_reply_err(req, 0) != 0){
        evr_panic("Unable to report successful release of file handle %u", (unsigned int)fi->fh);
        return evr_error;
    }
    return evr_ok;
}

static int evr_fs_read_file(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);

static int evr_fs_read_status_online(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);

static void evr_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    int err = EINVAL;
    log_debug("fuse read %zu bytes from file handle %u on inode %d at offset %zu", size, (unsigned int)fi->fh, (int)ino, (size_t)off);
    evr_lock_inode_set_or_panic();
    struct evr_inode *nd = evr_get_inode(req, ino);
    switch(nd->type){
    default:
        evr_unlock_inode_set_or_panic();
        evr_panic("Unexpected inode type %d on release", nd->type);
        goto fail;
    case evr_inode_type_file:
        evr_unlock_inode_set_or_panic();
        if(evr_fs_read_file(req, ino, size, off, fi) != evr_ok){
            goto fail;
        }
        break;
    case evr_inode_type_status_online:
        evr_unlock_inode_set_or_panic();
        if(evr_fs_read_status_online(req, ino, size, off, fi) != evr_ok){
            goto fail;
        }
        break;
    }
    return;
 fail:
    if(fuse_reply_err(req, err) != 0){
        evr_panic("Unable to report error %d on read file handle %u on inode %d", err, (unsigned int)fi->fh, (int)ino);
    }
    log_debug("fuse read file handle %u on inode %d failed", (unsigned int)fi->fh, (int)ino);
}

static int evr_fs_read_status_online(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    if(off == 0){
        char buf[1];
        buf[0] = online ? '1' : '0';
        if(fuse_reply_buf(req, buf, sizeof(buf)) != 0){
            return evr_error;
        }
    } else {
        if(fuse_reply_buf(req, NULL, 0) != 0){
            return evr_error;
        }
    }
    return evr_ok;
}

static int evr_fs_read_file(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    char *buf = malloc(size);
    if(!buf){
        goto fail;
    }
    struct evr_open_file *f = &open_files.files[fi->fh];
    size_t read_size = size;
    if(evr_open_file_read(f, buf, &read_size, off) != evr_ok){
        goto fail_with_free_buf;
    }
    if(fuse_reply_buf(req, buf, read_size) != 0){
        goto fail_with_free_buf;
    }
    free(buf);
    return evr_ok;
 fail_with_free_buf:
    free(buf);
 fail:
    return evr_error;
}

struct evr_inode *evr_get_inode(fuse_req_t req, fuse_ino_t ino){
    if(ino < FUSE_ROOT_ID || ino >= inode_set.inodes_len){
        log_debug("fuse request %p readdir failed because inode %d out of bounds", req, (int)ino);
        return NULL;
    }
    struct evr_inode *nd = &inode_set.inodes[ino];
    if(nd->type == evr_inode_type_unlinked){
        log_debug("fuse request %p readdir failed because inode %d is unlinked", req, (int)ino);
        return NULL;
    }
    return nd;
}

int evr_index_watch_worker(void *_ctx);

int evr_start_index_watch(void **arg){
    struct evr_index_watch_ctx **ctx = (struct evr_index_watch_ctx**)arg;
    struct evr_index_watch_ctx *c;
    c = malloc(sizeof(struct evr_index_watch_ctx));
    if(!c){
        goto fail;
    }
    if(evr_connect_to_index(&c->c, &c->r, &cfg, cfg.index_host, cfg.index_port) != evr_ok){
        goto fail_with_free_c;
    }
    if(evr_attri_write_watch(&c->c) != evr_ok){
        goto fail_with_close_c;
    }
    online = 1;
    if(thrd_create(&c->worker, evr_index_watch_worker, c) != thrd_success){
        goto fail_with_close_c;
    }
    *ctx = c;
    return evr_ok;
 fail_with_close_c:
    evr_free_buf_read(c->r);
    if(c->c.close(&c->c) != 0){
        evr_panic("Unable to close evr-attr-index connection");
    }
 fail_with_free_c:
    free(c);
 fail:
    return evr_error;
}

int evr_index_watch_worker_visit_changed_seed(void *ctx, evr_blob_ref index_ref, evr_claim_ref seed, evr_time last_modified);

int is_running(void);

int evr_index_watch_worker(void *_ctx){
    int ret = evr_error;
    struct evr_index_watch_ctx *ctx = _ctx;
    log_debug("Start processing index watch responses");
    while(running){
        int watch_res = evr_attri_read_watch(ctx->r, evr_index_watch_worker_visit_changed_seed, ctx);
        online = 0;
        if(watch_res != evr_ok){
            goto out;
        }
        if(running){
            log_error("evr-attr-index watch connection lost");
        }
        int failed_retries = 0;
        while(running){
            int delay_res = evr_back_off_delay(failed_retries, is_running);
            if(delay_res == evr_end){
                break;
            } else if(delay_res != evr_ok){
                goto out;
            }
            log_debug("evr-attr-index watch reconnect try %d", failed_retries);
            if(evr_connect_to_index(&ctx->c, &ctx->r, &cfg, cfg.index_host, cfg.index_port) != evr_ok){
                log_debug("evr-attr-index watch reconnect try %d connect failed", failed_retries);
                ++failed_retries;
                continue;
            }
            if(evr_attri_write_watch(&ctx->c) != evr_ok){
                log_debug("evr-attr-index watch reconnect try %d watch failed", failed_retries);
                ++failed_retries;
                if(ctx->c.close(&ctx->c) != 0){
                    evr_panic("Unable to close evr-attr-index connection");
                }
                continue;
            }
            online = 1;
            log_info("evr-attr-index watch reconnected");
            break;
        }
    }
    log_debug("End processing index watch responses");
    ret = evr_ok;
 out:
    log_debug("Index watch worker ended with result %d", ret);
    return ret;
}

int is_running(void){
    return running;
}

int evr_collect_affected_seeds(struct evr_llbuf_s *affected_seeds, evr_claim_ref seed);

int evr_index_watch_worker_visit_changed_seed(void *ctx, evr_blob_ref index_ref, evr_claim_ref seed, evr_time last_modified){
    int ret = evr_error;
#ifdef EVR_LOG_DEBUG
    {
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_debug("Seed %s has changed in evr-attr-index", seed_str);
    }
#endif
    struct evr_llbuf_s affected_seeds;
    evr_init_llbuf_s(&affected_seeds, evr_claim_ref_size);
    if(evr_collect_affected_seeds(&affected_seeds, seed) != evr_ok){
        goto out;
    }
    struct evr_populate_inode_set_ctx inode_ctx;
    inode_ctx.ir = NULL;
    if(evr_connect_to_index(&inode_ctx.ic, &inode_ctx.ir, &cfg, cfg.index_host, cfg.index_port) != evr_ok){
        goto out_with_free_affected_seeds;
    }
    struct evr_llbuf_s_iter s_it;
    evr_init_llbuf_s_iter(&s_it, &affected_seeds);
    while(1){
        evr_claim_ref *s = evr_llbuf_s_iter_next(&s_it);
        if(!s){
            break;
        }
        if(evr_populate_inode_set_visit_seed(&inode_ctx, *s) != evr_ok){
            goto out_with_close_ir;
        }
    }
    ret = evr_ok;
 out_with_close_ir:
    if(inode_ctx.ir){
        evr_free_buf_read(inode_ctx.ir);
        if(inode_ctx.ic.close(&inode_ctx.ic) != 0){
            evr_panic("Unable to close evr-attr-index connection");
            ret = evr_error;
        }
    }
 out_with_free_affected_seeds:
    evr_llbuf_s_empty(&affected_seeds, NULL);
 out:
#ifdef EVR_LOG_DEBUG
    {
        evr_claim_ref_str seed_str;
        evr_fmt_claim_ref(seed_str, seed);
        log_debug("Seed %s update ended with status %d", seed_str, ret);
    }
#endif
    return ret;
}

int evr_collect_affected_seeds(struct evr_llbuf_s *affected_seeds, evr_claim_ref seed){
    int ret = evr_error;
    struct evr_llbuf_s affected_inodes;
    evr_init_llbuf_s(&affected_inodes, sizeof(fuse_ino_t));
    if(mtx_lock(&inode_set_lock) != thrd_success){
        goto out;
    }
    int collect_res = evr_collect_affected_inodes(&affected_inodes, &inode_set, seed);
    evr_unlock_inode_set_or_panic();
    if(collect_res != evr_ok){
        goto out;
    }
    struct evr_claim_ref_tiny_set *seed_set = evr_create_claim_ref_tiny_set(128);
    if(!seed_set){
        goto out_with_free_affected_inodes;
    }
    { // add root seed
        int add_res = evr_claim_ref_tiny_set_add(seed_set, seed);
        if(add_res != evr_ok){
            goto out_with_free_seed_set;
        }
        evr_claim_ref *s;
        if(evr_llbuf_s_append(affected_seeds, (void**)&s) != evr_ok){
            goto out_with_free_seed_set;
        }
        memcpy(*s, seed, evr_claim_ref_size);
    }
    struct evr_llbuf_s_iter ino_it;
    evr_init_llbuf_s_iter(&ino_it, &affected_inodes);
    evr_claim_ref *s;
    while(1){
        fuse_ino_t *ino = evr_llbuf_s_iter_next(&ino_it);
        if(!ino){
            break;
        }
        struct evr_inode *nd = &inode_set.inodes[*ino];
        int add_res = evr_claim_ref_tiny_set_add(seed_set, nd->data.file.seed);
        if(add_res == evr_exists){
            continue;
        }
        // else if add_res == evr_ok or evr_error we just continue. in
        // the case of evr_error we will add the seed multiple
        // times. that's not a big issue right now because it will
        // just lead to multiple inode recreations for that that
        // multiple seed.
        if(evr_llbuf_s_append(affected_seeds, (void**)&s) != evr_ok){
            goto out_with_free_seed_set;
        }
        memcpy(*s, nd->data.file.seed, evr_claim_ref_size);
    }
    ret = evr_ok;
 out_with_free_seed_set:
    evr_free_claim_ref_tiny_set(seed_set);
 out_with_free_affected_inodes:
    evr_llbuf_s_empty(&affected_inodes, NULL);
 out:
    return ret;
}

int evr_free_index_watch(void *arg){
    struct evr_index_watch_ctx *ctx = arg;
    int worker_res;
    running = 0;
    if(thrd_join(ctx->worker, &worker_res) != thrd_success){
        evr_panic("Unable to join index watch thread");
        return evr_error;
    }
    evr_free_buf_read(ctx->r);
    if(ctx->c.close(&ctx->c) != 0){
        evr_panic("Unable to close evr-attr-index connection");
        return evr_error;
    }
    free(ctx);
    return worker_res;
}
