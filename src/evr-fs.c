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
#include <fuse_lowlevel.h>
#include <argp.h>
#include <string.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>

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

struct evr_fs_cfg {
    char *storage_host;
    char *storage_port;
    char *index_host;
    char *index_port;
    struct evr_auth_token_cfg *auth_tokens;
    struct evr_cert_cfg *ssl_certs;
    /**
     * foreground's meaning is defined by the fuse -d option.
     */
    int foreground;
    /**
     * single_thread's meaning is defined by the fuse -s option.
     */
    int single_thread;
    /**
     * allow_other indicates if other users may access this file
     * system.
     */
    int allow_other;
    char *transformation;
    char *mount_point;

    /**
     * accepted_gpg_fprs contains the accepted gpg fingerprints for
     * signed claims.
     *
     * The llbuf data points to a fingerprint string.
     *
     * This field is only filled during the initialization of the
     * application. During runtime verify_ctx should be used.
     */
    struct evr_llbuf *accepted_gpg_fprs;

    struct evr_verify_ctx *verify_ctx;
};

struct evr_fs_cfg cfg;

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glacier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"index-host", arg_index_host, "HOST", 0, "The hostname of the evr-attr-index server to connect to. Default hostname is " evr_attr_index_host "."},
    {"index-port", arg_index_port, "PORT", 0, "The port of the evr-attr-index server to connect to. Default port is " to_string(evr_attr_index_port) "."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of the server. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"auth-token", arg_auth_token, "HOST:PORT:TOKEN", 0, "A hostname, port and authorization token which is presented to the server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"single-thread", 's', NULL, 0, "The fuse layer will be single threaded."},
    {"oallow-other", arg_allow_other, NULL, 0, "The file system will be accessible by other users. Requires the user_allow_other option to be set in the global fuse configuration."},
    {"accepted-gpg-key", arg_accepted_gpg_key, "FINGERPRINT", 0, "A GPG key fingerprint of claim signatures which will be accepted as valid. Can be specified multiple times to accept multiple keys. You can call 'gpg --list-public-keys' to see your known keys."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_fs_cfg *cfg = (struct evr_fs_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'f':
        cfg->foreground = 1;
        break;
    case 's':
        cfg->single_thread = 1;
        break;
    case arg_allow_other:
        cfg->allow_other = 1;
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
        const size_t arg_size = strlen(arg) + 1;
        struct evr_buf_pos bp;
        if(evr_llbuf_prepend(&cfg->accepted_gpg_fprs, &bp, arg_size) != evr_ok){
            usage(state);
            return ARGP_ERR_UNKNOWN;
        }
        evr_push_n(&bp, arg, arg_size);
        break;
    }
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            evr_replace_str(cfg->transformation, arg);
            break;
        case 1:
            evr_replace_str(cfg->mount_point, arg);
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
static struct evr_inode_set inode_set;
static struct evr_open_file_set open_files;

int evr_connect_to_storage(struct evr_file *c, struct evr_fs_cfg *cfg, char *host, char *port);
int evr_connect_to_index(struct evr_file *c, struct evr_buf_read **r, struct evr_fs_cfg *cfg, char *host, char *port);
xsltStylesheet *load_transformation(struct evr_fs_cfg *cfg, struct evr_file *gc);
int evr_populate_inode_set(struct evr_buf_read *ir, struct evr_fs_cfg *cfg);
int run_fuse(char *program, struct evr_fs_cfg *cfg);

int main(int argc, char *argv[]) {
    int ret = 1;
    evr_log_app = "f";
    evr_init_basics();
    evr_tls_init();
    xmlInitParser();
    evr_init_signatures();
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.index_host = strdup(evr_attr_index_host);
    cfg.index_port = strdup(to_string(evr_attr_index_port));
    cfg.auth_tokens = NULL;
    cfg.ssl_certs = NULL;
    cfg.foreground = 0;
    cfg.single_thread = 0;
    cfg.allow_other = 0;
    cfg.transformation = NULL;
    cfg.mount_point = NULL;
    cfg.accepted_gpg_fprs = NULL;
    cfg.verify_ctx = NULL;
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
    cfg.verify_ctx = evr_build_verify_ctx(cfg.accepted_gpg_fprs);
    if(!cfg.verify_ctx){
        goto out_with_free_cfg;
    }
    evr_free_llbuf_chain(cfg.accepted_gpg_fprs, NULL);
    cfg.accepted_gpg_fprs = NULL;
    struct evr_file gc;
    if(evr_connect_to_storage(&gc, &cfg, cfg.storage_host, cfg.storage_port) != evr_ok){
        goto out_with_free_cfg;
    }
    transformation = load_transformation(&cfg, &gc);
    if(!transformation){
        goto out_with_close_gc;
    }
    if(evr_init_inode_set(&inode_set) != evr_ok){
        goto out_with_free_transformation;
    }
    struct evr_file ic;
    struct evr_buf_read *ir = NULL;
    if(evr_connect_to_index(&ic, &ir, &cfg, cfg.index_host, cfg.index_port) != evr_ok){
        goto out_with_empty_inode_set;
    }
    if(evr_populate_inode_set(ir, &cfg) != evr_ok){
        goto out_with_close_ic;
    }
    if(evr_init_open_file_set(&open_files) != evr_ok){
        goto out_with_close_ic;
    }
    if(run_fuse(argv[0], &cfg) != 0){
        goto out_with_empty_open_file_set;
    }
    ret = 0;
 out_with_empty_open_file_set:
    if(evr_empty_open_file_set(&open_files) != evr_ok){
        ret = 1;
    }
 out_with_close_ic:
    if(ir){
        evr_free_buf_read(ir);
        if(ic.close(&ic) != 0){
            evr_panic("Unable to close evr-attr-index connection");
            ret = evr_error;
        }
    }
 out_with_empty_inode_set:
    evr_empty_inode_set(&inode_set);
 out_with_free_transformation:
    xsltFreeStylesheet(transformation);
 out_with_close_gc:
    if(gc.close(&gc) != 0){
        evr_panic("Unable to close connection to evr-glacier-storage");
        ret = 1;
    }
 out_with_free_cfg:
    do {
        void *tbfree[] = {
            cfg.storage_host,
            cfg.storage_port,
            cfg.index_host,
            cfg.index_port,
            cfg.transformation,
            cfg.mount_point,
        };
        void **tbfree_end = &tbfree[sizeof(tbfree) / sizeof(void*)];
        for(void **it = tbfree; it != tbfree_end; ++it){
            free(*it);
        }
    } while(0);
    evr_free_auth_token_chain(cfg.auth_tokens);
    evr_free_cert_chain(cfg.ssl_certs);
    evr_free_llbuf_chain(cfg.accepted_gpg_fprs, NULL);
    if(cfg.verify_ctx){
        evr_free_verify_ctx(cfg.verify_ctx);
    }
    xsltCleanupGlobals();
    xmlCleanupParser();
    evr_tls_free();
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

int evr_populate_inode_set_visit_seed(void *ctx, evr_claim_ref seed);

struct evr_populate_inode_set_ctx {
    struct evr_file ic;
    struct evr_buf_read *ir;
};

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
    xmlNode *desc_node;
    if(evr_seed_desc_create_doc(&desc_doc, &desc_node, seed) != evr_ok){
        goto out;
    }
    if(evr_seed_desc_append_attrs(desc_doc, desc_node, ctx->ir, seed) != evr_ok){
        goto out_with_free_desc_doc;
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
    for(xmlNode *fn = evr_first_file_node(file_set); fn; fn = evr_next_file_node(fn)){
        struct evr_fs_file *f = evr_parse_fs_file(fn);
        if(!f){
            evr_claim_ref_str seed_str;
            evr_fmt_claim_ref(seed_str, seed);
            char *fn_str = evr_format_xml_node(fn);
            log_error("Unable to parse XML file node based on seed %s: %s", seed_str, fn_str);
            free(fn_str);
            goto out_with_free_files_doc;
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
            goto out_with_free_files_doc;
        }
        struct evr_fs_inode *nd = &inode_set.inodes[ino];
        nd->created = f->created;
        nd->last_modified = f->last_modified;
        nd->data.file.file_size = f->size;
        memcpy(nd->data.file.file_ref, f->file_ref, evr_claim_ref_size);
        memcpy(nd->data.file.seed, seed, evr_claim_ref_size);
        evr_free_fs_file(f);
    }
    ret = evr_ok;
 out_with_free_files_doc:
    xmlFreeDoc(files_doc);
 out_with_free_desc_doc:
    xmlFreeDoc(desc_doc);
 out:
    return ret;
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

static void evr_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
static void evr_fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
static void evr_fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);

static const struct fuse_lowlevel_ops evr_fs_oper = {
    .lookup = evr_fs_lookup,
    .getattr = evr_fs_getattr,
    .readdir = evr_fs_readdir,
    .open = evr_fs_open,
    .release = evr_fs_release,
    .read = evr_fs_read,
};

struct evr_fs_inode *evr_get_inode(fuse_req_t req, fuse_ino_t ino);
int evr_fs_stat(fuse_req_t req, struct stat *st, fuse_ino_t ino);

static void evr_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name){
    log_debug("fuse lookup with parent inode %d the name %s", (int)parent, name);
    struct evr_fs_inode *pnd = evr_get_inode(req, parent);
    if(!pnd){
        return;
    }
    if(pnd->type != evr_fs_inode_type_dir){
        log_error("Inode %d is not a directory", (int)parent);
        if(fuse_reply_err(req, ENOTDIR) != 0){
            evr_panic("Unable to report lookup ENOTDIR error for name %s", name);
        }
        return;
    }
    struct evr_fs_inode_dir *dir = &pnd->data.dir;
    fuse_ino_t *c_end = &dir->children[dir->children_len];
    for(fuse_ino_t *c = dir->children; c != c_end; ++c){
        struct evr_fs_inode *cnd = &inode_set.inodes[*c];
        if(strcmp(name, cnd->name) != 0){
            continue;
        }
        struct fuse_entry_param e;
        memset(&e, 0, sizeof(e));
        e.ino = *c;
        e.attr_timeout = 1.0;
        e.entry_timeout = 1.0;
        if(evr_fs_stat(req, &e.attr, *c) != evr_ok){
            // error has been reported by evr_fs_stat
            return;
        }
        fuse_reply_entry(req, &e);
        return;
    }
    if(fuse_reply_err(req, ENOENT) != 0){
        evr_panic("Unable to report lookup ENOENT error for name %s", name);
    }
}

static void evr_fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    log_debug("fuse getattr with inode %d", (int)ino);
    struct stat st;
    if(evr_fs_stat(req, &st, ino) != evr_ok){
        return;
    }
    if(fuse_reply_attr(req, &st, 1.0) != 0){
        evr_panic("Unable to report reply for attr with inode %d", (int)ino);
    }
}

int evr_fs_stat(fuse_req_t req, struct stat *st, fuse_ino_t ino){
    struct evr_fs_inode *nd = evr_get_inode(req, ino);
    if(!nd){
        // error has been reported by evr_get_inode
        return evr_error;
    }
    memset(st, 0, sizeof(*st));
    switch(nd->type){
    default:
        evr_panic("Unknown node type %d", nd->type);
        return evr_error;
    case evr_fs_inode_type_dir:
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 1;
        break;
    case evr_fs_inode_type_file:
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = nd->data.file.file_size;
        break;
    }
    st->st_ino = ino;
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
        buf->size_used += fuse_add_direntry(req, &buf->data[buf->size_used], buf->size_allocated, name, &st, buf->size_used + entry_size); \
    } while(0)

static void evr_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    int err = EINVAL;
    log_debug("fuse readdir with inode %d (size %zu, off %zu)", (int)ino, size, off);
    struct evr_fs_inode *nd = evr_get_inode(req, ino);
    if(nd->type != evr_fs_inode_type_dir){
        log_error("Inode %d is not a directory", (int)ino);
        err = ENOTDIR;
        goto fail;
    }
    struct dynamic_array *buf = alloc_dynamic_array(0);
    if(!buf){
        goto fail;
    }
    struct stat st;
    memset(&st, 0, sizeof(st));
    evr_add_direntry(".", ino);
    evr_add_direntry("..", nd->parent);
    struct evr_fs_inode_dir *dir = &nd->data.dir;
    fuse_ino_t *c_end = &dir->children[dir->children_len];
    for(fuse_ino_t *c = dir->children; c != c_end; ++c){
        struct evr_fs_inode *cnd = &inode_set.inodes[*c];
        evr_add_direntry(cnd->name, *c);
    }
    if(off >= buf->size_used){
        if(fuse_reply_buf(req, NULL, 0) != 0){
            goto failed_reply;
        }
    } else {
        if(fuse_reply_buf(req, &buf->data[off], min(buf->size_used - off, size)) != 0){
            goto failed_reply;
        }
    }
    free(buf);
    return;
 fail:
    if(fuse_reply_err(req, err) != 0){
        evr_panic("Unable to report error %d on readdir", err);
    }
    return;
 failed_reply:
    free(buf);
    evr_panic("Failed to reply readdir for inode %d", (int)ino);
}

#undef evr_add_direntry

struct evr_file_claim *evr_fetch_file_claim(struct evr_file *c, evr_claim_ref claim_ref);

static void evr_fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    int err = EINVAL;
    log_debug("fuse open inode %d", (int)ino);
    struct evr_fs_inode *nd = evr_get_inode(req, ino);
    if(nd->type != evr_fs_inode_type_file){
        log_error("Inode %d is not a file", (int)ino);
        err = EISDIR;
        goto fail;
    }
    if(evr_allocate_open_file(&open_files, &fi->fh) != evr_ok){
        goto fail;
    }
    struct evr_open_file *of = &open_files.files[fi->fh];
    if(evr_connect_to_storage(&of->gc, &cfg, cfg.storage_host, cfg.storage_port) != evr_ok){
        log_error("Unable to connect to glacier when opening file with inode %d", (int)ino);
        goto fail_with_close_open_file;
    }
    of->claim = evr_fetch_file_claim(&of->gc, nd->data.file.file_ref);
    if(!of->claim){
        log_error("Unable to fetch file claim for inode %d", (int)ino);
        goto fail_with_close_open_file;
    }
    if(fuse_reply_open(req, fi) != 0){
        goto fail_with_close_open_file;
    }
    return;
 fail_with_close_open_file:
    if(evr_close_open_file(&open_files, fi->fh) != evr_ok){
        evr_panic("Unable to close file with inode %d on failed open", (int)ino);
    }
 fail:
    if(fuse_reply_err(req, err) != 0){
        evr_panic("Unable to report error %d on open", err);
    }
}

struct evr_file_claim *evr_fetch_file_claim(struct evr_file *c, evr_claim_ref claim_ref){
    struct evr_file_claim *ret = NULL;
    evr_blob_ref blob_ref;
    int claim_index;
    evr_split_claim_ref(blob_ref, &claim_index, claim_ref);
    xmlDoc *doc = NULL;
    if(evr_fetch_signed_xml(&doc, cfg.verify_ctx, c, blob_ref) != evr_ok){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("No validly signed XML found for ref %s", claim_ref_str);
        goto out;
    }
    xmlNode *cs = evr_get_root_claim_set(doc);
    if(!cs){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("No claim set found in blob for claim ref %s", claim_ref_str);
        goto out_with_free_doc;
    }
    xmlNode *cn = evr_nth_claim(cs, claim_index);
    if(!cn){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("There is no claim with index %d in claim-set with ref %s", claim_index, claim_ref_str);
        goto out_with_free_doc;
    }
    ret = evr_parse_file_claim(cn);
    if(!ret){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("Unable to parse file claim from claim XML with ref %s", claim_ref_str);
    }
 out_with_free_doc:
    xmlFreeDoc(doc);
 out:
    return ret;
}

static void evr_fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    log_debug("fuse release file handle %u for inode %d", (unsigned int)fi->fh, (int)ino);
    if(evr_close_open_file(&open_files, fi->fh) != evr_ok){
        goto fail;
    }
    return;
 fail:
    if(fuse_reply_err(req, EINVAL) != 0){
        evr_panic("Unable to report error on release");
    }
}

static void evr_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    int err = EINVAL;
    log_debug("fuse read %zu bytes from file handle %u on inode %d at offset %zu", size, (unsigned int)fi->fh, (int)ino, (size_t)off);
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
    return;
 fail_with_free_buf:
    free(buf);
 fail:
    if(fuse_reply_err(req, err) != 0){
        evr_panic("Unable to report error %d on read file handle %u", err, (unsigned int)fi->fh);
    }
}

struct evr_fs_inode *evr_get_inode(fuse_req_t req, fuse_ino_t ino){
    if(ino < FUSE_ROOT_ID || ino >= inode_set.inodes_len){
        log_debug("readdir failed because inode %d out of bounds", (int)ino);
        goto fail_with_enoent;
    }
    struct evr_fs_inode *nd = &inode_set.inodes[ino];
    if(nd->type == evr_fs_inode_type_unlinked){
        log_debug("readdir failed because inode %d is unlinked", (int)ino);
        goto fail_with_enoent;
    }
    return nd;
 fail_with_enoent:
    if(fuse_reply_err(req, ENOENT) != 0){
        evr_panic("Unable to report error on get inode %d", (int)ino);
    }
    return NULL;
}

int run_fuse(char *program, struct evr_fs_cfg *cfg){
    int ret = 1;
    size_t fuse_argv_len = 2;
    char *fuse_argv[] = {
        program,
        "-osubtype=" program_name,
        NULL,
    };
    if(cfg->allow_other){
        fuse_argv[fuse_argv_len++] = "-oallow_other";
    }
    struct fuse_args fuse_args = FUSE_ARGS_INIT(fuse_argv_len, fuse_argv);
    struct fuse_session *se = fuse_session_new(&fuse_args, &evr_fs_oper, sizeof(evr_fs_oper), NULL);
    if(se == NULL) {
        goto out;
    }
    if(fuse_set_signal_handlers(se) != 0) {
        goto out_with_destroy_session;
    }
    if(fuse_session_mount(se, cfg->mount_point) != 0) {
        goto out_with_free_signal_handlers;
    }
    fuse_daemonize(cfg->foreground);
    if(cfg->single_thread) {
        ret = fuse_session_loop(se);
    } else {
        struct fuse_loop_config fcfg;
        fcfg.clone_fd = 0;
        fcfg.max_idle_threads = 10;
        ret = fuse_session_loop_mt(se, &fcfg);
    }
    fuse_session_unmount(se);
 out_with_free_signal_handlers:
    fuse_remove_signal_handlers(se);
 out_with_destroy_session:
    fuse_session_destroy(se);
 out:
    return ret;
}
