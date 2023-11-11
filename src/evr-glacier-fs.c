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

#include <stdlib.h>
#include <fuse_lowlevel.h>
#include <argp.h>
#include <unistd.h>
#include <threads.h>

#include "basics.h"
#include "logger.h"
#include "configp.h"
#include "evr-tls.h"
#include "daemon.h"
#include "claims.h"
#include "evr-glacier-client.h"
#include "evr-fuse.h"
#include "open-files.h"

#define program_name "evr-glacier-fs"

const char *argp_program_version = " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " is a virtual file system to access evr blobs and files by blob key.\n\n";

static char args_doc[] = "MOUNT_POINT";

#define arg_storage_host 256
#define arg_storage_port 257
#define arg_ssl_cert 258
#define arg_auth_token 259
#define arg_log_path 260
#define arg_allow_other 261
#define arg_pid_path 262
#define arg_accepted_gpg_key 263

struct evr_glacier_fs_cfg {
    char *storage_host;
    char *storage_port;
    struct evr_auth_token_cfg *auth_tokens;
    struct evr_cert_cfg *ssl_certs;
    char *log_path;
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
};

struct evr_glacier_fs_cfg cfg;

static struct argp_option options[] = {
    {"storage-host", arg_storage_host, "HOST", 0, "The hostname of the evr-glacier-storage server to connect to. Default hostname is " evr_glacier_storage_host "."},
    {"storage-port", arg_storage_port, "PORT", 0, "The port of the evr-glacier-storage server to connect to. Default port is " to_string(evr_glacier_storage_port) "."},
    {"ssl-cert", arg_ssl_cert, "HOST:PORT:FILE", 0, "The hostname, port and path to the pem file which contains the public SSL certificate of the server. This option can be specified multiple times. Default entry is " evr_glacier_storage_host ":" to_string(evr_glacier_storage_port) ":" default_storage_ssl_cert_path "."},
    {"auth-token", arg_auth_token, "HOST:PORT:TOKEN", 0, "A hostname, port and authorization token which is presented to the server so our requests are accepted. The authorization token must be a 64 characters string only containing 0-9 and a-f. Should be hard to guess and secret."},
    {"accepted-gpg-key", arg_accepted_gpg_key, "FINGERPRINT", 0, "A GPG key fingerprint of claim signatures which will be accepted as valid. Can be specified multiple times to accept multiple keys. You can call 'gpg --list-public-keys' to see your known keys."},
    {"log", arg_log_path, "FILE", 0, "A file to which log output messages will be appended. By default logs are written to stdout."},
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"single-thread", 's', NULL, 0, "The fuse layer will be single threaded."},
    {"oallow-other", arg_allow_other, NULL, 0, "The file system will be accessible by other users. Requires the user_allow_other option to be set in the global fuse configuration."},
    {"pid", arg_pid_path, "FILE", 0, "A file to which the daemon's pid is written."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct evr_glacier_fs_cfg *cfg = (struct evr_glacier_fs_cfg*)state->input;
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
    case 'f':
        cfg->fuse.foreground = 1;
        break;
    case 's':
        cfg->fuse.single_thread = 1;
        break;
    case arg_allow_other:
        cfg->fuse.allow_other = 1;
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
            evr_replace_str(cfg->fuse.mount_point, arg);
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

static error_t parse_opt_glacier(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

/**
 * lifetime duration of an inode assignment in milliseconds.
 */
#define evr_inode_lifetime 1000

static mtx_t evr_inodes_mtx;

struct evr_inode {
    evr_claim_ref ref;

    /**
     * Absolute timestamp until when the inode must stay valid.
     */
    evr_time timeout;
};

static struct evr_inode evr_inodes[512];

static struct evr_open_file_set open_files;

static int evr_lookup_inode(evr_claim_ref ref, fuse_ino_t ino);
static int evr_acquire_inode(fuse_ino_t *ino, evr_claim_ref ref);

static void evr_glacier_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
static void evr_glacier_fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_glacier_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);
static void evr_glacier_fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_glacier_fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void evr_glacier_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi);

int evr_connect_to_storage(struct evr_file *c, char *host, char *port);

int main(int argc, char *argv[]) {
    int ret = 1;
    evr_log_app = "a";
    evr_init_basics();
    evr_tls_init();
    xmlInitParser();
    gcry_check_version(EVR_GCRY_MIN_VERSION);
    evr_init_signatures();
    cfg.storage_host = strdup(evr_glacier_storage_host);
    cfg.storage_port = strdup(to_string(evr_glacier_storage_port));
    cfg.auth_tokens = NULL;
    cfg.ssl_certs = NULL;
    cfg.log_path = NULL;
    cfg.fuse.foreground = 0;
    cfg.fuse.single_thread = 0;
    cfg.fuse.allow_other = 0;
    cfg.fuse.mount_point = NULL;
    cfg.fuse.pid_path = NULL;
    cfg.uid = getuid();
    cfg.gid = getgid();
    evr_init_verify_cfg(&cfg.verify);
    if(evr_push_cert(&cfg.ssl_certs, evr_glacier_storage_host, to_string(evr_glacier_storage_port), default_storage_ssl_cert_path) != evr_ok){
        goto out_with_free_cfg;
    }
    char *config_paths[] = evr_program_config_paths();
    struct configp configp = { options, parse_opt, args_doc, doc };
    if(configp_parse(&configp, config_paths, &cfg) != 0){
        goto out_with_free_cfg;
    }
    struct argp argp = { options, parse_opt_glacier, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    if(evr_setup_log(cfg.log_path) != evr_ok){
        goto out_with_free_cfg;
    }
    if(evr_verify_cfg_parse(&cfg.verify) != evr_ok){
        goto out_with_free_cfg;
    }
    if(mtx_init(&evr_inodes_mtx, mtx_plain) != thrd_success){
        goto out_with_free_cfg;
    }
    memset(evr_inodes, 0, sizeof(evr_inodes));
    if(evr_init_open_file_set(&open_files) != evr_ok){
        goto out_with_destroy_inodes_mtx;;
    }
    cfg.fuse.ops.lookup = evr_glacier_fs_lookup;
    cfg.fuse.ops.getattr = evr_glacier_fs_getattr;
    cfg.fuse.ops.readdir = evr_glacier_fs_readdir;
    cfg.fuse.ops.open = evr_glacier_fs_open;
    cfg.fuse.ops.release = evr_glacier_fs_release;
    cfg.fuse.ops.read = evr_glacier_fs_read;
    cfg.fuse.setup = NULL;
    cfg.fuse.teardown = NULL;
    if(evr_run_fuse(argv[0], program_name, &cfg.fuse) != 0){
        goto out_with_empty_open_file_set;
    }
    ret = 0;
 out_with_empty_open_file_set:
    if(evr_empty_open_file_set(&open_files) != evr_ok){
        ret = 1;
    }
 out_with_destroy_inodes_mtx:
    if(mtx_lock(&evr_inodes_mtx) != thrd_success){
        evr_panic("Unable to lock inodes mutex for followup destruction");
    }
    mtx_destroy(&evr_inodes_mtx);
 out_with_free_cfg:
    do {
        void *tbfree[] = {
            cfg.storage_host,
            cfg.storage_port,
            cfg.log_path,
            cfg.fuse.mount_point,
            cfg.fuse.pid_path,
        };
        void **tbfree_end = &tbfree[static_len(tbfree)];
        for(void **it = tbfree; it != tbfree_end; ++it){
            free(*it);
        }
    } while(0);
    evr_free_auth_token_chain(cfg.auth_tokens);
    evr_free_cert_chain(cfg.ssl_certs);
    evr_free_verify_cfg(&cfg.verify);
    xmlCleanupParser();
    evr_tls_free();
    if(evr_teardown_log() != evr_ok){
        ret = 1;
    }
    return ret;
}

#define evr_glacier_fs_ino_root 1
#define evr_glacier_fs_ino_files 2
#define evr_glacier_fs_ino_files_name "file"
#define evr_glacier_fs_ino_dyn 3

static int evr_lookup_inode(evr_claim_ref ref, fuse_ino_t ino){
    int ret = evr_error;
    evr_time t;
    struct evr_inode *ind;
    if(ino < evr_glacier_fs_ino_dyn || (ino - evr_glacier_fs_ino_dyn) >= static_len(evr_inodes)){
        goto out;
    }
    evr_now(&t);
    if(mtx_lock(&evr_inodes_mtx) != thrd_success){
        goto out;
    }
    ind = &evr_inodes[ino - evr_glacier_fs_ino_dyn];
    if(ind->timeout < t){
        ret = evr_not_found;
        goto out_with_unlock_inodes;
    }
    memcpy(ref, ind->ref, evr_claim_ref_size);
    ret = evr_ok;
 out_with_unlock_inodes:
    if(mtx_unlock(&evr_inodes_mtx) != thrd_success){
        evr_panic("Unable to unlock inodes mutex");
    }
 out:
    return ret;
}

static int evr_acquire_inode(fuse_ino_t *ino, evr_claim_ref ref){
    int ret = evr_error;
    evr_time t;
    struct evr_inode *ind_end, *ind_it, *available_ind;
    available_ind = NULL;
    if(mtx_lock(&evr_inodes_mtx) != thrd_success){
        goto out;
    }
    evr_now(&t);
    ind_end = &evr_inodes[static_len(evr_inodes)];
    for(ind_it = evr_inodes; ind_it != ind_end; ++ind_it){
        if(ind_it->timeout < t){
            if(!available_ind) {
                available_ind = ind_it;
            }
        } else {
            if(evr_cmp_claim_ref(ref, ind_it->ref) == 0){
                *ino = ind_it - evr_inodes + evr_glacier_fs_ino_dyn;
                ind_it->timeout = t + evr_inode_lifetime;
                ret = evr_ok;
#ifdef EVR_LOG_DEBUG
                {
                    evr_claim_ref_str ref_str;
                    evr_fmt_claim_ref(ref_str, ref);
                    log_debug("Extended lifetime of inode %zu with assignemt %s", (size_t)*ino, ref_str);
                }
#endif
                goto out_with_unlock_inodes;
            }
        }
    }
    if(!available_ind){
        ret = evr_temporary_occupied;
        goto out_with_unlock_inodes;
    }
    ret = evr_ok;
    *ino = available_ind - evr_inodes + evr_glacier_fs_ino_dyn;
    memcpy(available_ind->ref, ref, evr_claim_ref_size);
    available_ind->timeout = t + evr_inode_lifetime;
#ifdef EVR_LOG_DEBUG
    {
        evr_claim_ref_str ref_str;
        evr_fmt_claim_ref(ref_str, ref);
        log_debug("Assigned inode %zu to %s", (size_t)*ino, ref_str);
    }
#endif
 out_with_unlock_inodes:
    if(mtx_unlock(&evr_inodes_mtx) != thrd_success){
        evr_panic("Unable to unlock inodes mutex");
    }
 out:
    return ret;
}

static void evr_glacier_fs_file_dir_stat(struct stat *stat);
static void evr_glacier_fs_lookup_file(fuse_req_t req, const char *seed_str);

static void evr_glacier_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name){
    struct fuse_entry_param ep;
    log_debug("fuse request %p: lookup %s with parent %d", req, name, (int)parent);
    switch(parent){
    case evr_glacier_fs_ino_root:
        if(strcmp(name, evr_glacier_fs_ino_files_name) == 0){
            memset(&ep, 0, sizeof(ep));
            ep.ino = evr_glacier_fs_ino_files;
            evr_glacier_fs_file_dir_stat(&ep.attr);
            ep.attr_timeout = DBL_MAX;
            ep.entry_timeout = DBL_MAX;
            if(fuse_reply_entry(req, &ep) != 0){
                evr_panic("fuse request %p unable to reply entry", req);
            }
            return;
        }
        break;
    case evr_glacier_fs_ino_files:
        evr_glacier_fs_lookup_file(req, name);
        return;
    }
    if(fuse_reply_err(req, ENOENT) != 0){
        evr_panic("fuse request %p ENOENT can't be replied", req);
    }
}

static void evr_glacier_fs_file_dir_stat(struct stat *stat){
    stat->st_mode = S_IFDIR | 0444;
    stat->st_nlink = 1;
    stat->st_uid = cfg.uid;
    stat->st_gid = cfg.gid;
}

static void evr_glacier_fs_lookup_file(fuse_req_t req, const char *ref_str){
    int err = EIO, res;
    evr_claim_ref ref;
    struct evr_file gc;
    struct evr_file_claim *file;
    struct fuse_entry_param ep;
    evr_time file_created;
    if(evr_parse_claim_ref(ref, ref_str) != evr_ok){
        err = ENOENT;
        goto out;
    }
    if(evr_connect_to_storage(&gc, cfg.storage_host, cfg.storage_port) != evr_ok){
        goto out;
    }
    file = evr_fetch_file_claim(&gc, ref, cfg.verify.ctx, &file_created);
    if(!file){
        err = ENOENT;
        goto out_with_close_gc;
    }
    memset(&ep, 0, sizeof(ep));
    res = evr_acquire_inode(&ep.ino, ref);
    if(res == evr_temporary_occupied) {
        // if you ever see this error the evr_inodes buffer should
        // probably be changed from a fixed size to a dynamically
        // growing buffer.
        log_info("Unable to acquire another inode. inode buffer fully occupied.");
        err = EBUSY;
        goto out_with_free_file;
    } else if(res != evr_ok){
        goto out_with_free_file;
    }
    ep.attr.st_mode = S_IFREG | 0444;
    ep.attr.st_nlink = 1;
    ep.attr.st_size = evr_file_claim_file_size(file);
    ep.attr.st_uid = cfg.uid;
    ep.attr.st_gid = cfg.gid;
    evr_time_to_timespec(&ep.attr.st_mtim, &file_created);
    evr_time_to_timespec(&ep.attr.st_ctim, &file_created);
    ep.attr_timeout = evr_inode_lifetime / 1000.0;
    ep.entry_timeout = ep.attr_timeout;
    if(fuse_reply_entry(req, &ep) != 0){
        evr_panic("fuse request %p unable to reply entry", req);
    }
    err = 0;
 out_with_free_file:
    free(file);
 out_with_close_gc:
    if(gc.close(&gc) != 0){
        evr_panic("Unable to close connection to evr-glacier-storage");
    }
 out:
    if(err != 0 && fuse_reply_err(req, err) != 0){
        evr_panic("fuse request %p can't be replied", req);
    }
}

static void evr_glacier_fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    struct stat st;
    log_debug("fuse request %p: getattr for inode %d", req, (int)ino);
    if(ino == evr_glacier_fs_ino_root){
        st.st_mode = S_IFDIR | 0555;
        st.st_nlink = 1;
    } else if(ino == evr_glacier_fs_ino_files) {
        evr_glacier_fs_file_dir_stat(&st);
    } else {
        if(fuse_reply_err(req, ENOENT) != 0){
            evr_panic("not yet implemented");
        }
    }
    st.st_uid = cfg.uid;
    st.st_gid = cfg.gid;
    if(fuse_reply_attr(req, &st, 1.0) != 0){
        evr_panic("fuser request %p unable to reply attr", req);
    }
}

#define evr_add_direntry(name, ino)                                     \
    do {                                                                \
        st.st_ino = ino;                                                \
        entry_size = fuse_add_direntry(req, NULL, 0, name, &st, 0);     \
        if(bp.pos + entry_size > buf_end){                              \
            evr_panic("evr-glacier-fs readdir buf is too small");       \
        }                                                               \
        bp.pos += fuse_add_direntry(req, bp.pos, buf_end - bp.pos, name, &st, bp.pos - buf + entry_size); \
    } while(0)

static void evr_glacier_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    char buf[1024];
    struct evr_buf_pos bp;
    struct stat st;
    size_t entry_size;
    char *buf_end = &buf[sizeof(buf)];
    log_debug("fuse request %p: readdir for inode %d at %zu+%zu", req, (int)ino, (size_t)off, size);
    if(ino == evr_glacier_fs_ino_root){
        evr_init_buf_pos(&bp, buf);
        memset(&st, 0, sizeof(st));
        evr_add_direntry(".", ino);
        evr_add_direntry("..", 0); // TODO is 0 correct here?
        evr_add_direntry(evr_glacier_fs_ino_files_name, evr_glacier_fs_ino_files);
        if(buf + off >= bp.pos){
            if(fuse_reply_buf(req, NULL, 0) != 0){
                evr_panic("Falied to reply fuse request %p", req);
            }
        } else {
            if(fuse_reply_buf(req, &buf[off], min(bp.pos - buf - (size_t)off, size)) != 0){
                evr_panic("Falied to reply fuse request %p", req);
            }
        }
    } else if(ino == evr_glacier_fs_ino_files) {
        if(fuse_reply_buf(req, NULL, 0) != 0){
            evr_panic("Falied to reply fuse request %p", req);
        }
    } else {
        if(fuse_reply_err(req, EIO) != 0){
            evr_panic("Falied to reply fuse request %p", req);
        }
    }
}

#undef evr_add_direntry

static int evr_glacier_fs_open_file(fuse_req_t req, struct fuse_file_info *fi, evr_claim_ref ref);

static void evr_glacier_fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    int err = EIO, res;
    evr_claim_ref ref;
    log_debug("fuse request %p: open for inode %d", req, (int)ino);
    switch(ino){
    default:
        res = evr_lookup_inode(ref, ino);
        if(res == evr_not_found) {
            log_error("No file ref found for inode %zu", (size_t)ino);
            err = ENOENT;
            goto out;
        } else if(res != evr_ok){
            goto out;
        }
        if(evr_glacier_fs_open_file(req, fi, ref) != evr_ok){
            goto out;
        }
        err = 0;
        break;
    case evr_glacier_fs_ino_root:
    case evr_glacier_fs_ino_files:
        err = EISDIR;
        goto out;
    }
 out:
    if(err && fuse_reply_err(req, err) != 0){
        evr_panic("Falied to reply fuse request %p", req);
    }
}

static int evr_glacier_fs_open_file(fuse_req_t req, struct fuse_file_info *fi, evr_claim_ref ref){
    if(evr_allocate_open_file(&open_files, &fi->fh) != evr_ok){
        evr_claim_ref_str ref_str;
        evr_fmt_claim_ref(ref_str, ref);
        log_error("Unable to allocate file handle for ref %s", ref_str);
        goto fail;
    }
    struct evr_open_file *of = &open_files.files[fi->fh];
    if(evr_connect_to_storage(&of->gc, cfg.storage_host, cfg.storage_port) != evr_ok){
        evr_claim_ref_str ref_str;
        evr_fmt_claim_ref(ref_str, ref);
        log_error("Unable to connect to glacier when opening file for ref %s", ref_str);
        goto fail_with_close_open_file;
    }
    of->claim = evr_fetch_file_claim(&of->gc, ref, cfg.verify.ctx, NULL);
    if(!of->claim){
        evr_claim_ref_str ref_str;
        evr_fmt_claim_ref(ref_str, ref);
        log_error("Unable to fetch file claim for ref %s", ref_str);
        goto fail_with_close_open_file;
    }
    if(fuse_reply_open(req, fi) != 0){
        goto fail_with_close_open_file;
    }
#ifdef EVR_LOG_DEBUG
    {
        evr_claim_ref_str ref_str;
        evr_fmt_claim_ref(ref_str, ref);
        log_debug("opened file handle %u for ref %s", (unsigned int)fi->fh, ref_str);
    }
#endif
    return evr_ok;
 fail_with_close_open_file:
    if(evr_close_open_file(&open_files, fi->fh) != evr_ok){
        evr_claim_ref_str ref_str;
        evr_fmt_claim_ref(ref_str, ref);
        evr_panic("Unable to close file for ref %s on failed open", ref_str);
    }
 fail:
    return evr_error;
}

static void evr_glacier_fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    int err = EIO;
    log_debug("fuse request %p: release for inode %d", req, (int)ino);
    if(evr_close_open_file(&open_files, fi->fh) != evr_ok){
        goto out;
    }
    err = 0;
 out:
    if(err && fuse_reply_err(req, err) != 0){
        evr_panic("Unable to close file");
    }
}

static void evr_glacier_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi){
    int err = EIO;
    struct evr_open_file *f;
    size_t read_size;
    char *buf;
    log_debug("fuse request %p: read for inode %d at %zu+%zu", req, (int)ino, (size_t)off, size);
    buf = malloc(size);
    if(!buf){
        goto out;
    }
    f = &open_files.files[fi->fh];
    read_size = size;
    if(evr_open_file_read(f, buf, &read_size, off) != evr_ok){
        goto out_with_free_buf;
    }
    log_debug(">>> pass %zu bytes to fuse", read_size);
    if(fuse_reply_buf(req, buf, read_size) != 0){
        goto out_with_free_buf;
    }
    err = 0;
 out_with_free_buf:
    free(buf);
 out:
    if(err && fuse_reply_err(req, err) != 0){
            evr_panic("not yet implemented");
    }
}

int evr_connect_to_storage(struct evr_file *c, char *host, char *port){
    struct evr_auth_token_cfg *t_cfg;
    if(evr_find_auth_token(&t_cfg, cfg.auth_tokens, host, port) != evr_ok){
        log_error("No auth token found for server %s:%s", host, port);
        return evr_error;
    }
    if(evr_tls_connect_once(c, host, port, cfg.ssl_certs) != evr_ok){
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
