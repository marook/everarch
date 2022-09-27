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

#include "basics.h"
#include "configp.h"

#define program_name "evr-fs"

const char *argp_program_version = " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = program_name " is a virtual file system to access evr files.";

static char args_doc[] = "TRANSFORMATION MOUNT_POINT";

struct evr_fs_cfg {
    /**
     * foreground's meaning is defined by the fuse -d option.
     */
    int foreground;
    /**
     * single_thread's meaning is defined by the fuse -s option.
     */
    int single_thread;
    char *transformation;
    char *mount_point;
};

static struct argp_option options[] = {
    {"foreground", 'f', NULL, 0, "The process will not demonize. It will stay in the foreground instead."},
    {"single-thread", 's', NULL, 0, "The fuse layer will be single threaded."},
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

static const struct fuse_lowlevel_ops evr_fs_oper = {
    /*.lookup = evr_fs_lookup,
      .getattr = evr_fs_getattr,
      .readdir = evr_fs_readdir,
      .open = evr_fs_open,
      .read = evr_fs_read,*/
};

int main(int argc, char *argv[]) {
    int ret = 1;
    evr_init_basics();
    struct evr_fs_cfg cfg;
    cfg.foreground = 0;
    cfg.single_thread = 0;
    cfg.transformation = NULL;
    cfg.mount_point = NULL;
    char *config_paths[] = evr_program_config_paths();
    struct configp configp = { options, parse_opt, args_doc, doc };
    if(configp_parse(&configp, config_paths, &cfg) != 0){
        goto out_with_free_cfg;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    char *fuse_argv[] = {
        argv[0],
        "-osubtype=evr-fs",
    };
    struct fuse_args fuse_args = FUSE_ARGS_INIT(sizeof(fuse_argv) / sizeof(char*), fuse_argv);
    struct fuse_session *se = fuse_session_new(&fuse_args, &evr_fs_oper, sizeof(evr_fs_oper), NULL);
    if(se == NULL) {
        goto out_with_free_cfg;
    }
    if(fuse_set_signal_handlers(se) != 0) {
        goto out_with_destroy_session;
    }
    if(fuse_session_mount(se, cfg.mount_point) != 0) {
        goto out_with_free_signal_handlers;
    }
    fuse_daemonize(cfg.foreground);
    if(cfg.single_thread) {
        ret = fuse_session_loop(se);
    } else {
        struct fuse_loop_config config;
        config.clone_fd = 0;
        config.max_idle_threads = 10;
        ret = fuse_session_loop_mt(se, &config);
    }
    fuse_session_unmount(se);
 out_with_free_signal_handlers:
    fuse_remove_signal_handlers(se);
 out_with_destroy_session:
    fuse_session_destroy(se);
 out_with_free_cfg:
    do {
        void *tbfree[] = {
            cfg.transformation,
            cfg.mount_point,
        };
        void **tbfree_end = &tbfree[sizeof(tbfree) / sizeof(void*)];
        for(void **it = tbfree; it != tbfree_end; ++it){
            free(*it);
        }
    } while(0);
    return ret;
}
