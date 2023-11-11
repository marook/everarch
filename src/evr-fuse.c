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

#include "evr-fuse.h"

#include <stddef.h>
#include <string.h>

#include "daemon.h"
#include "errors.h"
#include "logger.h"

#define evr_fuse_opt_subtype "-osubtype="
#define evr_fuse_opt_allow_other "-oallow_other"

int evr_run_fuse(char *prog, char *prog_name, struct evr_fuse_cfg *cfg){
    int ret = 1;
    size_t fuse_argv_len = 1;
    char *fuse_argv[] = {
        prog,
        // reserved for evr_fuse_opt_subtype and evr_fuse_opt_allow_other
        NULL,
        NULL,
    };
    struct fuse_args fuse_args = FUSE_ARGS_INIT(fuse_argv_len, fuse_argv);
    struct fuse_session *se;
    void *ctx;
    const size_t prog_name_len = strlen(prog_name);
    char buf_subtype[sizeof(evr_fuse_opt_subtype) - 1 + prog_name_len + 1];
    memcpy(buf_subtype, evr_fuse_opt_subtype, sizeof(evr_fuse_opt_subtype) - 1);
    memcpy(&buf_subtype[sizeof(evr_fuse_opt_subtype)], prog_name, prog_name_len + 1);
    fuse_argv[fuse_argv_len++] = buf_subtype;
    if(cfg->allow_other){
        fuse_argv[fuse_argv_len++] = evr_fuse_opt_allow_other;
    }
    se = fuse_session_new(&fuse_args, &cfg->ops, sizeof(cfg->ops), NULL);
    if(se == NULL) {
        goto out;
    }
    if(fuse_set_signal_handlers(se) != 0) {
        goto out_with_destroy_session;
    }
    if(fuse_session_mount(se, cfg->mount_point) != 0) {
        goto out_with_free_signal_handlers;
    }
    if(!cfg->foreground){
        if(evr_daemonize(cfg->pid_path) != evr_ok){
            goto out_with_session_unmount;
        }
    }
    if(cfg->setup && cfg->setup(&ctx) != evr_ok){
        goto out_with_session_unmount;
    }
    if(cfg->single_thread) {
        ret = fuse_session_loop(se);
    } else {
        struct fuse_loop_config fcfg;
        fcfg.clone_fd = 0;
        fcfg.max_idle_threads = 10;
        ret = fuse_session_loop_mt(se, &fcfg);
    }
    if(cfg->teardown && cfg->teardown(ctx) != evr_ok){
        evr_panic("Unable to tear down fuse context.");
        ret = evr_error;
    }
 out_with_session_unmount:
    fuse_session_unmount(se);
 out_with_free_signal_handlers:
    fuse_remove_signal_handlers(se);
 out_with_destroy_session:
    fuse_session_destroy(se);
 out:
    return ret;
}
