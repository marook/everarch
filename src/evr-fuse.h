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

#ifndef evr_fuse_h
#define evr_fuse_h

#include "config.h"

#include <fuse_lowlevel.h>

struct evr_fuse_cfg {
    struct fuse_lowlevel_ops ops;
    
    char *mount_point;

    /**
     * allow_other indicates if other users may access this file
     * system.
     */
    int allow_other;
    
    /**
     * single_thread's meaning is defined by the fuse -s option.
     */
    int single_thread;
    
    /**
     * foreground's meaning is defined by the fuse -d option.
     */
    int foreground;

    char *pid_path;

    int (*setup)(void **ctx);
    int (*teardown)(void *ctx);
};

int evr_run_fuse(char *prog, char *prog_name, struct evr_fuse_cfg *cfg);


#endif
