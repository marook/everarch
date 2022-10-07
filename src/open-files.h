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

#ifndef open_files_h
#define open_files_h

#include "config.h"

#include <threads.h>

#include "claims.h"
#include "files.h"

struct evr_open_file {
    int open;

    mtx_t lock;

    /**
     * gc is the clacier connection. Has fd 0 if not open.
     */
    struct evr_file gc;

    struct evr_file_claim *claim;

    size_t cached_slice_index;
    char *cached_slice_buf;
};

int evr_open_file_read(struct evr_open_file *f, char *buf, size_t *size, off_t off);

struct evr_open_file_set {
    mtx_t files_lock;
    struct evr_open_file *files;
    size_t files_len;
};

int evr_init_open_file_set(struct evr_open_file_set *ofs);

int evr_empty_open_file_set(struct evr_open_file_set *ofs);

int evr_allocate_open_file(struct evr_open_file_set *ofs, uint64_t *fh);

int evr_close_open_file(struct evr_open_file_set *ofs, uint64_t fh);

#endif
