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

/*
 * file-mem.h declares an in memory implementation of struct evr_file.
 */

#ifndef file_mem_h
#define file_mem_h

#include "config.h"

#include "files.h"

struct evr_file_mem {
    size_t max_size;
    size_t alloc_size;
    size_t used_size;
    /**
     * Current offset of the read and write pointer inside data.
     */
    size_t offset;
    char *data;
};

int evr_init_file_mem(struct evr_file_mem *fm, size_t initial_size, size_t max_size);
void evr_destroy_file_mem(struct evr_file_mem *fm);

void evr_file_bind_file_mem(struct evr_file *f, struct evr_file_mem *fm);

#endif
