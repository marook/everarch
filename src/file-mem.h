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

#ifndef file_mem_h
#define file_mem_h

#include "config.h"

#include "dyn-mem.h"
#include "files.h"

struct evr_file_mem {
    /**
     * Current offset of the read and write pointer inside data.
     */
    size_t offset;
    struct dynamic_array *data;
};

/**
 * evr_init_file_mem initalizes a struct evr_file_mem.
 *
 * An error occured if fm->data is NULL after the call.
 */
#define evr_init_file_mem(fm, max_size)                 \
    do {                                                \
        (fm)->offset = 0;                               \
        (fm)->data = alloc_dynamic_array(max_size);     \
    } while (0)

void evr_file_bind_file_mem(struct evr_file *f, struct evr_file_mem *fm);

#endif
