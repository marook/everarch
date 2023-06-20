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

#ifndef metadata_h
#define metadata_h

#include "config.h"

#include "files.h"

#define evr_meta_signed_by 0

int evr_meta_open(struct evr_file *meta, char *path);

/**
 * evr_meta_write_str writes metadata for the given key into the given
 * meta file handle. This function does nothing and returns
 * successfully if meta points to null.
 *
 * meta_key must be one of the evr_meta_* constants.
 *
 * Returns evr_ok on success.
 */
int evr_meta_write_str(struct evr_file *meta, int meta_key, char *value);

#endif
