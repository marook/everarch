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

#ifndef __glacier_storage_configuration_h__
#define __glacier_storage_configuration_h__

#include "config.h"

#include <stddef.h>

/**
 * evr_glacier_storage_configuration aggregates configuration options
 * for the evr-glacier-storage application.
 *
 * All pointers within this structure must be freed using
 * free_evr_glacier_storage_configuration function.
 */
struct evr_glacier_storage_configuration {
    char *cert_path;
    char *key_path;
    char *cert_root_path;

    /**
     * max_bucket_size is the maximum size of one bucket in bytes.
     */
    size_t max_bucket_size;

    /**
     * bucket_dir_path is a template string which produces the
     * path for a bucket with a given index.
     *
     * %d is used to place the bucket index within the template.
     */
    char *bucket_dir_path;
};

struct evr_glacier_storage_configuration *create_evr_glacier_storage_configuration();

void free_evr_glacier_storage_configuration(struct evr_glacier_storage_configuration *config);

/**
 * load_evr_glacier_storage_configurations loads and merges configs
 * from one or more files and expands it.
 */
int load_evr_glacier_storage_configurations(struct evr_glacier_storage_configuration *config, const char **paths, size_t paths_len);

int merge_evr_glacier_storage_configuration_file(struct evr_glacier_storage_configuration *config, const char *config_path);

int expand_evr_glacier_storage_configuration(struct evr_glacier_storage_configuration *config);

#endif
