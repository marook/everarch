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
 * evr_glacier_storage_cfg aggregates configuration options
 * for the evr-glacier-storage application.
 *
 * All pointers within this structure must be freed using
 * free_evr_glacier_storage_cfg function.
 */
struct evr_glacier_storage_cfg {
    char *host;
    char *port;
    char *ssl_cert_path;
    char *ssl_key_path;
    
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

void evr_free_glacier_storage_cfg(struct evr_glacier_storage_cfg *cfg);

#endif
