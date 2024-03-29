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

#include "auth.h"

/**
 * evr_glacier_storage_cfg aggregates configuration options
 * for the evr-glacier-storage application.
 *
 * All pointers within this structure must be freed using
 * free_evr_glacier_storage_cfg function.
 *
 * Here are some places you might need to touch if you modify struct:
 * 1) evr_free_glacier_storage_cfg(…)
 * 2) create_temp_evr_glacier_storage_cfg(…) in configuration-testutil.c
 * 3) clone_config(…) in glacier-test.c
 */
struct evr_glacier_storage_cfg {
    char *host;
    char *port;
    char *ssl_cert_path;
    char *ssl_key_path;
    int auth_token_set;
    evr_auth_token auth_token;
    
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

    /**
     * index_db_path may specify an alternative path for the sqlite
     * bucket index DB. The default path within the bucket directory
     * should be used when pointing to NULL.
     */
    char *index_db_path;

    /**
     * foreground's indicates if the process should stay in the
     * started process or fork into a daemon.
     */
    int foreground;

    char *log_path;
    char *pid_path;
};

void evr_free_glacier_storage_cfg(struct evr_glacier_storage_cfg *cfg);

#endif
