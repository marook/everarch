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
#include <string.h>

#include "assert.h"
#include "configuration-testutil.h"
#include "logger.h"

const char *temp_dir_template = "/tmp/evr-glacier-test-XXXXXX";

char *new_temp_dir_path(){
    size_t dir_len = strlen(temp_dir_template);
    char *s = (char*)malloc(dir_len + 1);
    assert(s);
    memcpy(s, temp_dir_template, dir_len + 1);
    assert(mkdtemp(s));
    return s;
}

struct evr_glacier_storage_cfg *create_temp_evr_glacier_storage_cfg(){
    struct evr_glacier_storage_cfg *config = malloc(sizeof(struct evr_glacier_storage_cfg));
    assert(config);
    memset(config, 0, sizeof(struct evr_glacier_storage_cfg));
    config->host = strdup("localhost");
    config->port = strdup(to_string(evr_glacier_storage_port));
    config->max_bucket_size = 10<<20;
    config->bucket_dir_path = new_temp_dir_path();
    log_info("Using %s as bucket dir", config->bucket_dir_path);
    return config;
}

struct evr_attr_index_cfg *create_temp_attr_index_db_configuration(){
    struct evr_attr_index_cfg *cfg = malloc(sizeof(struct evr_attr_index_cfg));
    assert(cfg);
    memset(cfg, 0, sizeof(struct evr_attr_index_cfg));
    cfg->state_dir_path = new_temp_dir_path();
    cfg->host = strdup("localhost");
    cfg->port = strdup(to_string(evr_glacier_attr_index_port));
    cfg->storage_host = strdup("localhost");
    cfg->storage_port = strdup(to_string(evr_glacier_storage_port));
    log_info("Using %s as attr-index state dir", cfg->state_dir_path);
    return cfg;
}
