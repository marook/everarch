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

char *new_temp_dir_path(void){
    size_t dir_len = strlen(temp_dir_template);
    char *s = (char*)malloc(dir_len + 1);
    assert(s);
    memcpy(s, temp_dir_template, dir_len + 1);
    assert(mkdtemp(s));
    return s;
}

static struct evr_glacier_storage_cfg evr_glacier_storage_cfg_init = { 0 };

struct evr_glacier_storage_cfg *create_temp_evr_glacier_storage_cfg(void){
    struct evr_glacier_storage_cfg *config = malloc(sizeof(struct evr_glacier_storage_cfg));
    assert(config);
    *config = evr_glacier_storage_cfg_init;
    config->host = strdup("localhost");
    config->port = strdup(to_string(evr_glacier_storage_port));
    config->ssl_cert_path = strdup("../testing/tls/glacier-cert.pem");
    config->ssl_key_path = strdup("../testing/tls/glacier-key.pem");
    config->auth_token_set = 1;
    memset(config->auth_token, 7, sizeof(config->auth_token));
    config->max_bucket_size = 10<<20;
    config->bucket_dir_path = new_temp_dir_path();
    log_info("Using %s as bucket dir", config->bucket_dir_path);
    return config;
}

static struct evr_attr_index_cfg evr_attr_index_cfg_init = { 0 };

struct evr_attr_index_cfg *create_temp_attr_index_db_configuration(void){
    struct evr_attr_index_cfg *cfg = malloc(sizeof(struct evr_attr_index_cfg));
    assert(cfg);
    *cfg = evr_attr_index_cfg_init;
    cfg->state_dir_path = new_temp_dir_path();
    cfg->host = strdup("localhost");
    cfg->port = strdup(to_string(evr_attr_index_port));
    cfg->storage_host = strdup("localhost");
    cfg->storage_port = strdup(to_string(evr_glacier_storage_port));
    log_info("Using %s as attr-index state dir", cfg->state_dir_path);
    return cfg;
}
