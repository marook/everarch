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

const char *bucket_dir_template = "/tmp/evr-glacier-test-XXXXXX";

char *new_bucket_dir_path(){
    size_t dir_len = strlen(bucket_dir_template);
    char *s = (char*)malloc(dir_len + 1);
    assert_not_null(s);
    memcpy(s, bucket_dir_template, dir_len + 1);
    assert_not_null(mkdtemp(s));
    return s;
}

evr_glacier_storage_configuration *create_temp_evr_glacier_storage_configuration(){
    evr_glacier_storage_configuration *config = create_evr_glacier_storage_configuration();
    assert_not_null(config);
    if(config->bucket_dir_path){
        free(config->bucket_dir_path);
    }
    config->bucket_dir_path = new_bucket_dir_path();
    printf("Using %s as bucket dir\n", config->bucket_dir_path);
    return config;
}

