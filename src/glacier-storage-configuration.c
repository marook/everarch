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

#include "glacier-storage-configuration.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <unistd.h>

#include "files.h"
#include "logger.h"
#include "errors.h"
#include "configurations.h"

#define free_pointer(p)                         \
    if(p){                                      \
        free(p);                                \
    }

char *get_object_string_property(const cJSON *obj, const char* key);
int evr_single_wordexp(char **pathname);

struct evr_glacier_storage_configuration *create_evr_glacier_storage_configuration(){
    struct evr_glacier_storage_configuration *config = (struct evr_glacier_storage_configuration*)malloc(sizeof(struct evr_glacier_storage_configuration));
    if(!config){
        return NULL;
    }
    config->cert_path = NULL;
    config->key_path = NULL;
    config->cert_root_path = NULL;
    config->max_bucket_size = 1024*1024*1024;
    config->bucket_dir_path = NULL;
    replace_string(config->cert_path, "~/.config/everarch/cert.pem", fail);
    replace_string(config->key_path, "~/.config/everarch/key.pem", fail);
    replace_string(config->bucket_dir_path, "~/var/everarch/glacier", fail);
    return config;
 fail:
    free_evr_glacier_storage_configuration(config);
    return NULL;
}

void free_evr_glacier_storage_configuration(struct evr_glacier_storage_configuration *config){
    if(!config){
        return;
    }
    free_pointer(config->cert_path);
    free_pointer(config->key_path);
    free_pointer(config->cert_root_path);
    free_pointer(config->bucket_dir_path);
    free(config);
}

int merge_evr_glacier_storage_configuration_file(void *cfg, const char *config_path){
    struct evr_glacier_storage_configuration *config = cfg;
    int ret = evr_error;
    cJSON *json = evr_parse_json_config(config_path);
    if(!json){
        goto out;
    }
    if(!cJSON_IsObject(json)){
        goto out_with_free_json;
    }
    replace_string(config->cert_path, evr_get_object_string_property(json, "cert_path"), out_with_free_json);
    replace_string(config->key_path, evr_get_object_string_property(json, "key_path"), out_with_free_json);
    replace_string(config->cert_root_path, evr_get_object_string_property(json, "cert_root_path"), out_with_free_json);
    // TODO replace max_bucket_size
    replace_string(config->bucket_dir_path, evr_get_object_string_property(json, "bucket_dir_path"), out_with_free_json);
    ret = evr_ok;
 out_with_free_json:
    cJSON_Delete(json);
 out:
    return ret;
}

int expand_evr_glacier_storage_configuration(void *cfg){
    struct evr_glacier_storage_configuration *config = cfg;
    int ret = evr_error;
    evr_single_expand_property(config->cert_path, out);
    evr_single_expand_property(config->key_path, out);
    evr_single_expand_property(config->cert_root_path, out);
    evr_single_expand_property(config->bucket_dir_path, out);
    ret = evr_ok;
 out:
    return ret;
}
