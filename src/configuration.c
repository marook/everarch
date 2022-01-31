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

#include "configuration.h"

#include <cjson/cJSON.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "memory.h"
#include "files.h"
#include "logger.h"

#define replace_string(dest, src, error_target) {char *src_var = src; if(src_var){if(dest){free(dest);} size_t src_len = strlen(src_var); dest = malloc(src_len+1); if(!dest){goto error_target;} memcpy(dest, src_var, src_len+1);}}

#define free_pointer(p) if(p){free(p);}

char *get_object_string_property(const cJSON *obj, const char* key);
int is_json_ignored(int c);

evr_glacier_storage_configuration *create_evr_glacier_storage_configuration(){
    evr_glacier_storage_configuration *config = (evr_glacier_storage_configuration*)malloc(sizeof(evr_glacier_storage_configuration));
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

void free_evr_glacier_storage_configuration(evr_glacier_storage_configuration *config){
    if(!config){
        return;
    }
    free_pointer(config->cert_path);
    free_pointer(config->key_path);
    free_pointer(config->cert_root_path);
    free_pointer(config->bucket_dir_path);
    free(config);
}

int load_evr_glacier_storage_configurations(evr_glacier_storage_configuration *config, const char **paths, size_t paths_len){
    const char **paths_end = &(paths[paths_len]);
    for(const char **p = paths; p != paths_end; p++){
        if(access(*p, F_OK)){
            // path *p does not exist
            continue;
        }
        if(merge_evr_glacier_storage_configuration_file(config, *p)){
            return 1;
        }
    }
    return 0;
}

int merge_evr_glacier_storage_configuration_file(evr_glacier_storage_configuration *config, const char *config_path){
    dynamic_array *buffer = alloc_dynamic_array(4096);
    if(!buffer){
        return 1;
    }
    int ret = 1;
    if(read_file_str(&buffer, config_path, 1*1024*1024)){
        log_error("Failed to read evr-glacier-storage configuration file content at %s\n", config_path);
        goto end_buffer;
    }
    rtrim_dynamic_array(buffer, is_json_ignored);
    ((char*)buffer->data)[buffer->size_used] = '\0';
    
    cJSON *json = cJSON_Parse((char*)buffer->data);
    if(!json){
        log_error("Failed to parse JSON from %s at '%s'\n", config_path, cJSON_GetErrorPtr());
        goto end_buffer;
    }
    if(!cJSON_IsObject(json)){
        goto end_json;
    }
    replace_string(config->cert_path, get_object_string_property(json, "cert_path"), end_json);
    replace_string(config->key_path, get_object_string_property(json, "key_path"), end_json);
    replace_string(config->cert_root_path, get_object_string_property(json, "cert_root_path"), end_json);
    // TODO replace max_bucket_size
    replace_string(config->bucket_dir_path, get_object_string_property(json, "bucket_dir_path"), end_json);
    ret = 0;
 end_json:
    cJSON_Delete(json);
 end_buffer:
    free(buffer);
    return ret;
}

int is_json_ignored(int c){
    return c == 0 || isspace(c);
}

char *get_object_string_property(const cJSON *obj, const char* key){
    cJSON *str = cJSON_GetObjectItem(obj, key);
    if(!str){
        return NULL;
    }
    return cJSON_GetStringValue(str);
}
