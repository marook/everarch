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

#include "attr-index-db-configuration.h"

#include <stdlib.h>

#include "configurations.h"
#include "errors.h"

#define free_pointer(p)                         \
    if(p){                                      \
        free(p);                                \
    }

struct evr_attr_index_db_configuration *evr_create_attr_index_db_configuration(){
    struct evr_attr_index_db_configuration *cfg = malloc(sizeof(struct evr_attr_index_db_configuration));
    if(!cfg){
        goto out;
    }
    cfg->state_dir_path = NULL;
    replace_string(cfg->state_dir_path, "~/var/everarch/attr-index", out_with_free_cfg);
 out:
    return cfg;
 out_with_free_cfg:
    free(cfg);
    return NULL;
}

void evr_free_attr_index_db_configuration(struct evr_attr_index_db_configuration *cfg){
    if(!cfg){
        return;
    }
    free_pointer(cfg->state_dir_path);
    free(cfg);
}

int evr_merge_attr_index_db_configuration(void *config, const char *config_path){
    struct evr_attr_index_db_configuration *cfg = config;
    int ret = evr_error;
    cJSON *json = evr_parse_json_config(config_path);
    if(!json){
        goto out;
    }
    if(!cJSON_IsObject(json)){
        goto out_with_free_json;
    }
    replace_string(cfg->state_dir_path, evr_get_object_string_property(json, "state_dir"), out_with_free_json);
    ret = evr_ok;
 out_with_free_json:
    cJSON_Delete(json);
 out:
    return ret;
}

int evr_expand_attr_index_db_configuration(void *config){
    struct evr_attr_index_db_configuration *cfg = config;
    int ret = evr_error;
    evr_single_expand_property(cfg->state_dir_path, out);
    ret = evr_ok;
 out:
    return ret;
}
