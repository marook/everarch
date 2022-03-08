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

#include "configurations.h"

#include <ctype.h>
#include <unistd.h>
#include <wordexp.h>

#include "errors.h"
#include "files.h"
#include "logger.h"

int evr_single_wordexp(char **pathname){
    int ret = evr_error;
    if(*pathname){
        wordexp_t p;
        wordexp(*pathname, &p, 0);
        if(p.we_wordc != 1){
            log_error("Pathname %s must only expand to one file", *pathname);
            goto out_with_free_p;
        }
        replace_string(*pathname, p.we_wordv[0], out_with_free_p);
        ret = evr_ok;
    out_with_free_p:
        wordfree(&p);
    } else {
        ret = evr_ok;
    }
    return ret;
}

int is_json_ignored(int c);

cJSON *evr_parse_json_config(const char *path){
    cJSON *json = NULL;
    struct dynamic_array *buf = alloc_dynamic_array(4096);
    if(!buf){
        goto out;
    }
    if(read_file_str(&buf, path, 1*1024*1024)){
        log_error("Failed to read configuration file %s\n", path);
        goto out_with_free_buf;
    }
    rtrim_dynamic_array(buf, is_json_ignored);
    ((char*)buf->data)[buf->size_used] = '\0';
    json = cJSON_Parse((char*)buf->data);
    if(!json){
        log_error("Failed to parse JSON from %s at '%s'\n", path, cJSON_GetErrorPtr());
        goto out_with_free_buf;
    }
 out_with_free_buf:
    free(buf);
 out:
    return json;
}

int is_json_ignored(int c){
    return c == 0 || isspace(c);
}

int evr_load_configurations(void *config, const char **paths, size_t paths_len, int (*merge)(void *config, const char *config_path), int (*expand)(void *config)){
    int ret = evr_error;
    const char **paths_end = &(paths[paths_len]);
    wordexp_t we;
    for(const char **p = paths; p != paths_end; p++){
        wordexp(*p, &we, 0);
        for(int i = 0; i < we.we_wordc; ++i){
            char *pe = we.we_wordv[i];
            if(access(pe, F_OK)){
                // path *p does not exist
                continue;
            }
            log_debug("Load configuration from %s", pe);
            if(merge(config, pe) != evr_ok){
                wordfree(&we);
                goto out;
            }
        }
        wordfree(&we);
    }
    if(expand(config) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

char *evr_get_object_string_property(const cJSON *obj, const char* key){
    cJSON *str = cJSON_GetObjectItem(obj, key);
    if(!str){
        return NULL;
    }
    return cJSON_GetStringValue(str);
}
