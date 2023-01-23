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

#include <stdlib.h>

#include "basics.h"

void evr_free_glacier_storage_cfg(struct evr_glacier_storage_cfg *cfg){
    if(!cfg){
        return;
    }
    char *str_options[] = {
        cfg->host,
        cfg->port,
        cfg->ssl_cert_path,
        cfg->ssl_key_path,
        cfg->bucket_dir_path,
        cfg->index_db_path,
        cfg->log_path,
        cfg->pid_path,
    };
    char **str_options_end = &str_options[static_len(str_options)];
    for(char **it = str_options; it != str_options_end; ++it){
        if(*it){
            free(*it);
        }
    }
    free(cfg);
}
