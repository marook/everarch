/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021  Markus Peröbner
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

#include <picoquic.h>
#include <stdio.h>

#include "configuration.h"

int main(){
    evr_glacier_storage_configuration *config = create_evr_glacier_storage_configuration();
    if(!config){
        return 1;
    }
    const char *config_paths[] = {
        "~/.config/everarch/glacier-storage.json",
        "glacier-storage.json",
    };
    if(load_evr_glacier_storage_configurations(config, config_paths, sizeof(config_paths) / sizeof(char*))){
        return 1;
    }
    // TODO start server
    return 0;
}
