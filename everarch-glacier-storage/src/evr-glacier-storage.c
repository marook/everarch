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

/*
picoquic_quic_t *evr_bind_quic_server(const evr_glacier_storage_configuration *config){
    picoquic_quic_config_t config;
    picoquic_config_init(&config);

    
    picoquic_quic_t *ctx =
        picoquic_create(32, config->cert_path, config->key_path, NULL, PICOQUIC_SAMPLE_ALPN, sample_server_callback, &default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);
    if(!ctx){
        fprintf(stderr, "Could not bind quic server.\n");
        return NULL;
    }
    picoquic_set_cookie_mode(quic, 2);
    picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);
    picoquic_set_qlog(quic, qlog_dir);
    picoquic_set_log_level(quic, 1);
    picoquic_set_key_log_file_from_env(quic);
}
*/

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
