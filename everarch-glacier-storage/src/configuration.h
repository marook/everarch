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

#ifndef __configuration_h__
#define __configuration_h__

/**
 * evr_glacier_storage_configuration aggregates configuration options
 * for the evr-glacier-storage application.
 *
 * All pointers within this structure must be freed using
 * free_evr_glacier_storage_configuration function.
 */
typedef struct {
    char *cert_path;
    char *key_path;
    char *cert_root_path;
} evr_glacier_storage_configuration;

evr_glacier_storage_configuration *create_evr_glacier_storage_configuration();

void free_evr_glacier_storage_configuration(evr_glacier_storage_configuration *config);

int load_evr_glacier_storage_configurations(evr_glacier_storage_configuration *config, const char **paths, size_t paths_len);

int merge_evr_glacier_storage_configuration_file(evr_glacier_storage_configuration *config, const char *config_path);

#endif
