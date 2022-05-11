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

#ifndef __evr_configuration_testutil_h__
#define __evr_configuration_testutil_h__

#include "glacier-storage-configuration.h"
#include "attr-index-db.h"

/**
 * create_temp_evr_glacier_storage_cfg allocates a new
 * struct evr_glacier_storage_cfg which points to a temporary
 * glacier directory.
 *
 * Every call can assume to point to an empty glacier.
 */
struct evr_glacier_storage_cfg *create_temp_evr_glacier_storage_cfg();

struct evr_attr_index_cfg *create_temp_attr_index_db_configuration();

#endif
