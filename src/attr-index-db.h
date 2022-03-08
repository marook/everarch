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

#ifndef __attr_index_db_h__
#define __attr_index_db_h__

#include "config.h"

#include <sqlite3.h>

#include "attr-index-db-configuration.h"
#include "claims.h"

struct evr_attr_ops {
    sqlite3_stmt *insert_attr;
};

struct evr_attr_index_db {
    sqlite3 *db;
    struct evr_attr_ops str_ops;
    struct evr_attr_ops int_ops;
};

struct evr_attr_index_db *evr_open_attr_index_db(struct evr_attr_index_db_configuration *cfg, char *name);

int evr_free_glacier_index_db(struct evr_attr_index_db *db);

/**
 * evr_setup_attr_index_db sets up an empty attr-index db.
 */
int evr_setup_attr_index_db(struct evr_attr_index_db *db, struct evr_attr_spec_claim *spec);

#endif
