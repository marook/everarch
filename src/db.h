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

#ifndef __db_h__
#define __db_h__

#include "config.h"

#include <sqlite3.h>

/**
 * evr_sqlite3_busy_timeout defines the amount of milliseconds which
 * evr sqlite3 databases should wait for sqlite locks until they give
 * up.
 *
 * For more details see https://sqlite.org/c3ref/busy_timeout.html
 */
#define evr_sqlite3_busy_timeout 1000

int evr_prepare_stmt(sqlite3 *db, const char *sql, sqlite3_stmt **stmt);

int evr_step_stmt(sqlite3 *db, sqlite3_stmt *stmt);

#endif

