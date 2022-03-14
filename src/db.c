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

#include "db.h"

#include "logger.h"
#include "errors.h"

int evr_prepare_stmt(sqlite3 *db, const char *sql, sqlite3_stmt **stmt){
    log_debug("Prepare sqlite stamenent: %s", sql);
    if(sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("Failed to prepare statement '%s': %s", sql, sqlite_error_msg);
        return evr_error;
    }
    return evr_ok;
}

int evr_step_stmt(sqlite3 *db, sqlite3_stmt *stmt){
    int ret = sqlite3_step(stmt);
    if(ret != SQLITE_ROW && ret != SQLITE_DONE){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("Failed to step statement: %s", sqlite_error_msg);
    }
    return ret;
}
