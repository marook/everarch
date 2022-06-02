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

#ifdef EVR_PROFILE_SQLITE_STMTS
#include <time.h>
#endif

#include "logger.h"
#include "errors.h"

int evr_prepare_stmt(sqlite3 *db, const char *sql, sqlite3_stmt **stmt){
    log_debug("Prepare sqlite statement: %s", sql);
    if(sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("Failed to prepare statement '%s': %s", sql, sqlite_error_msg);
        return evr_error;
    }
    return evr_ok;
}

#define evr_stmt_log_msg_prefix "sqlite statement duration"

int evr_step_stmt(sqlite3 *db, sqlite3_stmt *stmt){
#ifdef EVR_PROFILE_SQLITE_STMTS
    struct timespec t_start;
    struct timespec t_end;
    if(clock_gettime(CLOCK_MONOTONIC, &t_start) != 0){
        evr_panic("Unable to measure evr_step_stmt step start time.");
        return SQLITE_ERROR;
    }
#endif
    int ret = sqlite3_step(stmt);
#ifdef EVR_PROFILE_SQLITE_STMTS
    if(clock_gettime(CLOCK_MONOTONIC, &t_end) != 0){
        evr_panic("Unable to measure evr_step_stmt step end time.");
        return SQLITE_ERROR;
    }
    long dt = t_end.tv_nsec - t_start.tv_nsec + (t_end.tv_sec - t_start.tv_sec) * 1000000000l;
    const char *raw_sql = sqlite3_sql(stmt);
    log_debug(evr_stmt_log_msg_prefix " raw %ldns: %s", dt, raw_sql);
    char *exp_sql = sqlite3_expanded_sql(stmt);
    if(exp_sql){
        log_debug(evr_stmt_log_msg_prefix " exp %ldns: %s", dt, exp_sql);
        sqlite3_free(exp_sql);
    } else {
        evr_panic("Unable to get expanded sql for statement with raw sql: %s", raw_sql);
        return SQLITE_ERROR;
    }
#endif
    if(ret != SQLITE_ROW && ret != SQLITE_DONE){
        const char *sqlite_error_msg = sqlite3_errmsg(db);
        log_error("Failed to step statement: %s", sqlite_error_msg);
    }
    return ret;
}

#undef evr_stmt_log_msg_prefix
