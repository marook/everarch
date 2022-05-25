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

#include "logger.h"

#include <alloca.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int evr_log_fd = STDOUT_FILENO;
char *evr_log_app = "";

const char *log_date_format = "%Y-%m-%dT%H:%M:%S";

void evr_log(const char *level, const char *fmt, ...){
    time_t t;
    time(&t);
    const size_t app_len = strlen(evr_log_app);
    const size_t level_len = strlen(level);
    const size_t fmt_len = strlen(fmt);
    // format: <log level> <datetime> <message fmt> \0
    const size_t log_fmt_size = app_len + level_len + 1 + 19 + 1 + fmt_len + 1 + 1;
    char *log_fmt = alloca(log_fmt_size);
    char *p = log_fmt;
    struct tm bt;
    localtime_r(&t, &bt);
    p += strftime(p, 19 + 1, log_date_format, &bt);
    *p++ = ' ';
    memcpy(p, evr_log_app, app_len);
    p += app_len;
    memcpy(p, level, level_len);
    p += level_len;
    *p++ = ' ';
    memcpy(p, fmt, fmt_len);
    p += fmt_len;
    *p++ = '\n';
    *p++ = '\0';
    va_list args;
    va_start(args, fmt);
    vdprintf(evr_log_fd, log_fmt, args);
    va_end(args);
}
