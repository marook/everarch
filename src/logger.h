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

/*
 * logger.h defines a log interface with log levels and output to
 * stdout.
 *
 * log levels may only be enabled/disabled during compile time using
 * the defines EVR_LOG_DEBUG or EVR_LOG_INFO.
 */

#ifndef __logger_h__
#define __logger_h__

#include "config.h"

#include <stdlib.h>

/**
 * evr_log_fd is the file descriptor to which all log statements are
 * written.
 *
 * By default all logs are written to stdout. May be changed in order
 * to write to stderr.
 */
extern int evr_log_fd;

/**
 * evr_log_app is an extra identifier which is added to all log
 * statements. It should identify the application. Usefull if multiple
 * applications dump their logs to the same output stream.
 */
extern char *evr_log_app;

#define evr_log_level_debug "D"
#define evr_log_level_info "I"
#define evr_log_level_error "E"
#define evr_log_level_panic "P"

#ifdef EVR_LOG_DEBUG
#  ifndef EVR_LOG_INFO
#    define EVR_LOG_INFO 1
#  endif
#  define log_debug(args...) evr_log(evr_log_level_debug, args)
#else
#  define log_debug(args...)
#endif

#ifdef EVR_LOG_INFO
#  define log_info(args...) evr_log(evr_log_level_info, args)
#else
#  define log_info(args...)
#endif

#define log_error(args...) evr_log(evr_log_level_error, args)

int evr_setup_log(char *log_file);
int evr_teardown_log(void);

void evr_log(const char *level, const char *fmt, ...);

/**
 * evr_log_xml_error is compatible to libxml's error logging.
 */
void evr_log_xml_error(void *ctx, const char *msg, ...);

#define evr_panic(args...)                      \
    {                                           \
        evr_log(evr_log_level_panic, args);     \
        exit(1);                                \
    }

#endif
