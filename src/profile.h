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
 * profile.h provides utilities for profiling execution durations of
 * caller defined code blocks.
 *
 * You may want to do the following:
 *
 * evr_profile_block_enter(disk_write);
 * ye_profiled_op_1();
 * ye_profiled_op_2();
 * evr_profile_block_leave(disk_write);
 *
 * Profiling results will be written to log with level debug.
 */

#ifndef profile_h
#define profile_h

#include "config.h"

#include <time.h>

#include "logger.h"

/**
 * evr_profile_block_enter starts a duration measurement identified by
 * name.
 *
 * You should use evr_profile_block_leave to measure the duration and
 * log the duration. If necessary measuring and logging can be
 * performed separately with evr_profile_block_measure and
 * evr_profile_block_log.
 */
#define evr_profile_block_enter(name)                                   \
    struct timespec profile_block_ ## name ## _t_start;                 \
    struct timespec profile_block_ ## name ## _t_end;                   \
    do {                                                                \
        if(clock_gettime(CLOCK_MONOTONIC, &profile_block_ ## name ## _t_start) != 0){ \
            evr_panic("Unable to measure profile block start time for " #name "."); \
        }                                                               \
    } while(0)

#define evr_profile_block_measure(name)                                 \
    do {                                                                \
        if(clock_gettime(CLOCK_MONOTONIC, &profile_block_ ## name ## _t_end) != 0){ \
            evr_panic("Unable to measure profile block end time for " #name "."); \
        }                                                               \
    } while(0)

/**
 * evr_profile_block_log logs the measurement. If no extra formatting
 * arguments are required use "" for fmt and NULL for args.
 */
#define evr_profile_block_log(name, log_prefix, fmt, args...)           \
    do {                                                                \
        long dt =                                                       \
            profile_block_ ## name ## _t_end.tv_nsec - profile_block_ ## name ## _t_start.tv_nsec \
            + (profile_block_ ## name ## _t_end.tv_sec - profile_block_ ## name ## _t_start.tv_sec) * 1000000000l; \
        log_debug(log_prefix " " #name " %ldns" fmt, dt, args);         \
    } while(0)

/**
 * evr_profile_block_log measures the duration and logs the
 * duration. If no extra formatting arguments are required use "" for
 * fmt and NULL for args.
 */
#define evr_profile_block_leave(name, log_prefix, fmt, args...) \
    do {                                                        \
        evr_profile_block_measure(name);                        \
        evr_profile_block_log(name, log_prefix, fmt, args);     \
    } while(0)

#endif
