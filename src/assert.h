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

#ifndef __assert_h__
#define __assert_h__

#include <stdarg.h>
#include <stdlib.h>

#include "basics.h"

#define evr_src_loc() (__FILE__ ":" to_string(__LINE__))

void loc_fail(const char *loc, const char *format, ...);
#define fail() loc_fail(evr_src_loc(), "Assertion failed")
#define fail_msg(msg, ...) loc_fail(evr_src_loc(), msg, __VA_ARGS__)

#define assert(check)                                   \
    do {                                                \
        if(!(check)) {                                  \
            fail();                                     \
        }                                               \
    } while(0)                                  

#define assert_msg(check, msg, ...)                      \
    do {                                                 \
        if(!(check)) {                                   \
            fail_msg(msg, __VA_ARGS__);                  \
        }                                                \
    } while(0)

int is_ok(int result);
int is_err(int result);
int is_str_eq(const char *a, const char *b);
int is_str_in(const char *haystack, const char *needle);

#endif
