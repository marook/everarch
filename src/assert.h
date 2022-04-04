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

void fail(const char *format, ...);
void vfail(const char* format, va_list args);

void assert_zero(int i);
void assert_ok(int result);
void assert_ok_msg(int result, const char *format, ...);
void assert_err(int result);
void assert_err_msg(int result, const char *format, ...);
void assert_equal(int actual, int expected);
void assert_equal_msg(int actual, int expected, const char *format, ...);
void assert_greater_equal(long actual, long min);
void assert_greater_then(long actual, long min);
#define assert_true assert_truthy
void assert_truthy(int i);
void assert_null(const void *p);
void assert_not_null(const void *p);
void assert_not_null_msg(const void *p, const char *format, ...);
void assert_str_eq(const char *actual, const char *expected);
void assert_str_contains(const char *haystack, const char *needle);
void assert_int_eq(int actual, int expected);
void assert_int_eq_msg(int actual, int expected, const char *format, ...);
void assert_p_eq(void *actual, void *expected);
void assert_size_eq(size_t actual, size_t expected);

#endif
