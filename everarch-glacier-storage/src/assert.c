/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021  Markus Peröbner
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

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assert.h"

void print_backtrace();

void fail(const char *format, ...){
    va_list args;
    va_start(args, format);
    vfail(format, args);
    va_end(args);
}

void vfail(const char* format, va_list args){
    vfprintf(stderr, format, args);
    print_backtrace();
    exit(1);
}

void print_backtrace(){
    const size_t max_pointers = 100;
    void *buffer[max_pointers];
    int len = backtrace(buffer, max_pointers);
    backtrace_symbols_fd(buffer, len, 2);
}

void assert_zero(int i){
    if(i){
        fail("Expected %d to be 0\n", i);
    }
}

void assert_equal(int actual, int expected){
    assert_equal_msg(actual, expected, "Expected %d to be %d\n", actual, expected);
}

void assert_equal_msg(int actual, int expected, const char *format, ...){
    if(actual != expected){
        va_list args;
        va_start(args, format);
        vfail(format, args);
        va_end(args);
    }
}

void assert_greater_equal(int actual, int min){
    if(actual < min){
        fail("Expected %d to be >= %d\n", actual, min);
    }
}

void assert_truthy(int i){
    if(!i){
        fail("Expected %d to be truthy\n", i);
    }
}

void assert_null(const void *p){
    if(p){
        fail("Expected pointer to be null\n");
    }
}

void assert_not_null(const void *p){
    assert_not_null_msg(p, "Expected pointer to be not null\n");
}

void assert_not_null_msg(const void *p, const char *format, ...){
    if(!p){
        va_list args;
        va_start(args, format);
        vfail(format, args);
        va_end(args);
    }
}

#define assert_eq(formatStr) if(actual != expected) {fail("Expected " formatStr " to be " formatStr "\n", actual, expected);}

void assert_str_eq(const char *actual, const char *expected){
    assert_not_null_msg(actual, "actual must not be null\n");
    assert_not_null_msg(expected, "expected must not be null\n");
    if(strcmp(actual, expected)){
        fail("Expected '%s' to be '%s'\n", actual, expected);
    }
}

void assert_int_eq(int actual, int expected){
    assert_eq("%d");
}

void assert_size_eq(size_t actual, size_t expected){
    assert_eq("%ld");
}
