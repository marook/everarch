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

#include "assert.h"

#ifdef EVR_HAVE_BACKTRACE
#include <execinfo.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "errors.h"

void vfail(const char* format, va_list args);

void loc_fail(const char *loc, const char *format, ...){
    const char *sep = ": assertion failed: ";
    const size_t sep_len = strlen(sep);
    size_t loc_len = strlen(loc);
    size_t fmt_len = strlen(format);
    char buf[loc_len + sep_len + fmt_len + 1 + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, loc);
    evr_push_concat(&bp, sep);
    evr_push_concat(&bp, format);
    evr_push_concat(&bp, "\n");
    evr_push_eos(&bp);
    va_list args;
    va_start(args, format);
    vfail(buf, args);
    va_end(args);
}

void print_backtrace();

void vfail(const char* format, va_list args){
    vfprintf(stderr, format, args);
    print_backtrace();
    exit(1);
}

void print_backtrace(){
#ifdef EVR_HAVE_BACKTRACE
    const size_t max_pointers = 100;
    void *buffer[max_pointers];
    int len = backtrace(buffer, max_pointers);
    backtrace_symbols_fd(buffer, len, 2);
#endif
}

int is_ok(int result){
    return result == evr_ok;
}

int is_err(int result){
    return result == evr_error;
}

int is_str_eq(const char *a, const char *b){
    return a && b && strcmp(a, b) == 0;
}

int is_str_in(const char *haystack, const char *needle){
    return haystack && needle && strstr(haystack, needle);
}

int path_exists(char *path){
    struct stat s;
    return stat(path, &s) == 0;
}
