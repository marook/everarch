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

#include "basics.h"

#include <string.h>
#include <stdio.h>

#include "logger.h"
#include "errors.h"

#define is_whitespace(w) (w != ' ' && w != '\t' && w != '\n')

void evr_trim(char **start, char **end, char *s){
    *start = s;
    *end = &s[strlen(s)];
    for(; !is_whitespace(**start) && *start != *end; ++(*start)){
    }
    for(; *end != *start && !is_whitespace(*(*end - 1)); --(*end)){
    }
}

void evr_now(evr_time *t){
    struct timespec ts;
    if(clock_gettime(CLOCK_REALTIME, &ts) != 0){
        evr_panic("Can't get time");
    }
    evr_time_from_timespec(t, &ts);
}

const char *evr_iso_8601_timestamp_fmt = "%FT%TZ";
#define evr_second_fraction_digits 6

int evr_time_from_iso8601(evr_time *t, const char *s){
    int ret = evr_error;
    size_t slen = strlen(s);
    if(slen < 2 + evr_second_fraction_digits){
        goto out;
    }
    const char *p = &s[slen - (2 + evr_second_fraction_digits)];
    const char *dot_s = p++;
    if(*dot_s != '.'){
        goto out;
    }
    const char *ms_s = p;
    for(int i = 0; i < evr_second_fraction_digits; ++i){
        char c = *p++;
        if(c < '0' || c > '9'){
            goto out;
        }
    }
    if(*p != 'Z'){
        goto out;
    }
    int ms;
    if(sscanf(ms_s, "%0" to_string(evr_second_fraction_digits) "d", &ms) != 1){
        goto out;
    }
    struct tm tm;
    {
        size_t buf_len = dot_s - s + 1;
        char buf[buf_len];
        memcpy(buf, s, buf_len - 1);
        buf[buf_len - 1] = 'Z';
        buf[buf_len] = '\0';
        char *end = &buf[buf_len];
        if(strptime(buf, evr_iso_8601_timestamp_fmt, &tm) != end){
            goto out;
        }
    }
    *t = ((evr_time)timegm(&tm)) * 1000 + ms / 1000;
    ret = evr_ok;
 out:
    return ret;
}

void evr_time_to_iso8601(char *s, size_t s_size, const evr_time *t){
    time_t tt = *t / 1000;
    int ms = (*t % 1000) * 1000;
    struct tm tm;
    gmtime_r(&tt, &tm);
    strftime(s, s_size, evr_iso_8601_timestamp_fmt, &tm);
    size_t slen = strlen(s);
    char *p = &s[slen - 1];
    if(*p != 'Z'){
        evr_panic("strftime produced an ISO 8601 date format which can't be handled: %s", s);
    }
    if(slen + 1 + evr_second_fraction_digits + 1 >= s_size){
        evr_panic("Unable to format ISO 8601 date into buffer with just %u bytes", s_size);
    }
    *p++ = '.';
    sprintf(p, "%0" to_string(evr_second_fraction_digits) "dZ", ms);
}
