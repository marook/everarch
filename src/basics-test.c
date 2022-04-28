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

#include "config.h"

#include <string.h>

#include "assert.h"
#include "basics.h"
#include "test.h"

void test_evr_trim(){
    char *s;
    char *start;
    char *end;
    
    s = "hello";
    evr_trim(&start, &end, s);
    assert(start == s);
    assert(&s[strlen(s)] == end);

    evr_trim(&start, &end, "");
    assert(start == end);

    evr_trim(&start, &end, " ");
    assert(start == end);

    evr_trim(&start, &end, "\t");
    assert(start == end);

    evr_trim(&start, &end, "\n");
    assert(start == end);

    evr_trim(&start, &end, " \t");
    assert(start == end);

    s = " x ";
    evr_trim(&start, &end, s);
    assert(start == &s[1]);
    assert(end == &s[2]);
}

#define assert_invalid_syntaxt(s)                                       \
    do {                                                                \
        evr_time t;                                                     \
        assert_msg(is_err(evr_time_from_iso8601(&t, s)), "Expected " s " to be invalid syntax but was successfully parsed\n", NULL); \
    } while(0)

void test_evr_time(){
    evr_time t_past, t_future;
    assert(is_ok(evr_time_from_iso8601(&t_past, "2022-04-01T12:01:02.123000Z")));
    assert(is_ok(evr_time_from_iso8601(&t_future, "2022-04-01T13:00:00.000000Z")));
    assert(t_past < t_future);
    assert(t_future > t_past);
    assert(t_past != t_future);
    char buf[evr_max_time_iso8601_size];
    evr_time_to_iso8601(buf, sizeof(buf), &t_past);
    assert(is_str_eq(buf, "2022-04-01T12:01:02.123000Z"));
    evr_time_add_ms(&t_past, 345);
    evr_time_to_iso8601(buf, sizeof(buf), &t_past);
    assert(is_str_eq(buf, "2022-04-01T12:01:02.468000Z"));
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    evr_time t;
    evr_time_from_timespec(&t, &ts);
    evr_time_to_iso8601(buf, sizeof(buf), &t);
    assert(is_str_eq(buf, "1970-01-01T00:00:00.000000Z"));
    assert_invalid_syntaxt("2022-04-01T12:01:02.123000");
    assert_invalid_syntaxt("2022-04-01T12:01:02.12000Z");
    assert_invalid_syntaxt("2022-04-01T12:01:02.12000aZ");
    assert_invalid_syntaxt("2022-04-01T12:01:021000Z");
}

#undef assert_invalid_syntaxt

int main(){
    run_test(test_evr_trim);
    run_test(test_evr_time);
    return 0;
}
