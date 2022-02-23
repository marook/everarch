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
    assert_p_eq(start, s);
    assert_p_eq(&s[strlen(s)], end);

    evr_trim(&start, &end, "");
    assert_p_eq(start, end);

    evr_trim(&start, &end, " ");
    assert_p_eq(start, end);

    evr_trim(&start, &end, "\t");
    assert_p_eq(start, end);

    evr_trim(&start, &end, "\n");
    assert_p_eq(start, end);

    evr_trim(&start, &end, " \t");
    assert_p_eq(start, end);

    s = " x ";
    evr_trim(&start, &end, s);
    assert_p_eq(start, &s[1]);
    assert_p_eq(end, &s[2]);
}

int main(){
    run_test(test_evr_trim);
    return 0;
}
