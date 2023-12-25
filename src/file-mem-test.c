/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
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

#include "assert.h"
#include "test.h"
#include "file-mem.h"

void test_write_and_read(void){
    struct evr_file_mem fm;
    struct evr_file f;
    char data[] = "hi";
    char buf[sizeof(data)];
    assert(is_ok(evr_init_file_mem(&fm, 16, 16)));
    evr_file_bind_file_mem(&f, &fm);
    assert(f.write(&f, data, sizeof(data)) == sizeof(data));
    assert(f.read(&f, buf, sizeof(buf)) == 0);
    fm.offset = 0;
    assert(f.read(&f, buf, sizeof(buf)) == sizeof(data));
    assert(strcmp("hi", buf) == 0);
    evr_destroy_file_mem(&fm);
}

void test_write_and_read_realloc(void){
    struct evr_file_mem fm;
    struct evr_file f;
    char data[] = "hello world!";
    char buf[sizeof(data)];
    assert(is_ok(evr_init_file_mem(&fm, 2, 16)));
    evr_file_bind_file_mem(&f, &fm);
    assert(f.write(&f, data, sizeof(data)) == sizeof(data));
    assert(f.read(&f, buf, sizeof(buf)) == 0);
    fm.offset = 0;
    assert(f.read(&f, buf, sizeof(buf)) == sizeof(data));
    assert(strcmp("hello world!", buf) == 0);
    evr_destroy_file_mem(&fm);
}

void test_write_and_read_max_size_reached(void){
    struct evr_file_mem fm;
    struct evr_file f;
    char data[] = "hello world!";
    char buf[3];
    assert(is_ok(evr_init_file_mem(&fm, 2, 4)));
    evr_file_bind_file_mem(&f, &fm);
    assert(f.write(&f, data, sizeof(data)) == -1);
    assert(f.read(&f, buf, sizeof(buf)) == 0);
    evr_destroy_file_mem(&fm);
}

int main(void){
    run_test(test_write_and_read);
    run_test(test_write_and_read_realloc);
    run_test(test_write_and_read_max_size_reached);
    return 0;
}
