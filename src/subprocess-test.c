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
#include <unistd.h>
#include <sys/wait.h>

#include "assert.h"
#include "test.h"
#include "subprocess.h"
#include "errors.h"
#include "files.h"
#include "logger.h"

void test_cat_subprocess(){
    struct evr_subprocess sp;
    char *argv[] = {
        "/bin/cat",
        "-",
        NULL
    };
    assert_ok(evr_spawn(&sp, argv));
    const char msg[] = "hello world!";
    const size_t msg_len = strlen(msg);
    assert_ok_msg(write_n(sp.stdin, msg, msg_len), "Failed to write to subprocess\n");
    assert_zero(close(sp.stdin));
    char buf[msg_len + 1];
    assert_ok_msg(read_n(sp.stdout, buf, msg_len), "Failed to read from subprocess\n");
    buf[sizeof(buf) - 1] = '\0';
    assert_str_eq(msg, buf);
    assert_zero(close(sp.stdout));
    assert_zero(close(sp.stderr));
    int status;
    assert_greater_equal(waitpid(sp.pid, &status, WUNTRACED), 0);
    assert_zero(status);
}

void test_false_subprocess(){
    struct evr_subprocess sp;
    char *argv[] = {
        "/bin/false",
        NULL
    };
    assert_ok(evr_spawn(&sp, argv));
    assert_zero(close(sp.stdin));
    assert_zero(close(sp.stdout));
    assert_zero(close(sp.stderr));
    int status;
    assert_greater_equal(waitpid(sp.pid, &status, WUNTRACED), 0);
    assert_truthy(status);
}

void test_pass_path_to_subprocess(){
    struct evr_subprocess sp;
    char *argv[] = {
        "/bin/sh",
        "-c",
        "echo PATH=$PATH",
        NULL
    };
    char *my_path = evr_env_path();
    // if the following assert breaks you have to extend this test to
    // support not existing PATH environment variables
    assert_not_null(my_path);
    assert_ok(evr_spawn(&sp, argv));
    assert_zero(close(sp.stdin));
    char sp_path[4096];
    ssize_t bytes_read = read(sp.stdout, sp_path, sizeof(sp_path));
    sp_path[min(bytes_read, sizeof(sp_path)) - 1] = '\0';
    assert_zero(strncmp(my_path, sp_path, sizeof(sp_path) - 1));
    assert_zero(close(sp.stdout));
    assert_zero(close(sp.stderr));
    int status;
    assert_greater_equal(waitpid(sp.pid, &status, WUNTRACED), 0);
    assert_zero(status);
}

int main(){
    run_test(test_cat_subprocess);
    run_test(test_false_subprocess);
    run_test(test_pass_path_to_subprocess);
    return 0;
}
