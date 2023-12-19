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

#include "subprocess.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "errors.h"
#include "logger.h"

#define replace_fd(oldfd, newfd)                \
    do {                                        \
        if(dup2(oldfd, newfd) < 0) {            \
            goto panic;                         \
        }                                       \
        if(close(oldfd) != 0){                  \
            goto panic;                         \
        }                                       \
    } while(0)

int evr_spawn(struct evr_subprocess *p, char *argv[]){
    int ret = evr_ok;
    log_debug("Spawn subprocess %s", argv[0]);
    int child_in[2];
    int child_out[2];
    int child_err[2];
    if(pipe(child_in)){
        goto out;
    }
    if(pipe(child_out)){
        goto panic;
    }
    if(pipe(child_err)){
        goto panic;
    }
    pid_t pid = fork();
    if(pid < 0){
        goto panic;
    }
    if(evr_log_fd == STDOUT_FILENO){
        // switch logging output to stderr. that should stream evr log
        // calls into the right direction until we call execvp later
        // in this function.
        evr_log_fd = STDERR_FILENO;
    }
    if (pid == 0) {
        for(int f = 0; f <= 2; ++f){
            if(close(f)){
                goto panic;
            }
        }
        if(close(child_in[1])){
            goto panic;
        }
        if(close(child_out[0])){
            goto panic;
        }
        if(close(child_err[0])){
            goto panic;
        }
        replace_fd(child_in[0], 0);
        replace_fd(child_out[1], 1);
        replace_fd(child_err[1], 2);
        if(execvp(argv[0], argv)){
            char err_buf[1024];
            char *err_msg = err_buf;
            int exec_errno = errno;
            if(evr_strerror_r(exec_errno, &err_msg, sizeof(err_buf)) != evr_ok){
                evr_panic("Unable to produce error message for errno %d", exec_errno);
            }
            evr_panic("Failed to execute %s: %s", argv[0], err_msg);
            goto out;
        }
    } else {
        if(close(child_in[0])){
            goto panic;
        }
        if(close(child_out[1])){
            goto panic;
        }
        if(close(child_err[1])){
            goto panic;
        }
        p->pid = pid;
        p->in = child_in[1];
        p->out = child_out[0];
        p->err = child_err[0];
    }
    ret = evr_ok;
 out:
    return ret;
 panic:
    evr_panic("Failed to prepare subprocess spawn");
    return evr_error;
}

#undef replace_fd
