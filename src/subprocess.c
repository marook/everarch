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

#include <unistd.h>

#include "errors.h"
#include "logger.h"

#define replace_fd(oldfd, newfd)                     \
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
        char* envp[] = { NULL };
        if(execve(argv[0], argv, envp)){
            evr_panic("Failed to execute %s", argv[0]);
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
        p->stdin = child_in[1];
        p->stdout = child_out[0];
        p->stderr = child_err[0];
    }
    ret = evr_ok;
 out:
    return ret;
 panic:
    evr_panic("Failed to prepare subprocess spawn");
    return evr_error;
}

#undef replace_fd
