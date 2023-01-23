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

#include "daemon.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "errors.h"
#include "logger.h"

int evr_write_pid_file(char *path);

int evr_daemonize(char *pid_path){
    int ret = evr_error;
    int waiter_fd[2];
    if(pipe(waiter_fd) != 0){
        goto out;
    }
    int fork_res = fork();
    if(fork_res < 0){
        goto out_with_close_waiter_fd;
    } else if(fork_res > 0){
        char buf;
        if(read(waiter_fd[0], &buf, sizeof(buf)) != sizeof(buf)){
            evr_panic("Unable to wait for forked process");
            goto out_with_close_waiter_fd;
        }
        _exit(0);
        goto out;
    }
    if(pid_path && evr_write_pid_file(pid_path) != evr_ok){
        goto out_with_close_waiter_fd;
    }
    if(setsid() == -1){
        goto out_with_close_waiter_fd;
    }
    int null_fd = open("/dev/null", O_RDWR);
    if(null_fd < 0){
        goto out_with_close_waiter_fd;
    }
    if(dup2(null_fd, STDIN_FILENO) == -1){
        goto out_with_close_null_fd;
    }
    if(dup2(null_fd, STDOUT_FILENO) == -1){
        goto out_with_close_null_fd;
    }
    if(dup2(null_fd, STDERR_FILENO) == -1){
        goto out_with_close_null_fd;
    }
    {
        char buf = 1;
        if(write(waiter_fd[1], &buf, sizeof(buf)) != sizeof(buf)){
            log_error("Unable to signal fork completion to original process");
            goto out_with_close_null_fd;
        }
    }
    ret = evr_ok;
 out_with_close_null_fd:
    if(close(null_fd) != 0){
        evr_panic("Unable to close null_fd");
        ret = evr_error;
    }
 out_with_close_waiter_fd:
    if(close(waiter_fd[0]) != 0){
        evr_panic("Unable to close waiter_fd[0]");
        ret = evr_error;
    }
    if(close(waiter_fd[1]) != 0){
        evr_panic("Unable to close waiter_fd[1]");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_write_pid_file(char *path){
    int ret = evr_error;
    pid_t pid = getpid();
    char buf[32];
    int size = snprintf(buf, sizeof(buf), "%lu", (unsigned long)pid);
    if(size < 0 || size >= (int)sizeof(buf)){
        goto out;
    }
    int f = open(path, O_WRONLY | O_CREAT, 0744);
    if(f < 0){
        log_error("Unable to open pid file %s", path);
        goto out;
    }
    ssize_t written = write(f, buf, size);
    if(written != size){
        goto out_with_close_f;
    }
    ret = evr_ok;
 out_with_close_f:
    if(close(f) != 0){
        evr_panic("Unable to close pid file %s", path);
        ret = evr_error;
    }
 out:
    return ret;
}
