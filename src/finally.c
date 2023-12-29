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

#include <config.h>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "basics.h"
#include "logger.h"
#include "subprocess.h"
#include "errors.h"

static const int end_signals[] = {
    SIGINT,
    SIGTERM,
};

int main(int argc, char **argv){
    int ret = 1;
    size_t i;
    sigset_t ss;
    siginfo_t info;
    struct evr_subprocess sp;
    int res;
    const char *nt_argv[argc + 1 - 1];
    evr_log_app = "F";
    evr_init_basics();
    if(sigemptyset(&ss) != 0){
        goto out;
    }
    for(i = 0; i < static_len(end_signals); ++i){
        if(sigaddset(&ss, end_signals[i]) != 0){
            log_error("Unable to add signal %d to set", end_signals[i]);
            goto out;
        }
    }
    if (sigprocmask(SIG_BLOCK, &ss, NULL) == -1) {
        log_error("Unable to block end signals");
        goto out;
    }    
    log_debug("Waiting for end signals");
    if(sigwaitinfo(&ss, &info) <= 0){
        log_error("Unable to wait for signal");
        goto out;
    }
    log_debug("End signal retieved. Spawning subprocess.");
    for(i = 0; i < (size_t)(argc - 1); ++i){
        nt_argv[i] = argv[i + 1];
    }
    nt_argv[argc - 1] = NULL;
    if(evr_spawn(&sp, nt_argv) != evr_ok){
        log_error("Unable to spawn subprocess");
        goto out;
    }
    close(sp.in);
    if(evr_subprocess_pipe_output(&sp, STDOUT_FILENO) != evr_ok){
        goto out;
    }
    log_debug("Waiting for subprocess termination");
    if(waitpid(sp.pid, &res, WUNTRACED) < 0){
        evr_panic("Unable to wait for subprocess");
    }
    if(res == 0){
        ret = 0;
    } else {
        log_error("Subprocess failed with exit code %d", res);
    }
 out:
    return ret;
}
