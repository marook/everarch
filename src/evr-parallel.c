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

#include <stddef.h>
#include <threads.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>

#include "basics.h"
#include "errors.h"
#include "logger.h"
#include "subprocess.h"
#include "files.h"

struct evr_cmd {
    size_t args_len;
    char **args;
    char *run_as_user;
    pid_t pid;
};

static int stopping = 0;
static int running_counter = 0;
static int any_cmd_failed = 0;
static mtx_t status_lock;
static cnd_t status_cnd;
static size_t cmds_max_len;
static struct evr_cmd *cmds = NULL;

static void evr_handle_delegate_signal(int signum);

static int evr_split_cmds(struct evr_cmd *cmds, size_t cmds_len, size_t argc, char **argv);

static int evr_start_cmds(struct evr_cmd *cmds, size_t cmds_len);

int main(int argc, char **argv){
    int ret = 1;
    evr_log_app = "p";
    evr_init_basics();
    cmds_max_len = max(16, evr_page_size / sizeof(struct evr_cmd));
    cmds = malloc(cmds_max_len * sizeof(struct evr_cmd));
    if(!cmds){
        goto out;
    }
    memset(cmds, 0, cmds_max_len * sizeof(struct evr_cmd));
    if(evr_split_cmds(cmds, cmds_max_len, argc, argv) != evr_ok){
        goto out_with_free_cmds;
    }
    if(mtx_init(&status_lock, mtx_plain) != thrd_success){
        goto out_with_free_cmds;
    }
    if(cnd_init(&status_cnd) != thrd_success){
        goto out_with_destroy_status_lock;
    }
    if(mtx_lock(&status_lock) != thrd_success){
        goto out_with_destroy_status_cnd;
    }
    {
        struct sigaction action = { 0 };
        action.sa_handler = evr_handle_delegate_signal;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    if(evr_start_cmds(cmds, cmds_max_len) != evr_ok){
        goto out_with_unlock_status_lock;
    }
    while(running_counter){
        if(cnd_wait(&status_cnd, &status_lock) != thrd_success){
            evr_panic("Unable to wait for status signal");
        }
    }
    ret = 0;
 out_with_unlock_status_lock:
    if(mtx_unlock(&status_lock) != thrd_success){
        evr_panic("Unable to unlock status lock on teardown");
    }
    if(ret == 0){
        ret = any_cmd_failed;
    }
 out_with_destroy_status_cnd:
    cnd_destroy(&status_cnd);
 out_with_destroy_status_lock:
    mtx_destroy(&status_lock);
 out_with_free_cmds:
    free(cmds);
 out:
    return ret;
}

void evr_handle_delegate_signal(int signum){
    struct evr_cmd *p_it, *p_end;
    const union sigval sigval = { 0 };
    stopping = 1;
    log_debug("Sending signal %d to commands", signum);
    p_end = &cmds[cmds_max_len];
    for(p_it = cmds; p_it != p_end; ++p_it){
        if(!p_it->pid){
            continue;
        }
        if(sigqueue(p_it->pid, signum, sigval) != 0){
            log_error("Unable to send signal %d to pid %" PRIdMAX, signum, (intmax_t)p_it->pid);
        }
    }
}

static int evr_split_cmds(struct evr_cmd *cmds, size_t cmds_len, size_t argc, char **argv){
    size_t i;
    struct evr_cmd *ca, *ca_end;
    ca = cmds;
    ca_end = &cmds[cmds_len];
    for(i = 1; i < argc; ++i){
        if(strcmp(argv[i], ";") == 0){
            ++ca;
            if(ca == ca_end){
                return evr_error;
            }
            continue;
        }
        if(ca->args_len == 0){
            if(strcmp(argv[i], "--user") == 0){
                if(i + 1 >= argc){
                    log_error("Expecting username after --user argument");
                    return evr_error;
                }
                ca->run_as_user = argv[++i];
            } else {
                ca->args = &argv[i];
                ++ca->args_len;
            }
        } else {
            ++ca->args_len;
        }
    }
    return evr_ok;
}

static int evr_run_cmd(void *ctx);

static int evr_start_cmds(struct evr_cmd *cmds, size_t cmds_len){
    struct evr_cmd *ca, *ca_end;
    thrd_t thrd;
    ca_end = &cmds[cmds_len];
    for(ca = cmds; ca != ca_end; ++ca){
        if(ca->args_len == 0){
            break;
        }
        if(stopping){
            break;
        }
        ++running_counter;
        if(thrd_create(&thrd, evr_run_cmd, ca) != thrd_success){
            evr_panic("Unable to create command runner thread");
        }
        if(thrd_detach(thrd) != thrd_success){
            evr_panic("Unable to detach from command runner thread");
        }
    }
    return evr_ok;
}

static int evr_term_all_cmds(void);

static int evr_run_cmd(void *ctx){
    struct evr_cmd *cmd = ctx;
    struct evr_subprocess p;
    int res;
    const char *argv[cmd->args_len + 1];
    log_debug("Running command %s", cmd->args[0]);
    memcpy(argv, cmd->args, sizeof(char*) * cmd->args_len);
    argv[cmd->args_len] = NULL;
    if(stopping){
        return 0;
    }
    if(evr_spawn(&p, argv, cmd->run_as_user) != evr_ok){
        evr_panic("Unable to spawn %s", argv[0]);
    }
    cmd->pid = p.pid;
    close(p.in);
    if(evr_subprocess_pipe_output(&p, STDOUT_FILENO) != evr_ok){
        evr_panic("Unable to pipe output streams for command %s", cmd->args[0]);
    }
    if(waitpid(p.pid, &res, WUNTRACED) < 0){
        evr_panic("Unable to wait for command %s", cmd->args[0]);
    }
    cmd->pid = 0;
    log_debug("Command %s ended with exit code %d", cmd->args[0], res);
    if(res != 0){
        stopping = 1;
        log_error("Command failed: %s", cmd->args[0]);
        if(evr_term_all_cmds()){
            evr_panic("Unable to terminate commands");
        }
        exit(1);
    }
    if(mtx_lock(&status_lock) != thrd_success){
        evr_panic("Unable to lock status lock");
    }
    running_counter -= 1;
    if(mtx_unlock(&status_lock) != thrd_success){
        evr_panic("Unable to unlock status lock");
    }
    if(cnd_broadcast(&status_cnd) != thrd_success){
        evr_panic("Unable to signal status condition");
    }
    return 0;
}

static int evr_term_all_cmds(void){
    int ret = evr_ok;
    struct evr_cmd *p_it, *p_end;
    const union sigval sigval = { 0 };
    stopping = 1;
    log_debug("Sending SIGTERM to commands");
    p_end = &cmds[cmds_max_len];
    for(p_it = cmds; p_it != p_end; ++p_it){
        if(!p_it->pid){
            continue;
        }
        if(sigqueue(p_it->pid, SIGTERM, sigval) != 0){
            log_error("Unable to send SIGTERM to pid %" PRIdMAX, (intmax_t)p_it->pid);
            ret = evr_error;
        }
    }
    return ret;
}
