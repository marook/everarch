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

/*
 * subprocess.h contains functions for spawning new sub processes.
 */

#ifndef subprocess_h
#define subprocess_h

#include "config.h"

#include <sys/types.h>

struct evr_subprocess {
    pid_t pid;
    int in;
    int out;
    int err;
};

/**
 * evr_spawn forks a new process and executes the arguments given in argv.
 *
 * The spawned process details are written to p. The caller must close
 * in, out and err if evr_spawn returns with evr_ok.
 *
 * as_user is the username as which the subprocess is executed. It may
 * be NULL if the user should not be switched.
 *
 * Returns evr_ok on success.
 */
int evr_spawn(struct evr_subprocess *p, const char *argv[], const char *as_user);

int evr_subprocess_pipe_output(struct evr_subprocess *p, int out_fd);

#endif
