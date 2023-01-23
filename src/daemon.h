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

#ifndef daemon_h
#define daemon_h

#include "config.h"

/**
 * evr_daemonize forks this process into a daemon. This process will
 * exit after the fork.
 *
 * If pid_path is unequal NULL then evr_daemonize will write the pid
 * of the forked process into a file at pid_path.
 */
int evr_daemonize(char *pid_path);

#endif
