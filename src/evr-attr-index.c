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
#include <signal.h>
#include <stdatomic.h>

#include "errors.h"
#include "logger.h"

sig_atomic_t running = 1;

void handle_sigterm(int signum);

int main(){
    int ret = evr_error;
    {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_sigterm;
        sigaction(SIGINT, &action, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
    // TODO
    return ret;
}

void handle_sigterm(int signum){
    if(running){
        log_info("Shutting down");
        running = 0;
    }
}
