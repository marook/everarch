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

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int i, fd, err;
    char buf[1];
    ssize_t bytes_read;
    struct timespec ts;
    for(i = 1; i < argc; ++i){
        fd = open(argv[i], O_RDONLY);
        if(fd < 0){
            fprintf(stderr, "Unable to open file: %s\n", argv[i]);
            return 1;
        }
        for(;;){
            bytes_read = read(fd, buf, sizeof(buf));
            if(bytes_read == 0){
                break;
            } else if(bytes_read != sizeof(buf)) {
                err = errno;
                fprintf(stderr, "Unable to read file %s: %s\n", argv[i], strerror(err));
                return 1;
            }
            if(write(1, buf, sizeof(buf)) != sizeof(buf)){
                fprintf(stderr, "Writing file to stdout failed\n");
                return 1;
            }
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            if(nanosleep(&ts, NULL) != 0){
                fprintf(stderr, "Unable to sleep\n");
            }
        }
        if(close(fd) != 0){
            fprintf(stderr, "Unable to close file: %s\n", argv[i]);
            return 1;
        }
    }

    return 0;
}
