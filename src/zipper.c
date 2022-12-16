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

#include <unistd.h>
#include <fcntl.h>

#include "logger.h"

int main(int argc, char *argv[]){
    int ret = 1;
    evr_log_fd = STDERR_FILENO;
    evr_log_app = "z";
    const int file_count = argc - 1;
    int fds[file_count];
    for(int i = 0; i < file_count; ++i){
        fds[i] = -1;
    }
    for(int i = 0; i < file_count; ++i){
        int f = open(argv[i + 1], O_RDONLY);
        if(f < 0){
            goto out_with_close_files;
        }
        fds[i] = f;
    }
    char buf[1];
    for(int open_fds = file_count; open_fds > 0;){
        for(int i = 0; i < file_count; ++i){
            int f = fds[i];
            if(f == -1){
                continue;
            }
            ssize_t bytes_read = read(f, buf, sizeof(buf));
            if(bytes_read < 0){
                goto out_with_close_files;
            } else if(bytes_read == 0){
                if(close(f) != 0){
                    evr_panic("Unable to close fd %d", f);
                    goto out_with_close_files;
                }
                fds[i] = -1;
                --open_fds;
            } else {
                if(write(1, buf, sizeof(buf)) != sizeof(buf)){
                    evr_panic("Unable to write buffer to stdout");
                    goto out_with_close_files;
                }
            }
        }
    }
    ret = 0;
 out_with_close_files:
    for(int i = 0; i < file_count; ++i){
        int f = fds[i];
        if(f == -1){
            continue;
        }
        if(close(f) != 0){
            evr_panic("Unable to close fd %d", f);
            ret = 1;
            goto out;
        }
    }
 out:
    return ret;
}
