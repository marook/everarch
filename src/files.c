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

#include "files.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "basics.h"
#include "errors.h"

int read_file(dynamic_array **buffer, const char *path, size_t max_size){
    int result = evr_error;
    int f = open(path, O_RDONLY);
    if(!f){
        goto open_fail;
    }
    if(read_fd(buffer, f, max_size) != evr_ok){
        goto read_fail;
    }
    result = evr_ok;
 read_fail:
    close(f);
 open_fail:
    return result;
}

int read_fd(dynamic_array **buffer, int fd, size_t max_size) {
    while(1){
        if((*buffer)->size_allocated == (*buffer)->size_used){
            *buffer = grow_dynamic_array(*buffer);
            if(!*buffer){
                return evr_error;
            }
        }
        size_t max_read = min((*buffer)->size_allocated, max_size) - (*buffer)->size_used;
        void *out = &(((char*)(*buffer)->data)[(*buffer)->size_used]);
        ssize_t bytes_read = read(fd, out, max_read);
        if(bytes_read == 0){
            break;
        } else if(bytes_read < 0){
            return evr_error;
        }
        (*buffer)->size_used += bytes_read;
        if((*buffer)->size_used == max_size){
            return evr_error;
        }
    }
    return evr_ok;
}

int read_file_str(dynamic_array **buffer, const char *path, size_t max_size){
    if(read_file(buffer, path, max_size)){
        return 1;
    }
    if((*buffer)->size_used == max_size){
        return 1;
    }
    if((*buffer)->size_allocated == (*buffer)->size_used){
        *buffer = grow_dynamic_array(*buffer);
        if(!*buffer){
            return 1;
        }
    }
    ((char*)(*buffer)->data)[(*buffer)->size_used] = '\0';
    (*buffer)->size_used++;
    return 0;
}

int read_n(int f, char *buffer, size_t bytes){
    size_t remaining = bytes;
    while(remaining > 0){
        size_t nbytes = read(f, buffer, remaining);
        if(nbytes < 0){
            return evr_error;
        }
        if(nbytes == 0){
            return evr_end;
        }
        buffer += nbytes;
        remaining -= nbytes;
    }
    return evr_ok;
}

int write_n(int fd, const void *buffer, size_t size){
    size_t remaining = size;
    while(remaining > 0){
        ssize_t written = write(fd, buffer, remaining);
        if(written == 0){
            return evr_end;
        } else if(written == -1){
            return evr_error;
        }
        buffer += written;
        remaining -= written;
    }
    return evr_ok;
}

int pipe_n(int dest, int src, size_t size){
    char buffer[2048];
    size_t remaining = size;
    while(remaining > 0){
        ssize_t bytes_read = read(src, buffer, min(remaining, sizeof(buffer)));
        if(bytes_read <= 0){
            return evr_error;
        }
        remaining -= bytes_read;
        if(write_n(dest, buffer, bytes_read) != evr_ok){
            return evr_error;
        }
    }
    return evr_ok;
}

chunk_set_t *read_into_chunks(int fd, size_t size){
    size_t chunks_len = ceil_div(size, evr_chunk_size);
    chunk_set_t *cs = evr_allocate_chunk_set(chunks_len);
    if(!cs){
        goto out;
    }
    size_t remaining = size;
    for(int i = 0; i < chunks_len; ++i){
        size_t chunk_read_size = min(remaining, evr_chunk_size);
        if(read_n(fd, cs->chunks[i], chunk_read_size) != evr_ok){
            goto out_free_cs;
        }
        remaining -= chunk_read_size;
    }
    return cs;
 out_free_cs:
    evr_free_chunk_set(cs);
 out:
    return NULL;
}
