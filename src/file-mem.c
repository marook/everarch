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

#include "file-mem.h"

#include "logger.h"
#include "errors.h"

int evr_init_file_mem(struct evr_file_mem *fm, size_t initial_size, size_t max_size){
    char *buf;
    buf = malloc(initial_size);
    if(!buf){
        return evr_error;
    }
    fm->max_size = max_size;
    fm->alloc_size = initial_size;
    fm->used_size = 0;
    fm->offset = 0;
    fm->data = buf;
    return evr_ok;
}

void evr_destroy_file_mem(struct evr_file_mem *fm){
    free(fm->data);
}

int evr_file_mem_get_fd(struct evr_file *f);
int evr_file_mem_wait_for_data(struct evr_file *f, int timeout);
size_t evr_file_mem_pending(struct evr_file *f);
int evr_file_mem_received_shutdown(struct evr_file *f);
ssize_t evr_file_mem_read(struct evr_file *f, void *buf, size_t count);
ssize_t evr_file_mem_write(struct evr_file *f, const void *buf, size_t count);
int evr_file_mem_close(struct evr_file *f);

void evr_file_bind_file_mem(struct evr_file *f, struct evr_file_mem *fm){
    f->ctx.p = fm;
    f->get_fd = evr_file_mem_get_fd;
    f->wait_for_data = evr_file_mem_wait_for_data;
    f->pending = evr_file_mem_pending;
    f->received_shutdown = evr_file_mem_received_shutdown;
    f->read = evr_file_mem_read;
    f->write = evr_file_mem_write;
    f->close = evr_file_mem_close;
}

int evr_file_mem_get_fd(struct evr_file *f){
    return 123;
}

int evr_file_mem_wait_for_data(struct evr_file *f, int timeout){
    evr_panic("Implement me!");
    return evr_error;
}

size_t evr_file_mem_pending(struct evr_file *f){
    return 0;
}

int evr_file_mem_received_shutdown(struct evr_file *f){
    return 0;
}

#define evr_file_get_mem(f) ((struct evr_file_mem*)(f)->ctx.p)

ssize_t evr_file_mem_read(struct evr_file *f, void *buf, size_t count){
    struct evr_file_mem *fm = evr_file_get_mem(f);
    if(!fm->data){
        return 0;
    }
    if(fm->offset > fm->used_size){
        log_error("Offset may never be greater than used_size in a defined file-mem state.");
        return -1;
    }
    size_t possible = fm->used_size - fm->offset;
    size_t read_bytes = min(count, possible);
    memcpy(buf, &fm->data[fm->offset], read_bytes);
    fm->offset += read_bytes;
    return read_bytes;
}

ssize_t evr_file_mem_write(struct evr_file *f, const void *buf, size_t count){
    char *data;
    size_t new_size;
    struct evr_file_mem *fm = evr_file_get_mem(f);
    if(!fm->data){
        return -1;
    }
    size_t min_size = fm->offset + count;
    if(min_size > fm->alloc_size){
        if(min_size > fm->max_size){
            return -1;
        }
        new_size = max(2*fm->alloc_size, 2*min_size);
        if(new_size > fm->max_size){
            new_size = fm->max_size;
        }
        data = realloc(fm->data, new_size);
        if(!data){
            return -1;
        }
        fm->data = data;
        fm->alloc_size = new_size;
    }
    memcpy(&fm->data[fm->offset], buf, count);
    fm->offset = min_size;
    fm->used_size = min_size;
    return count;
}

int evr_file_mem_close(struct evr_file *f){
    return 0;
}
