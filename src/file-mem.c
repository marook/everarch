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
    if(fm->offset > fm->data->size_used){
        log_error("Offset may never be greater than size_used in a defined file-mem state.");
        return -1;
    }
    size_t possible = fm->data->size_used - fm->offset;
    size_t read_bytes = min(count, possible);
    memcpy(buf, &fm->data->data[fm->offset], count);
    fm->offset += read_bytes;
    return read_bytes;
}

ssize_t evr_file_mem_write(struct evr_file *f, const void *buf, size_t count){
    struct evr_file_mem *fm = evr_file_get_mem(f);
    if(!fm->data){
        return -1;
    }
    size_t min_size = fm->offset + count;
    if(min_size < fm->data->size_allocated){
        fm->data = grow_dynamic_array_at_least(fm->data, min_size);
        if(!fm->data){
            return -1;
        }
    }
    memcpy(&fm->data->data[fm->offset], buf, count);
    fm->offset = min_size;
    fm->data->size_used += count;
    return count;
}

int evr_file_mem_close(struct evr_file *f){
    return 0;
}
