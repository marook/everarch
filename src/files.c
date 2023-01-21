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
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "basics.h"
#include "errors.h"
#include "rollsum.h"
#include "logger.h"

int evr_open_res(char **res_paths){
    for(char **p = res_paths; *p; ++p){
        int f = open(*p, O_RDONLY);
        if(f < 0){
            if(errno == ENOENT){
                continue;
            }
            log_error("Unable to open resource file %s", *p);
            return -1;
        }
        log_debug("Opened file %s", *p);
        return f;
    }
    return -1;
}

int evr_file_fd_get_fd(struct evr_file *f);
size_t evr_file_fd_pending(struct evr_file *f);
int evr_file_fd_received_shutdown(struct evr_file *f);
ssize_t evr_file_fd_read(struct evr_file *f, void *buf, size_t count);
ssize_t evr_file_fd_write(struct evr_file *f, const void *buf, size_t count);
int evr_file_fd_close(struct evr_file *f);

void evr_file_bind_fd(struct evr_file *f, int fd){
    f->ctx.i = fd;
    f->get_fd = evr_file_fd_get_fd;
    f->wait_for_data = evr_file_select;
    f->pending = evr_file_fd_pending;
    f->received_shutdown = evr_file_fd_received_shutdown;
    f->read = evr_file_fd_read;
    f->write = evr_file_fd_write;
    f->close = evr_file_fd_close;
}

#define evr_file_get_fd(f) (f->ctx.i)

int evr_file_fd_get_fd(struct evr_file *f){
    return evr_file_get_fd(f);
}

int evr_file_select(struct evr_file *f, int timeout){
    fd_set active_fd_set;
    int fd = f->get_fd(f);
    if(fd < 0){
        return evr_error;
    }
    FD_ZERO(&active_fd_set);
    FD_SET(fd, &active_fd_set);
    struct timeval tv;
    if(timeout >= 0){
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
    }
    int sres = select(fd + 1, &active_fd_set, NULL, NULL, timeout >= 0 ? &tv : NULL);
    if(sres < 0){
        return evr_error;
    }
    if(sres == 0){
        return evr_end;
    }
    return evr_ok;
}

size_t evr_file_fd_pending(struct evr_file *f){
    return 0;
}

int evr_file_fd_received_shutdown(struct evr_file *f){
    return 0;
}

ssize_t evr_file_fd_read(struct evr_file *f, void *buf, size_t count){
    return read(evr_file_get_fd(f), buf, count);
}

ssize_t evr_file_fd_write(struct evr_file *f, const void *buf, size_t count){
    return write(evr_file_get_fd(f), buf, count);
}

int evr_file_fd_close(struct evr_file *f){
    return close(evr_file_get_fd(f));
}

int evr_file_unbound_close(struct evr_file *f);

void evr_file_unbound(struct evr_file *f){
    f->ctx.i = -1;
    f->get_fd = evr_file_fd_get_fd;
    f->wait_for_data = evr_file_select;
    f->pending = evr_file_fd_pending;
    f->received_shutdown = evr_file_fd_received_shutdown;
    f->read = evr_file_fd_read;
    f->write = evr_file_fd_write;
    f->close = evr_file_unbound_close;
}

int evr_file_unbound_close(struct evr_file *f){
    return 0;
}

int read_fd(struct dynamic_array **buffer, int fd, size_t max_size) {
    size_t total_read = 0;
    while(1){
        if((*buffer)->size_allocated == (*buffer)->size_used){
            *buffer = grow_dynamic_array(*buffer);
            if(!*buffer){
                return evr_error;
            }
        }
        size_t max_read = min(max_size, (*buffer)->size_allocated - (*buffer)->size_used);
        char *out = &(*buffer)->data[(*buffer)->size_used];
        ssize_t bytes_read = read(fd, out, max_read);
        if(bytes_read == 0){
            return evr_end;
        } else if(bytes_read < 0){
            return evr_error;
        }
        (*buffer)->size_used += bytes_read;
        total_read += bytes_read;
        if(total_read == max_size){
            return evr_ok;
        }
    }
}

int read_n(struct evr_file *f, char *buffer, size_t bytes, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx){
    size_t remaining = bytes;
    while(remaining > 0){
        ssize_t nbytes = f->read(f, buffer, remaining);
        if(nbytes < 0){
            return evr_error;
        }
        if(nbytes == 0){
            return evr_end;
        }
        if(side_effect && side_effect(ctx, buffer, nbytes) != evr_ok){
            return evr_error;
        }
        buffer += nbytes;
        remaining -= nbytes;
    }
    return evr_ok;
}

int write_n(struct evr_file *f, const void *buffer, size_t size){
    char *buf = buffer;
    size_t remaining = size;
    while(remaining > 0){
        ssize_t written = f->write(f, buf, remaining);
        if(written <= 0){
            if(errno == EPIPE){
                log_debug("write_n detected a broken pipe with file %d", f->get_fd(f));
                return evr_end;
            }
            return evr_error;
        }
        buf += written;
        remaining -= written;
    }
    return evr_ok;
}

int write_chunk_set(struct evr_file *f, const struct chunk_set *cs){
    size_t remaining = cs->size_used;
    char * const *c = cs->chunks;
    while(remaining > 0){
        size_t written_bytes = min(evr_chunk_size, remaining);
        if(write_n(f, *c, written_bytes) != evr_ok){
            return evr_error;
        }
        ++c;
        remaining -= written_bytes;
    }
    return evr_ok;
}

int pipe_n(struct evr_file *dest, struct evr_file *src, size_t n, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx){
    char buffer[4096];
    size_t remaining = n;
    while(remaining > 0){
        ssize_t bytes_read = src->read(src, buffer, min(remaining, sizeof(buffer)));
        if(bytes_read <= 0){
            return evr_error;
        }
        if(side_effect && side_effect(ctx, buffer, bytes_read) != evr_ok){
            return evr_error;
        }
        remaining -= bytes_read;
        int write_res = write_n(dest, buffer, bytes_read);
        if(write_res == evr_end){
            return evr_end;
        } else if(write_res != evr_ok){
            return evr_error;
        }
    }
    return evr_ok;
}

int dump_n(struct evr_file *f, size_t bytes, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx){
    char buf[min(bytes, 4096)];
    size_t remaining = bytes;
    while(remaining > 0){
        ssize_t nbytes = f->read(f, buf, min(sizeof(buf), remaining));
        if(nbytes < 0){
            return evr_error;
        }
        if(nbytes == 0){
            return evr_end;
        }
        if(side_effect && side_effect(ctx, buf, nbytes) != evr_ok){
            return evr_error;
        }
        remaining -= nbytes;
    }
    return evr_ok;
}

int visited_bytes_counter_se(void *ctx, char *buf, size_t size){
    size_t *visited_bytes = ctx;
    *visited_bytes += size;
    return evr_ok;
}

struct chunk_set *read_into_chunks(struct evr_file *f, size_t size, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx){
    size_t chunks_len = ceil_div(size, evr_chunk_size);
    struct chunk_set *cs = evr_allocate_chunk_set(chunks_len);
    if(!cs){
        goto out;
    }
    size_t remaining = size;
    for(size_t i = 0; i < chunks_len; ++i){
        size_t chunk_read_size = min(remaining, evr_chunk_size);
        if(read_n(f, cs->chunks[i], chunk_read_size, side_effect, ctx) != evr_ok){
            goto out_free_cs;
        }
        remaining -= chunk_read_size;
    }
    cs->size_used = size;
    return cs;
 out_free_cs:
    evr_free_chunk_set(cs);
 out:
    return NULL;
}

int append_into_chunk_set(struct chunk_set *cs, int f){
    while(1){
        int ci = cs->size_used / evr_chunk_size;
        size_t cip = cs->size_used % evr_chunk_size;
        for(int i = cs->chunks_len; i <= ci; ++i){
            if(evr_grow_chunk_set(cs, ci + 1) != evr_ok){
                return evr_error;
            }
        }
        size_t cir = evr_chunk_size - cip;
        ssize_t bytes_read = read(f, &cs->chunks[ci][cip], cir);
        if(bytes_read == 0){
            break;
        } else if(bytes_read < 0){
            return evr_error;
        }
        cs->size_used += bytes_read;
    }
    return evr_ok;
}

/**
 * evr_split_window_size defines the window for the Rollsum. Must be
 * power of 2.
 */
#define evr_split_window_size 64

/**
 * avg_blob_size indicates the average size at which bigger blobs
 * should be splitted using RollSum.
 *
 * The actual value is taken from perkeep's commit
 * 15ad53c5459e036c795348e7bb927d63ce259c13 which changes the const
 * blobSize. The perkeep history shows that Brad reduced the original
 * perkeep 32k (1<<15) value to 8k (1<<13). Unfortunately there is no
 * reason why written into the commit.
 */
#define avg_slice_size (256 << 10) // 256k
/**
 * min_first_slice_size is the minimum size of the first slice in any
 * file. This is bigger than the min_slice_size because many file
 * types store important metadata in the beginning of the file. Think
 * of file(1) command, EXIF metadata in JPEGs, ID3 in mp3 files.
 */
#define min_first_slice_size (256 << 10) // 256k
#define min_slice_size       ( 64 << 10) //  64k
#define max_slice_size       ( 10 << 20) //  10M

inline int evr_want_split(const struct Rollsum *rs){
    return (rs->s2 & (avg_slice_size - 1)) == (-1 & (avg_slice_size - 1));
}

int evr_rollsum_split(int f, size_t max_read, int (*slice)(char *buf, size_t size, void *ctx), void *ctx){
    int ret = evr_error;
    struct dynamic_array *buf = alloc_dynamic_array(1*1024*1024);
    if(!buf){
        goto out;
    }
    unsigned char window[evr_split_window_size];
    memset(window, 0, evr_split_window_size);
    size_t window_pos = 0;
    struct Rollsum rs;
    RollsumInit(&rs);
    while(1){
        if(buf->size_used == buf->size_allocated){
            // buffer is full. which indicates we could not reach a
            // split position within the current buffer size. so we
            // grow it.
            buf = grow_dynamic_array(buf);
            if(!buf){
                goto out;
            }
        }
        size_t split_test_start = buf->size_used;
        size_t want_read = min(max_read, buf->size_allocated) - buf->size_used;
        int read_res = read_fd(&buf, f, want_read);
        if(read_res != evr_ok && read_res != evr_end){
            goto out_with_free_buf;
        }
        size_t next_slice_start = 0;
        for(size_t p = split_test_start; p < buf->size_used; ++p){
            unsigned char b = (unsigned char)buf->data[p];
            RollsumRotate(&rs, window[window_pos], b);
            window[window_pos] = b;
            window_pos = (window_pos + 1) & (evr_split_window_size - 1);
            size_t slice_size = p - next_slice_start;
            if(slice_size > min_slice_size && (slice_size >= max_slice_size || evr_want_split(&rs))){
                if(slice_size > 0){
                    if(slice(&buf->data[next_slice_start], slice_size, ctx) != evr_ok){
                        goto out_with_free_buf;
                    }
                    next_slice_start = p;
                }
            }
        }
        if(next_slice_start > 0){
            if(dynamic_array_remove(buf, 0, next_slice_start) != evr_ok){
                goto out_with_free_buf;
            }
            max_read -= next_slice_start;
            next_slice_start = 0;
        }
        if(read_res == evr_end || buf->size_used == max_read){
            // flush the remaining buffer as one slice
            if(slice(buf->data, buf->size_used, ctx) != evr_ok){
                goto out_with_free_buf;
            }
            if(read_res == evr_end){
                ret = evr_end;
            } else {
                ret = evr_ok;
            }
            break;
        }
    }
 out_with_free_buf:
    if(buf){
        free(buf);
    }
 out:
    return ret;
}

int evr_peer_hang_up(struct evr_file *f){
    struct pollfd fds;
    fds.fd = f->get_fd(f);
    fds.events = POLLRDHUP | POLLHUP;
    if(poll(&fds, 1, 0) < 0){
        return evr_error;
    }
    if(fds.revents & (POLLRDHUP | POLLHUP)){
        // peer closed connection
        return evr_end;
    }
    return evr_ok;
}

struct evr_buf_read *evr_create_buf_read(struct evr_file *f, size_t buf_size_exp){
    size_t buf_size = 1 << buf_size_exp;
    char *buf = malloc(sizeof(struct evr_buf_read) + buf_size);
    if(!buf){
        return NULL;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_buf_read *br;
    evr_map_struct(&bp, br);
    br->f = f;
    br->read_i = 0;
    br->write_i = 0;
    br->buf = bp.pos;
    br->buf_size = buf_size;
    return br;
}

int evr_buf_read_read(struct evr_buf_read *br){
    size_t rsize;
    if(br->read_i <= br->write_i){
        rsize = br->buf_size - br->write_i;
        if(br->read_i == 0){
            --rsize;
        }
        if(rsize == 0){
            // buffer exceeded
            return -1;
        }
    } else {
        rsize = br->read_i - br->write_i - 1;
    }
    char *rbuf = &br->buf[br->write_i];
    int bytes_read = br->f->read(br->f, rbuf, rsize);
    if(bytes_read <= 0){
        return bytes_read;
    }
    br->write_i = (br->write_i + bytes_read) & (br->buf_size - 1);
    return bytes_read;
}

int evr_buf_read_read_until(struct evr_buf_read *br, char sentinel, size_t *offset){
    size_t i = 0;
    while(1){
        size_t bytes_ready = evr_buf_read_bytes_ready(br);
        for(; i < bytes_ready; ++i){
            if(evr_buf_read_peek(br, i) == sentinel){
                if(offset){
                    *offset = i;
                    return evr_ok;
                }
            }
        }
        int bytes_read = evr_buf_read_read(br);
        if(bytes_read == 0){
            return evr_end;
        } else if(bytes_read < 0) {
            return evr_error;
        }
    }
}

int evr_buf_read_pop(struct evr_buf_read *br, char *buf, size_t bytes){
    for(size_t i = 0; i < bytes; ++i){
        buf[i] = evr_buf_read_peek(br, i);
    }
    br->read_i = (br->read_i + bytes) & (br->buf_size - 1);
    return evr_ok;
}

int evr_acquire_process_lock(int *lock_fd, char *lock_path){
    int fd = open(lock_path, O_CREAT | O_WRONLY, 0600);
    if(fd < 0){
        log_error("Unable to open or create lock file %s", lock_path);
        goto fail;
    }
    if(flock(fd, LOCK_EX | LOCK_NB) != 0){
        log_error("Unable to lock %s", lock_path);
        goto fail_with_close_fd;
    }
    log_debug("locked %s via file handle %d", lock_path, fd);
    *lock_fd = fd;
    return evr_ok;
 fail_with_close_fd:
    if(close(fd) != 0){
        evr_panic("Unable to close lock file %s", lock_path);
    }
 fail:
    return evr_error;
}

int evr_release_process_lock(int lock_fd){
    if(flock(lock_fd, LOCK_UN) != 0){
        log_error("Unable to unlock lock file handle %d", lock_fd);
        return evr_error;
    }
    if(close(lock_fd) != 0){
        evr_panic("Unable to close lock file handle %d", lock_fd);
        return evr_error;
    }
    return evr_ok;
}
