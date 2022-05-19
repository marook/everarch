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

#ifndef __files_h__
#define __files_h__

#include "config.h"

#include "dyn-mem.h"

/**
 * union evr_file_ctx is used by struct evr_file so a void pointer OR
 * a simple integer can easily be stored in the evr_file struct. You
 * probably guessed that simple file descriptor instances can use the
 * int to store the file descriptor while more sophisticated instances
 * could store some context pointer also.
 */
union evr_file_ctx {
    void *p;
    int i;
};

/**
 * struct evr_file is an abstaction layer over files. It it used to
 * have a common interface for read and write operations on file
 * descriptors and OpenSSL connections.
 */
struct evr_file {
    /**
     * get_fd returns the underlying file descriptor of this evr_file.
     *
     * This function should be used for debugging when different, in
     * parallel open files should be identified in logs.
     */
    int (*get_fd)(struct evr_file *f);

    ssize_t (*read)(struct evr_file *f, void *buf, size_t count);
    ssize_t (*write)(struct evr_file *f, const void *buf, size_t count);

    /**
     * close must close the underlying file and free resources
     * allocated by ctx.
     */
    int (*close)(struct evr_file *f);

    union evr_file_ctx ctx;
};

void evr_file_bind_fd(struct evr_file *f, int fd);

int read_fd(struct dynamic_array **buffer, int fd, size_t max_size);

int read_n(struct evr_file *f, char *buffer, size_t bytes);

/**
 * Returns evr_ok if bytes got written. Returns evr_end if f signals
 * an EPIPE on write. Returns evr_error on errors.
 */
int write_n(struct evr_file *f, const void *buffer, size_t size);

int write_chunk_set(struct evr_file *f, const struct chunk_set *cs);

/**
 * pipe_n will pipe n bytes from src to dest.
 *
 * Returns evr_ok if bytes got piped. Returns evr_end if dest signals
 * an EPIPE on write. Returns evr_error on errors.
 */
int pipe_n(struct evr_file *dest, struct evr_file *src, size_t n);

int dump_n(struct evr_file *f, size_t bytes);

struct chunk_set *read_into_chunks(struct evr_file *f, size_t size);

int append_into_chunk_set(struct chunk_set *cs, int f);

/**
 * evr_rollsum_split reads from f in a streaming manner. Calls slice
 * callback if RollSum indicates a new block.
 *
 * Returns evr_ok if max_size has been read. Returns evr_end if less
 * than max_size has been read because of eof.
 */
int evr_rollsum_split(int f, size_t max_size, int (*slice)(char *buf, size_t size, void *ctx), void *ctx);

#endif
