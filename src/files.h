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
 * read_file reads the file content at a given path.
 *
 * *buffer must point to an existing buffer. *buffer may be null if
 * read_file returns with != 0.
 */
int read_file(struct dynamic_array **buffer, const char *path, size_t max_size);

int read_fd(struct dynamic_array **buffer, int fd, size_t max_size);

/**
 * read_file_str reads a file just like read_file and \0 terminates
 * the string.
 */
int read_file_str(struct dynamic_array **buffer, const char *path, size_t max_size);

int read_n(int f, char *buffer, size_t bytes);

int write_n(int fd, const void *buffer, size_t size);

int write_chunk_set(int f, const struct chunk_set *cs);

int pipe_n(int dest, int src, size_t size);

int dump_n(int f, size_t bytes);

struct chunk_set *read_into_chunks(int fd, size_t size);

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
