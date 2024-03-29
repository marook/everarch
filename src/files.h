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

#include <sys/types.h>

#include "dyn-mem.h"

/**
 * evr_open_res walks along the res_paths until it can open the file
 * read only or hits NULL.
 *
 * Returns a file handle or -1 if the resource could not be opened.
 */
int evr_open_res(char **res_paths);

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

    /**
     * wait_for_data will block until data is ready to be read.
     *
     * timeout is the number of seconds after which the wait times
     * out. 0 indicates no timeout.
     *
     * Returns evr_ok on success. evr_end on timeout. evr_error
     * otherwise.
     */
    int (*wait_for_data)(struct evr_file *f, int timeout);

    /**
     * pending returns the number bytes which are buffered in user
     * space and ready to be read.
     */
    size_t (*pending)(struct evr_file *f);

    /**
     * received_shutdown tests and indicates if the peer indicated it
     * wants to shutdown the connection.
     *
     * Returns 0 if shutdown was not indicated. Returns 1 if shutdown
     * was indicated.
     */
    int (*received_shutdown)(struct evr_file *f);

    ssize_t (*read)(struct evr_file *f, void *buf, size_t count);
    ssize_t (*write)(struct evr_file *f, const void *buf, size_t count);

    /**
     * close must close the underlying file and free resources
     * allocated by ctx.
     *
     * Returns zero on success.
     */
    int (*close)(struct evr_file *f);

    union evr_file_ctx ctx;
};

void evr_file_bind_fd(struct evr_file *f, int fd);

void evr_file_unbound(struct evr_file *f);

int evr_file_select(struct evr_file *f, int timeout);

int read_fd(struct dynamic_array **buffer, int fd, size_t max_size);

/**
 * side_effect will be called with the read data chunk by chunk. If
 * side_effect is NULL it is ignored.
 */
int read_n(struct evr_file *f, char *buffer, size_t bytes, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx);

/**
 * Returns evr_ok if bytes got written. Returns evr_end if f signals
 * an EPIPE on write. Returns evr_error on errors.
 */
int write_n(struct evr_file *f, const void *buffer, size_t size);

int write_chunk_set(struct evr_file *f, const struct chunk_set *cs);

/**
 * pipe_n will pipe n bytes from src to dest.
 *
 * side_effect will be called with the piped data chunk by chunk. If
 * side_effect is NULL it is ignored.
 *
 * Returns evr_ok if bytes got piped. Returns evr_end if dest signals
 * an EPIPE on write. Returns evr_error on errors.
 */
int pipe_n(struct evr_file *dest, struct evr_file *src, size_t n, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx);

int dump_n(struct evr_file *f, size_t bytes, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx);

int visited_bytes_counter_se(void *ctx, char *buf, size_t size);

struct chunk_set *read_into_chunks(struct evr_file *f, size_t size, int (*side_effect)(void *ctx, char *buf, size_t size), void *ctx);

int append_into_chunk_set(struct chunk_set *cs, int f);

/**
 * evr_rollsum_split reads from f in a streaming manner. Calls slice
 * callback if RollSum indicates a new block.
 *
 * Returns evr_ok if max_size has been read. Returns evr_end if less
 * than max_size has been read because of eof.
 */
int evr_rollsum_split(int f, size_t max_size, int (*slice)(char *buf, size_t size, void *ctx), void *ctx);

/**
 * evr_peer_hand_up detects if the peer closed the file.
 *
 * Returns evr_end if the peer closed the file. Returns evr_ok if the
 * file is still open.
 */
int evr_peer_hang_up(struct evr_file *f);

struct evr_buf_read {
    struct evr_file *f;
    size_t read_i;
    size_t write_i;
    char *buf;
    size_t buf_size;
};

struct evr_buf_read *evr_create_buf_read(struct evr_file *f, size_t buf_size_exp);

#define evr_free_buf_read(br) free(br)

#define evr_buf_read_bytes_ready(br) (((br)->write_i - (br)->read_i) & ((br)->buf_size - 1))

#define evr_buf_read_peek(br, offset) ((br)->buf[(((br)->read_i + offset) & ((br)->buf_size - 1))])

/**
 * evr_buf_read_read reads the next part into the buffer.
 *
 * Returns the number of bytes read. Returns -1 on error. Returns 0 if
 * the input evr_file ended.
 */
int evr_buf_read_read(struct evr_buf_read *br);

/**
 * evr_buf_read_read_until reads until the given sentinel character is
 * observed.
 *
 * The found sentinel index will be written to offset if not NULL.
 *
 * Returns evr_end if the underlying evr_buf_read ends before the
 * sentinel was reached.
 */
int evr_buf_read_read_until(struct evr_buf_read *br, char sentinel, size_t *offset);

/**
 * evr_buf_read_pop will read n bytes from struct evr_buf_read. Make
 * sure the buffer has at least n bytes via comparing with
 * evr_buf_read_bytes_ready's return value.
 *
 * Returns evr_ok on success.
 */
int evr_buf_read_pop(struct evr_buf_read *br, char *buf, size_t bytes);

/**
 * evr_acquire_process_lock creates an empty file at lock_path and
 * puts a exclusive flock lock on it.
 *
 * Returns evr_ok if the file exists after the call and the exclusive
 * lock was placed. Returns evr_error if the lock file can't be
 * created or another process already owns the lock.
 */
int evr_acquire_process_lock(int *lock_fd, char *lock_path);

/**
 * evr_release_process_lock releases the flock lock. The file created
 * using evr_acquire_process_lock will not be removed.
 */
int evr_release_process_lock(int lock_fd);

#endif
