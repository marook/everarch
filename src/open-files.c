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

#include "open-files.h"

#include "errors.h"
#include "logger.h"
#include "glacier-cmd.h"
#include "evr-glacier-client.h"

int evr_open_file_cache_slice(struct evr_open_file *f, size_t si);

int evr_open_file_read(struct evr_open_file *f, char *buf, size_t *size, off_t off){
    int ret = evr_error;
    size_t buf_bytes_written = 0;
    off_t slices_off = 0;
    if(mtx_lock(&f->lock) != thrd_success){
        goto out;
    }
    for(size_t si = 0; si < f->claim->slices_len; ++si){
        struct evr_file_slice *s = &f->claim->slices[si];
        if(off < slices_off + s->size){
            if(f->cached_slice_buf == NULL || f->cached_slice_index != si){
                if(evr_open_file_cache_slice(f, si) != evr_ok){
                    goto out_with_unlock;
                }
            }
            off_t s_off = slices_off >= off ? 0 : off - slices_off;
            size_t remaining_bytes = *size - buf_bytes_written;
            size_t s_size = remaining_bytes >= (s->size - s_off) ? (s->size - s_off) : remaining_bytes;
            log_debug("Read %zu bytes at offset %zu from slice %zu", s_size, (size_t)s_off, si);
            memcpy(&buf[buf_bytes_written], &f->cached_slice_buf[s_off], s_size);
            buf_bytes_written += s_size;
            if(buf_bytes_written == *size){
                break;
            }
        }
        slices_off += s->size;
    }
    ret = evr_ok;
 out_with_unlock:
    if(mtx_unlock(&f->lock) != thrd_success){
        evr_panic("Unable to unlock open file lock");
        ret = evr_error;
    }
    if(ret == evr_ok){
        *size = buf_bytes_written;
    }
 out:
    return ret;
}

int evr_open_file_cache_slice(struct evr_open_file *f, size_t si){
    int ret = evr_error;
    struct evr_file_slice *s = &f->claim->slices[si];
    struct evr_resp_header rhdr;
    if(evr_req_cmd_get_blob(&f->gc, s->ref, &rhdr) != evr_ok){
        goto out;
    }
    if(rhdr.status_code != evr_status_code_ok){
        if(dump_n(&f->gc, rhdr.body_size, NULL, NULL) != evr_ok){
            goto fail_with_close_gc;
        }
        goto out;
    }
    if(rhdr.body_size < evr_blob_flags_n_size){
        if(dump_n(&f->gc, rhdr.body_size, NULL, NULL) != evr_ok){
            goto fail_with_close_gc;
        }
        goto out;
    }
    if(dump_n(&f->gc, evr_blob_flags_n_size, NULL, NULL) != evr_ok){
        goto fail_with_close_gc;
    }
    free(f->cached_slice_buf);
    f->cached_slice_index = si;
    size_t blob_size = rhdr.body_size - evr_blob_flags_n_size;
    f->cached_slice_buf = malloc(blob_size);
    if(!f->cached_slice_buf){
        goto fail_with_close_gc;
    }
    evr_blob_ref_hd hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto fail_with_close_gc;
    }
    if(read_n(&f->gc, f->cached_slice_buf, blob_size, evr_blob_ref_write_se, hd) != evr_ok){
        free(f->cached_slice_buf);
        f->cached_slice_buf = NULL;
        goto fail_with_close_hd;
    }
    if(evr_blob_ref_hd_match(hd, s->ref) != evr_ok){
        free(f->cached_slice_buf);
        f->cached_slice_buf = NULL;
        goto out_with_close_hd;
    }
    ret = evr_ok;
 out_with_close_hd:
    evr_blob_ref_close(hd);
 out:
    return ret;
 fail_with_close_hd:
    evr_blob_ref_close(hd);
 fail_with_close_gc:
    log_error("Failed to communicate with glacier");
    if(f->gc.close(&f->gc) != 0){
        evr_panic("Unable to close glacier connection");
    }
    return evr_error;
}

int evr_init_open_file_set(struct evr_open_file_set *ofs){
    if(mtx_init(&ofs->files_lock, mtx_plain) != thrd_success){
        goto fail;
    }
    ofs->files_len = 64;
    ofs->files = malloc(sizeof(struct evr_open_file) * ofs->files_len);
    if(!ofs->files){
        goto fail_with_destroy_files_lock;
    }
    struct evr_open_file *f_end = &ofs->files[ofs->files_len];
    struct evr_open_file *f = ofs->files;
    for(; f != f_end; ++f){
        f->open = 0;
        if(mtx_init(&f->lock, mtx_plain) != thrd_success){
            goto fail_with_destroy_files_file_locks;
        }
        evr_file_bind_fd(&f->gc, 0);
        f->claim = NULL;
        f->cached_slice_buf = NULL;
    }
    return evr_ok;
 fail_with_destroy_files_file_locks:
    for(--f; f > ofs->files; --f){
        mtx_destroy(&f->lock);
    }
    free(ofs->files);
 fail_with_destroy_files_lock:
    mtx_destroy(&ofs->files_lock);
 fail:
    return evr_error;
}

int evr_empty_open_file_set(struct evr_open_file_set *ofs){
    struct evr_open_file *f_end = &ofs->files[ofs->files_len];
    for(struct evr_open_file *f = ofs->files; f != f_end; ++f){
        mtx_destroy(&f->lock);
        free(f->claim);
        free(f->cached_slice_buf);
    }
    mtx_destroy(&ofs->files_lock);
    free(ofs->files);
    return evr_ok;
}

int evr_allocate_open_file(struct evr_open_file_set *ofs, uint64_t *fh){
    int ret = evr_error;
    if(mtx_lock(&ofs->files_lock) != thrd_success){
        goto out;
    }
    struct evr_open_file *f_end = &ofs->files[ofs->files_len];
    for(struct evr_open_file *f = ofs->files; f != f_end; ++f){
        if(f->open){
            continue;
        }
        f->open = 1;
        *fh = f - ofs->files;
        ret = evr_ok;
        break;
    }
    if(mtx_unlock(&ofs->files_lock) != thrd_success){
        evr_panic("Unable to unlock open file set files lock");
        ret = evr_error;
    }
 out:
    return ret;
}

int evr_close_open_file(struct evr_open_file_set *ofs, uint64_t fh){
    int ret = evr_error;
    struct evr_open_file *f = &ofs->files[fh];
    if(mtx_lock(&f->lock) != thrd_success){
        goto out;
    }
    if(f->gc.close(&f->gc) != 0){
        evr_panic("Unable to close open file glacier connection for %u", (long int)fh);
        goto out_with_unlock;
    }
    evr_file_bind_fd(&f->gc, 0);
    free(f->claim);
    f->claim = NULL;
    free(f->cached_slice_buf);
    f->cached_slice_buf = NULL;
    ret = evr_ok;
 out_with_unlock:
    if(mtx_unlock(&f->lock) != thrd_success){
        evr_panic("Unable to unlock open file set files lock");
        ret = evr_error;
    }
 out:
    return ret;
}
