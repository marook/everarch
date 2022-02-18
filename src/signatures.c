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

#include <string.h>
#include <gpgme.h>

#include "signatures.h"
#include "errors.h"

int evr_signatures_build_ctx(gpgme_ctx_t *ctx);
int evr_signatures_read_data(struct dynamic_array **dest, gpgme_data_t d, size_t dest_size_hint);

void evr_init_signatures(){
    gpgme_check_version(NULL);
}

int evr_sign(struct dynamic_array **dest, const char *s){
    int ret = evr_error;
    gpgme_ctx_t ctx;
    if(evr_signatures_build_ctx(&ctx) != evr_ok){
        goto out;
    }
    size_t s_len = strlen(s);
    gpgme_data_t in;
    if(gpgme_data_new_from_mem(&in, s, s_len, 0) != GPG_ERR_NO_ERROR){
        goto out_with_release_ctx;
    }
    gpgme_data_t out;
    if(gpgme_data_new(&out) != GPG_ERR_NO_ERROR){
        goto out_with_release_in;
    }
    if(gpgme_op_sign(ctx, in, out, GPGME_SIG_MODE_CLEAR) != GPG_ERR_NO_ERROR){
        goto out_with_release_out;
    }
    if(evr_signatures_read_data(dest, out, s_len + 6 * 1024) != evr_ok){
        goto out_with_release_out;
    }
    ret = evr_ok;
 out_with_release_out:
    gpgme_data_release(out);
 out_with_release_in:
    gpgme_data_release(in);
 out_with_release_ctx:
    gpgme_release(ctx);
 out:
    return ret;
}

int evr_verify(struct dynamic_array **dest, const char *s, size_t s_maxlen){
    int ret = evr_error;
    gpgme_ctx_t ctx;
    if(evr_signatures_build_ctx(&ctx) != evr_ok){
        goto out;
    }
    size_t s_len = strnlen(s, s_maxlen);
    gpgme_data_t in;
    if(gpgme_data_new_from_mem(&in, s, s_len, 0) != GPG_ERR_NO_ERROR){
        goto out_with_release_ctx;
    }
    gpgme_data_t out;
    if(gpgme_data_new(&out) != GPG_ERR_NO_ERROR){
        goto out_with_release_in;
    }
    if(gpgme_op_verify(ctx, in, NULL, out) != GPG_ERR_NO_ERROR){
        goto out_with_release_out;
    }
    if(evr_signatures_read_data(dest, out, s_len) != evr_ok){
        goto out_with_release_out;
    }
    ret = evr_ok;
 out_with_release_out:
    gpgme_data_release(out);
 out_with_release_in:
    gpgme_data_release(in);
 out_with_release_ctx:
    gpgme_release(ctx);
 out:
    return ret;
}

int evr_signatures_build_ctx(gpgme_ctx_t *ctx){
    int ret = evr_error;
    if(gpgme_new(ctx) != GPG_ERR_NO_ERROR){
        goto out;
    }
    gpgme_set_textmode(*ctx, 1);
    gpgme_set_armor(*ctx, 1);
    ret = evr_ok;
 out:
    return ret;
}

int evr_signatures_read_data(struct dynamic_array **dest, gpgme_data_t d, size_t dest_size_hint){
    int ret = evr_error;
    gpgme_data_seek(d, 0, SEEK_SET);
    *dest = grow_dynamic_array_at_least(*dest, dest_size_hint);
    if(*dest == NULL){
        goto out;
    }
    char buffer[4096];
    while(1){
        ssize_t bytes_read = gpgme_data_read(d, buffer, sizeof(buffer));
        if(bytes_read < 0){
            goto out;
        } else if(bytes_read == 0){
            break;
        } else {
            *dest = write_n_dynamic_array(*dest, buffer, bytes_read);
            if(!*dest){
                goto out;
            }
        }
    }
    ret = evr_ok;
 out:
    return ret;
}
