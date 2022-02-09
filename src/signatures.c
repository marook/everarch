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

#include "signatures.h"

#include <string.h>
#include <gpgme.h>

#include "errors.h"

void evr_init_signatures(){
    gpgme_check_version(NULL);
}

int evr_sign(struct dynamic_array **dest, const char *s){
    int ret = evr_error;
    gpgme_ctx_t ctx;
    if(gpgme_new(&ctx) != GPG_ERR_NO_ERROR){
        goto out;
    }
    gpgme_set_textmode(ctx, 1);
    gpgme_set_armor(ctx, 1);
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
    gpgme_data_seek(out, 0, SEEK_SET);
    *dest = grow_dynamic_array_at_least(*dest, s_len + 6 * 1024);
    if(*dest == NULL){
        goto out_with_release_out;
    }
    char buffer[4096];
    while(1){
        ssize_t bytes_read = gpgme_data_read(out, buffer, sizeof(buffer));
        if(bytes_read < 0){
            goto out_with_release_out;
        } else if(bytes_read == 0){
            break;
        } else {
            *dest = write_n_dynamic_array(*dest, buffer, bytes_read);
        }
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
