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

#include "assert.h"
#include "signatures.h"
#include "test.h"
#include "logger.h"
#include "errors.h"

void stringify_dynamic_array(struct dynamic_array **da);

void test_hello_world_signature(){
    struct dynamic_array *out = NULL;
    assert(is_ok(evr_sign(NULL, &out, "hello world!")));
    assert(out);
    stringify_dynamic_array(&out);
    assert(is_str_in((char*)out->data, "hello world"));
    assert(is_str_in((char*)out->data, "-----BEGIN PGP SIGNATURE-----"));
    free(out);
}

int get_signature_fpr(char *fpr, size_t fpr_max_size, struct dynamic_array *msg);

void test_validate_hello_world_signature(){
    struct dynamic_array *sgn = NULL;
    assert(is_ok(evr_sign(NULL, &sgn, "hello world!")));
    assert(sgn);
    const size_t fpr_size = 64;
    char *fpr = alloca(fpr_size);
    assert(is_ok(get_signature_fpr(fpr, fpr_size, sgn)));
    log_info("Signing test was performed with gpg key %s", fpr);
    struct dynamic_array *msg = NULL;
    { // verify signature with correct expected fingerprint
        struct evr_verify_ctx *v_ctx = evr_init_verify_ctx(&fpr, 1);
        assert(v_ctx);
        assert(is_ok(evr_verify(v_ctx, &msg, sgn->data, sgn->size_used)));
        evr_free_verify_ctx(v_ctx);
    }
    { // verify signature with different fingerprint
        char *fpr = alloca(fpr_size + 1);
        memset(fpr, 'x', fpr_size);
        fpr[fpr_size] = '\0';
        struct evr_verify_ctx *v_ctx = evr_init_verify_ctx(&fpr, 1);
        assert(v_ctx);
        struct dynamic_array *msg2 = NULL;
        assert(evr_verify(v_ctx, &msg2, sgn->data, sgn->size_used) == evr_user_data_invalid);
        free(msg2);
        evr_free_verify_ctx(v_ctx);
    }
    free(sgn);
    sgn = NULL;
    assert(is_ok(evr_sign(fpr, &sgn, "hello world!")));
    assert(sgn);
    free(sgn);
    stringify_dynamic_array(&msg);
    if(msg->data[msg->size_used - 2] == '\n'){
        msg->data[msg->size_used - 2] = '\0';
    }
    assert(is_str_eq(msg->data, "hello world!"));
    free(msg);
}

int get_signature_fpr(char *fpr, size_t fpr_max_size, struct dynamic_array *msg){
    int ret = evr_error;
    gpgme_ctx_t gpg_ctx;
    if(gpgme_new(&gpg_ctx) != GPG_ERR_NO_ERROR){
        goto out;
    }
    gpgme_set_textmode(gpg_ctx, 1);
    gpgme_set_armor(gpg_ctx, 1);
    size_t s_len = strnlen(msg->data, msg->size_used);
    gpgme_data_t in;
    if(gpgme_data_new_from_mem(&in, msg->data, s_len, 0) != GPG_ERR_NO_ERROR){
        goto out_with_release_gpg_ctx;
    }
    if(gpgme_op_verify(gpg_ctx, in, NULL, NULL) != GPG_ERR_NO_ERROR){
        goto out_with_release_in;
    }
    gpgme_verify_result_t res = gpgme_op_verify_result(gpg_ctx);
    if(res == NULL){
        goto out_with_release_in;
    }
    gpgme_signature_t sig = res->signatures;
    if(sig == NULL){
        goto out_with_release_in;
    }
    if(sig->next != NULL){
        log_error("");
        goto out_with_release_in;
    }
    const size_t fpr_size = strlen(sig->fpr) + 1;
    if(fpr_size > fpr_max_size){
        log_error("Test fingerprint requires %lu bytes", fpr_size);
        goto out_with_release_in;
    }
    memcpy(fpr, sig->fpr, fpr_size);
    ret = evr_ok;
 out_with_release_in:
    gpgme_data_release(in);
 out_with_release_gpg_ctx:
    gpgme_release(gpg_ctx);
 out:
    return ret;
}

void stringify_dynamic_array(struct dynamic_array **da){
    char buf[1];
    *da = write_n_dynamic_array(*da, buf, sizeof(buf));
    assert(*da);
}

int main(){
    evr_init_basics();
    evr_init_signatures();
    run_test(test_hello_world_signature);
    run_test(test_validate_hello_world_signature);
    return 0;
}
