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
#include "logger.h"

void evr_init_signatures(){
    gpgme_check_version(NULL);
}

int evr_signatures_build_ctx(gpgme_ctx_t *ctx);

int evr_signatures_read_data(struct dynamic_array **dest, gpgme_data_t d, size_t dest_size_hint);

int evr_sign(char *signing_key_fpr, struct dynamic_array **dest, const char *s){
    int ret = evr_error;
    gpgme_ctx_t gpg_ctx;
    if(evr_signatures_build_ctx(&gpg_ctx) != evr_ok){
        goto out;
    }
    if(signing_key_fpr){
        gpgme_key_t key;
        if(gpgme_get_key(gpg_ctx, signing_key_fpr, &key, 0) != GPG_ERR_NO_ERROR){
            goto out_with_release_gpg_ctx;
        }
        if(gpgme_signers_add(gpg_ctx, key) != GPG_ERR_NO_ERROR){
            gpgme_key_release(key);
            goto out_with_release_gpg_ctx;
        }
        gpgme_key_release(key);
    }
    size_t s_len = strlen(s);
    gpgme_data_t in;
    if(gpgme_data_new_from_mem(&in, s, s_len, 0) != GPG_ERR_NO_ERROR){
        goto out_with_release_gpg_ctx;
    }
    gpgme_data_t out;
    if(gpgme_data_new(&out) != GPG_ERR_NO_ERROR){
        goto out_with_release_in;
    }
    gpgme_error_t sign_res = gpgme_op_sign(gpg_ctx, in, out, GPGME_SIG_MODE_CLEAR);
    if(sign_res != GPG_ERR_NO_ERROR){
        log_error("Unable to sign data with key %s: %s", signing_key_fpr, gpgme_strerror(sign_res));
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
 out_with_release_gpg_ctx:
    gpgme_release(gpg_ctx);
 out:
    return ret;
}

struct evr_verify_ctx *evr_build_verify_ctx(struct evr_llbuf *accepted_gpg_fprs){
    size_t fprs_len = 0;
    for(struct evr_llbuf *p = accepted_gpg_fprs; p; p = p->next){
        ++fprs_len;
    }
    char *fprs[fprs_len];
    char **f = fprs;
    for(struct evr_llbuf *p = accepted_gpg_fprs; p; p = p->next){
        *f++ = p->data;
    }
    return evr_init_verify_ctx(fprs, fprs_len);
}

struct evr_verify_ctx* evr_init_verify_ctx(char **accepted_fprs, size_t accepted_fprs_len){
    size_t accepted_fprs_size_sum = 0;
    char **accepted_fprs_end = &accepted_fprs[accepted_fprs_len];
    for(char **fprs = accepted_fprs; fprs != accepted_fprs_end; ++fprs){
        accepted_fprs_size_sum += strlen(*fprs) + 1;
    }
    char *buf = malloc(sizeof(struct evr_verify_ctx) + accepted_fprs_len * sizeof(char*) + accepted_fprs_size_sum);
    if(!buf){
        return NULL;
    }
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_verify_ctx *ctx;
    evr_map_struct(&bp, ctx);
    ctx->accepted_fprs = (char**)bp.pos;
    ctx->accepted_fprs_len = accepted_fprs_len;
    evr_inc_buf_pos(&bp, accepted_fprs_len * sizeof(char*));
    char **ctx_fpr = ctx->accepted_fprs;
    for(char **fprs = accepted_fprs; fprs != accepted_fprs_end; ++fprs){
        *ctx_fpr++ = bp.pos;
        size_t fpr_size = strlen(*fprs) + 1;
        evr_push_n(&bp, *fprs, fpr_size);
    }
    qsort(ctx->accepted_fprs, ctx->accepted_fprs_len, sizeof(*ctx->accepted_fprs), (int (*)(const void *l, const void *r))evr_strpcmp);
    return ctx;
}

int evr_is_signature_accepted(struct evr_verify_ctx* ctx, gpgme_signature_t s);

int evr_verify(struct evr_verify_ctx *ctx, struct dynamic_array **dest, const char *s, size_t s_maxlen, struct evr_file *meta){
    int ret = evr_error;
    gpgme_ctx_t gpg_ctx;
    if(evr_signatures_build_ctx(&gpg_ctx) != evr_ok){
        goto out;
    }
    size_t s_len = strnlen(s, s_maxlen);
    gpgme_data_t in;
    if(gpgme_data_new_from_mem(&in, s, s_len, 0) != GPG_ERR_NO_ERROR){
        goto out_with_release_gpg_ctx;
    }
    gpgme_data_t out;
    if(gpgme_data_new(&out) != GPG_ERR_NO_ERROR){
        goto out_with_release_in;
    }
    if(gpgme_op_verify(gpg_ctx, in, NULL, out) != GPG_ERR_NO_ERROR){
        goto out_with_release_out;
    }
    gpgme_verify_result_t res = gpgme_op_verify_result(gpg_ctx);
    if(res == NULL){
        goto out_with_release_out;
    }
    if(meta){
        for(gpgme_signature_t s = res->signatures; s; s = s->next){
            if(evr_meta_write_str(meta, evr_meta_signed_by, s->fpr) != evr_ok){
                goto out_with_release_out;
            }
        }
    }
    if(evr_is_signature_accepted(ctx, res->signatures) != evr_ok){
        ret = evr_user_data_invalid;
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
 out_with_release_gpg_ctx:
    gpgme_release(gpg_ctx);
 out:
    return ret;
}

int evr_is_signature_accepted(struct evr_verify_ctx* ctx, gpgme_signature_t s){
    for(; s; s = s->next){
        if((s->summary & GPGME_SIGSUM_VALID) == 0 && s->summary != GPGME_SIGSUM_KEY_EXPIRED){
            log_debug("Signature from key %s not valid. Signature summary is 0x%lx and status is %lu", s->fpr, (unsigned long)s->summary, (unsigned long)s->status);
            continue;
        }
        if(bsearch(&s->fpr, ctx->accepted_fprs, ctx->accepted_fprs_len, sizeof(*ctx->accepted_fprs), (int (*)(const void *l, const void *r))evr_strpcmp) == NULL){
            log_debug("Valid but not accepted signature of key with fingerprint %s found", s->fpr);
            continue;
        }
        return evr_ok;
    }
    return evr_error;
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

void evr_init_verify_cfg(struct evr_verify_cfg *cfg){
    cfg->accepted_gpg_fprs = NULL;
    cfg->ctx = NULL;
}

void evr_free_verify_cfg(struct evr_verify_cfg *cfg){
    if(cfg->ctx){
        evr_free_verify_ctx(cfg->ctx);
    }
    if(cfg->accepted_gpg_fprs){
        evr_free_llbuf_chain(cfg->accepted_gpg_fprs, NULL);
    }
}

int evr_verify_add_gpg_fpr(struct evr_verify_cfg *cfg, const char *fpr){
    struct evr_buf_pos bp;
    const size_t fpr_size = strlen(fpr) + 1;
    if(evr_llbuf_prepend(&cfg->accepted_gpg_fprs, &bp, fpr_size) != evr_ok){
        return evr_error;
    }
    evr_push_n(&bp, fpr, fpr_size);
    return evr_ok;
}

int evr_verify_cfg_parse(struct evr_verify_cfg *cfg){
    cfg->ctx = evr_build_verify_ctx(cfg->accepted_gpg_fprs);
    if(!cfg->ctx){
        return evr_error;
    }
    evr_free_llbuf_chain(cfg->accepted_gpg_fprs, NULL);
    cfg->accepted_gpg_fprs = NULL;
    return evr_ok;
}

