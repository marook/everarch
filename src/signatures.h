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

#ifndef __evr_signatures_h__
#define __evr_signatures_h__

#include "dyn-mem.h"
#include "metadata.h"

/**
 * evr_init_signatures must be called once in the process before any
 * sign operation.
 */
void evr_init_signatures(void);

/**
 * evr_sign will sign s and write the signed string s in text mode
 * into dest.
 *
 * evr_sign may add a trailing newline to the signed string. You may
 * retrieve the newline after extracting the signed string later using
 * evr_verify.
 *
 * *dest may point to NULL. The struct dynamic_array will be allocated
 * in that case.
 */
int evr_sign(char *signing_key_fpr, struct dynamic_array **dest, const char *s);

struct evr_verify_ctx {
    /**
     * accepted_fprs is the list of accepted gpg fingerprints for
     * validation.
     *
     * The list of fingerprints is sorted by strcmp.
     */
    char **accepted_fprs;
    size_t accepted_fprs_len;
};

struct evr_verify_ctx *evr_build_verify_ctx(struct evr_llbuf *accepted_gpg_fprs);

struct evr_verify_ctx* evr_init_verify_ctx(char **accepted_fprs, size_t accepted_fprs_len);

#define evr_free_verify_ctx(ctx) free(ctx)

/**
 * evr_verify will verify the signature attached to message s. Also it
 * will write the message without signature wrapping into dest.
 *
 * Return evr_ok on success. Returns evr_user_data_invalid if the
 * message's signature is not trusted for some reason. Otherwise evr_error.
 */
int evr_verify(struct evr_verify_ctx *ctx, struct dynamic_array **dest, const char *s, size_t s_maxlen, struct evr_file *meta);

struct evr_verify_cfg {
    /**
     * accepted_gpg_fprs contains the accepted gpg fingerprints for
     * signed claims.
     *
     * The llbuf data points to a fingerprint string.
     *
     * This field is only filled during the initialization of the
     * application. During runtime the ctx field should be used.
     */
    struct evr_llbuf *accepted_gpg_fprs;

    struct evr_verify_ctx *ctx;
};

// TODO check if this can also be used in evr cli or evr-attr-index
void evr_init_verify_cfg(struct evr_verify_cfg *cfg);
void evr_free_verify_cfg(struct evr_verify_cfg *cfg);

int evr_verify_add_gpg_fpr(struct evr_verify_cfg *cfg, const char *fpr);
int evr_verify_cfg_parse(struct evr_verify_cfg *cfg);

#endif
