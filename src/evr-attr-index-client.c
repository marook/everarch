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

#include "evr-attr-index-client.h"

int evr_attri_write_auth_token(struct evr_file *f, evr_auth_token t){
    char buf[2 + sizeof(evr_auth_token_str) - 1 + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, "a ");
    evr_fmt_auth_token(bp.pos, t);
    evr_inc_buf_pos(&bp, sizeof(evr_auth_token_str) - 1);
    evr_push_concat(&bp, "\n");
    return write_n(f, buf, bp.pos - bp.buf);
}

int evr_attri_write_list_claims_for_seed(struct evr_file *f, evr_claim_ref seed){
    char buf[2 + sizeof(evr_claim_ref_str) - 1 + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, "c ");
    evr_fmt_claim_ref(bp.pos, seed);
    evr_inc_buf_pos(&bp, sizeof(evr_claim_ref_str) - 1);
    evr_push_concat(&bp, "\n");
    return write_n(f, buf, bp.pos - bp.buf);
}
