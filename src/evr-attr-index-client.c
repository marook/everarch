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

#include "errors.h"
#include "logger.h"

int evr_attri_validate_argument(char *arg){
    for(char *c = arg; *c != '\0'; ++c){
        if(*c == '\n'){
            return evr_error;
        }
    }
    return evr_ok;
}

int evr_attri_write_auth_token(struct evr_file *f, evr_auth_token t){
    const char prefix[] = "a token ";
    char buf[sizeof(prefix) - 1 + sizeof(evr_auth_token_str) - 1 + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, prefix);
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

struct evr_attri_search_ctx {
    size_t visited_seed_count;
    void *ctx;
    int (*visit_seed)(void *ctx, evr_claim_ref seed);
    int (*visit_attr)(void *ctx, evr_claim_ref seed, char *key, char *val);
};

int evr_attri_search_visit_seed(void *ctx, evr_claim_ref seed);
int evr_attri_search_visit_attr(void *ctx, evr_claim_ref seed, char *key, char *val);

int evr_attri_search(struct evr_buf_read *r, char *query, int (*visit_seed)(void *ctx, evr_claim_ref seed), int (*visit_attr)(void *ctx, evr_claim_ref seed, char *key, char *val), void *ctx){
    size_t offset = 0;
    const size_t limit = 256;
    size_t query_len = strlen(query);
    const char limit_exp[] = " limit ";
    char limit_query[query_len + (sizeof(limit_exp) - 1) + 40];
    memcpy(limit_query, query, query_len);
    memcpy(&limit_query[query_len], limit_exp, sizeof(limit_exp) - 1);
    char *limit_query_offset = &limit_query[query_len + sizeof(limit_exp) - 1];
    struct evr_attri_search_ctx search_ctx;
    search_ctx.ctx = ctx;
    search_ctx.visit_seed = visit_seed;
    search_ctx.visit_attr = visit_attr;
    while(1){
        if(sprintf(limit_query_offset, "%zu offset %zu", limit, offset) <= 0){
            return evr_error;
        }
        if(evr_attri_write_search(r->f, limit_query) != evr_ok){
            return evr_error;
        }
        search_ctx.visited_seed_count = 0;
        int read_res = evr_attri_read_search(r, evr_attri_search_visit_seed, evr_attri_search_visit_attr, &search_ctx);
        if(read_res == evr_end){
            return evr_ok;
        } else if(read_res != evr_ok){
            return evr_error;
        }
        if(search_ctx.visited_seed_count < limit){
            break;
        }
        offset += limit;
    }
    return evr_ok;
}

int evr_attri_search_visit_seed(void *ctx, evr_claim_ref seed){
    struct evr_attri_search_ctx *search_ctx = ctx;
    search_ctx->visited_seed_count += 1;
    if(search_ctx->visit_seed){
        return search_ctx->visit_seed(search_ctx->ctx, seed);
    }
    return evr_ok;
}

int evr_attri_search_visit_attr(void *ctx, evr_claim_ref seed, char *key, char *val){
    struct evr_attri_search_ctx *search_ctx = ctx;
    if(search_ctx->visit_attr){
        return search_ctx->visit_attr(search_ctx->ctx, seed, key, val);
    }
    return evr_ok;
}

int evr_attri_write_search(struct evr_file *f, char *query){
    size_t query_len = strlen(query);
    char buf[2 + query_len + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_concat(&bp, "s ");
    evr_push_n(&bp, query, query_len);
    evr_push_concat(&bp, "\n");
    log_debug("Writing evr-attr-index query to fd %d: %s", f->get_fd(f), query);
    return write_n(f, buf, bp.pos - bp.buf);
}

int evr_attri_read_status(struct evr_buf_read *r);

int evr_attri_read_search(struct evr_buf_read *r, int (*visit_seed)(void *ctx, evr_claim_ref seed), int (*visit_attr)(void *ctx, evr_claim_ref seed, char *key, char *val), void *ctx){
    if(evr_attri_read_status(r) != evr_ok){
        return evr_error;
    }
    int has_seed = 0;
    evr_claim_ref seed;
    int end = 0;
    while(1){
        size_t nl_offset;
        if(evr_buf_read_read_until(r, '\n', &nl_offset) != evr_ok){
            return evr_error;
        }
        char line[nl_offset + 1];
        if(evr_buf_read_pop(r, line, sizeof(line)) != evr_ok){
            return evr_error;
        }
        if(line[0] == '\t'){
            if(!has_seed){
                return evr_error;
            }
            size_t eq_i = 1;
            for(; eq_i < sizeof(line); ++eq_i){
                if(line[eq_i] == '='){
                    break;
                }
            }
            if(eq_i == sizeof(line)){
                return evr_error;
            }
            line[eq_i] = '\0';
            line[sizeof(line) - 1] = '\0';
            if(visit_attr && visit_attr(ctx, seed, &line[1], &line[eq_i + 1]) != evr_ok){
                return evr_error;
            }
        } else if(line[0] == '\n'){
            return end ? evr_end : evr_ok;
        } else {
            // claim-ref line
            line[sizeof(line) - 1] = '\0';
            if(evr_parse_claim_ref(seed, line) != evr_ok){
                return evr_error;
            }
            has_seed = 1;
            if(visit_seed){
                int visit_res = visit_seed(ctx, seed);
                if(visit_res == evr_end){
                    end = 1;
                } else if(visit_res != evr_ok){
                    return evr_error;
                }
            }
        }
    }
}

int evr_attri_read_status(struct evr_buf_read *r){
    size_t nl_offset;
    if(evr_buf_read_read_until(r, '\n', &nl_offset) != evr_ok){
        return evr_error;
    }
    char line[nl_offset + 1];
    if(evr_buf_read_pop(r, line, sizeof(line)) != evr_ok){
        return evr_error;
    }
    line[nl_offset] = '\0';
    if(strcmp(line, "OK") != 0){
        log_error("evr-attr-index indicated former query failed: %s", line);
    }
    return evr_ok;
}

int evr_attri_write_describe_index(struct evr_file *f);

int evr_attri_describe_index(struct evr_buf_read *r, evr_blob_ref *index_ref){
    if(evr_attri_write_describe_index(r->f) != evr_ok){
        return evr_error;
    }
    if(evr_attri_read_status(r) != evr_ok){
        return evr_error;
    }
    int has_index_ref = 0;
    while(1){
        size_t nl_offset;
        if(evr_buf_read_read_until(r, '\n', &nl_offset) != evr_ok){
            return evr_error;
        }
        char line[nl_offset + 1];
        if(evr_buf_read_pop(r, line, sizeof(line)) != evr_ok){
            return evr_error;
        }
        if(line[0] == '\n'){
            break;
        }
        size_t colon_i = 0;
        for(; colon_i < sizeof(line); ++colon_i){
            if(line[colon_i] == ':'){
                break;
            }
        }
        // the 'one extra' is for the space after the colon
        if(colon_i >= sizeof(line) - 1){
            return evr_error;
        }
        if(line[colon_i + 1] != ' '){
            return evr_error;
        }
        char *value = &line[colon_i + 2];
        // replace \n with \0
        line[sizeof(line) - 1] = '\0';
        line[colon_i] = '\0';
        if(strcmp(line, "index-ref") == 0){
            has_index_ref = 1;
            if(evr_parse_blob_ref(*index_ref, value) != evr_ok){
                return evr_error;
            }
        }
    }
    if(!has_index_ref){
        return evr_error;
    }
    return evr_ok;
}

int evr_attri_write_describe_index(struct evr_file *f){
    log_debug("Writing evr-attr-index describe index command");
    char cmd[] = "i\n";
    return write_n(f, cmd, sizeof(cmd) - 1);
}
