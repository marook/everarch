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

#include "configp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <wordexp.h>

#include "logger.h"

#define configp_ok 0
#define configp_error 1
#define configp_no_such_file 2


int configp_parse_file(struct configp *p, char *file, void *input);

int configp_parse(struct configp *p, char **files, void *input){
    for(char **f = files; *f; ++f){
        int res = configp_parse_file(p, *f, input);
        if(res == configp_no_such_file){
            continue;
        } else if (res == configp_ok) {
            break;
        } else {
            _exit(1);
        }
    }
    return 0;
}

int configp_consume_arg(struct configp *p, char *key, char *val, struct argp_state *state, char *file, int line_no);

#define state_whitespace 0
#define state_comment 1
#define state_key 2
#define state_post_key 3
#define state_pre_val 4
#define state_val 5

#define is_key_char(c) (((c) >= 'a' && (c) <= 'z') || (c) == '-')
#define is_inline_whitespace_char(c) ((c) == ' ' || (c) == '\n')
#define push_char(c, p, end)                                             \
    do {                                                                \
        if(p == end) {                                                  \
            log_error("Too long string detected in %s:%d:%d", file, line_no, col_no); \
            goto out_with_close_f;                                      \
        }                                                               \
        *(p++) = c;                                                     \
    } while(0)
#define out_with_unexpected_char_at_point()                                      \
    do {                                                                \
        log_error("Unexpected character in %s:%d:%d: '%c' (state=%d)", file, line_no, col_no, *b, state); \
        goto out_with_close_f;                                          \
    } while(0)

int configp_parse_file(struct configp *p, char *file, void *input){
    int ret = configp_error;
    wordexp_t wexp;
    wordexp(file, &wexp, 0);
    if(wexp.we_wordc != 1){
        log_error("Config file name %s must only expand to one file", file);
        goto out_with_free_wexp;
    }
    char *exp_file = wexp.we_wordv[0];
    int f = open(exp_file, O_RDONLY);
    if(f < 0){
        if(errno == ENOENT){
            ret = configp_no_such_file;
            goto out_with_free_wexp;
        }
        log_error("Config file %s can't be opened: %s", exp_file, strerror(errno));
        goto out_with_free_wexp;
    }
    log_debug("Parsing config file %s", exp_file);
    struct argp_state argp_state;
    argp_state.input = input;
    char buf[4096];
    int state = state_whitespace;
    int line_no = 1;
    int col_no = 0;
    char key[256];
    char *key_end = &key[sizeof(key)];
    char *keyp = key;
    char val[4096];
    char *val_end = &val[sizeof(val)];
    char *valp = val;
    while(1){
        ssize_t bytes_read = read(f, buf, sizeof(buf));
        if(bytes_read == 0){
            break;
        }
        char *end = &buf[bytes_read];
        for(char *b = buf; b != end; ++b){
            switch(state){
            default:
                evr_panic("Unknown state %d", state);
                goto out_with_close_f;
            case state_whitespace:
                if(*b == '#'){
                    state = state_comment;
                } else if(is_inline_whitespace_char(*b) || *b == '\n') {
                    // just ignore whitespace
                } else if(is_key_char(*b)) {
                    state = state_key;
                    push_char(*b, keyp, key_end);
                } else {
                    out_with_unexpected_char_at_point();
                }
                break;
            case state_comment:
                if(*b == '\n'){
                    state = state_whitespace;
                }
                break;
            case state_key:
                if(is_key_char(*b)){
                    push_char(*b, keyp, key_end);
                } else if(*b == ' ') {
                    state = state_post_key;
                } else if(*b == '=') {
                    state = state_val;
                } else {
                    out_with_unexpected_char_at_point();
                }
                break;
            case state_post_key:
                if(*b == '='){
                    state = state_pre_val;
                } else {
                    out_with_unexpected_char_at_point();
                }
                break;
            case state_pre_val:
                if(is_inline_whitespace_char(*b) || *b == '\n'){
                    // just ignore
                } else {
                    state = state_val;
                    push_char(*b, valp, val_end);
                }
                break;
            case state_val:
                if(is_inline_whitespace_char(*b) || *b == '\n'){
                    push_char('\0', keyp, key_end);
                    push_char('\0', valp, val_end);
                    if(configp_consume_arg(p, key, val, &argp_state, exp_file, line_no) != 0){
                        goto out_with_close_f;
                    }
                    keyp = key;
                    valp = val;
                    state = state_whitespace;
                } else {
                    push_char(*b, valp, val_end);
                }
                break;
            }
            if(*b == '\n'){
                ++line_no;
                col_no = 0;
            } else {
                ++col_no;
            }
        }
    }
    if(state != state_whitespace){
        log_error("Missing final newline in config file %s", exp_file);
        goto out_with_close_f;
    }
    ret = configp_ok;
 out_with_close_f:
    if(close(f) != 0){
        evr_panic("Failed to close config file %s", exp_file);
        ret = configp_error;
    }
 out_with_free_wexp:
    wordfree(&wexp);
    return ret;
}

#undef push_char

const struct argp_option *configp_find_option(const struct argp_option *options, char *key);

void configp_nop_usage(const struct argp_state *state);

int configp_consume_arg(struct configp *p, char *key, char *val, struct argp_state *state, char* file, int line_no){
    const struct argp_option *opt = configp_find_option(p->options, key);
    if(!opt){
        log_error("Unknown config key %s found in %s:%d", key, file, line_no);
        return 1;
    }
    if(p->parser(opt->key, val, state, configp_nop_usage) != 0){
        log_error("Unable to parse %s=%s in %s:%d", key, val, file, line_no);
        return 1;
    }
    return 0;
}

const struct argp_option *configp_find_option(const struct argp_option *options, char *key){
    for(const struct argp_option *it = options; it->name; ++it){
        if(strcmp(it->name, key) == 0){
            return it;
        }
    }
    return NULL;
}

void configp_nop_usage(const struct argp_state *state){
    // nop
}
