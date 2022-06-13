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

#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "basics.h"
#include "configp.h"
#include "logger.h"
#include "errors.h"
#include "glacier.h"

#define program_name "evr-glacier-tool"

const char *argp_program_version = program_name " " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] =
    program_name " is a command line client for analyzing evr-glacier-storage server data files.\n\n"
    "Possible commands are bucket-ls.\n\n"
    "The bucket-ls command lists all blobs within a bucket file. It expects the bucket file name as first argument."
    ;

static char args_doc[] = "CMD";

static struct argp_option options[] = {
    {0}
};

#define cli_cmd_none 0
#define cli_cmd_bucket_ls 1

struct cli_cfg {
    int cmd;
    char *bucket_file;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct cli_cfg *cfg = (struct cli_cfg*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARG:
        switch(state->arg_num){
        default:
            usage(state);
            return ARGP_ERR_UNKNOWN;
        case 0:
            if(strcmp("bucket-ls", arg) == 0){
                cfg->cmd = cli_cmd_bucket_ls;
            } else {
                usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case 1:
            switch(cfg->cmd){
            default:
                usage(state);
                return ARGP_ERR_UNKNOWN;
            case cli_cmd_bucket_ls:
                evr_replace_str(cfg->bucket_file, arg);
                break;
            }
            break;
        break;
    case ARGP_KEY_END:
        // not enough arguments?
        switch(cfg->cmd){
        default:
            usage (state);
            return ARGP_ERR_UNKNOWN;
        case cli_cmd_bucket_ls:
            if(state->arg_num < 2){
                usage(state);
                return ARGP_ERR_UNKNOWN;
            }
            break;
        }
        break;
        }
    }
    return 0;
}

static error_t parse_opt_adapter(int key, char *arg, struct argp_state *state){
    return parse_opt(key, arg, state, argp_usage);
}

int evr_bucket_ls(struct cli_cfg *cfg);

int main(int argc, char **argv){
    int ret = 1;
    evr_log_fd = STDERR_FILENO;
    evr_log_app = "G";
    struct cli_cfg cfg;
    cfg.cmd = cli_cmd_none;
    cfg.bucket_file = NULL;
    char *config_paths[] = evr_program_config_paths();
    struct configp configp = { options, parse_opt, args_doc, doc };
    if(configp_parse(&configp, config_paths, &cfg) != 0){
        goto out_with_free_cfg;
    }
    struct argp argp = { options, parse_opt_adapter, args_doc, doc };
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    switch(cfg.cmd){
    case cli_cmd_bucket_ls:
        ret = evr_bucket_ls(&cfg);
        break;
    }
 out_with_free_cfg:
    do {} while(0);
    void *tbfree[] = {
        cfg.bucket_file,
    };
    void **tbfree_end = &tbfree[sizeof(tbfree) / sizeof(void*)];
    for(void **it = tbfree; it != tbfree_end; ++it){
        if(*it){
            free(*it);
        }
    }
    return ret;
}

int evr_bucket_ls_visit_bucket(void *ctx, size_t last_bucket_pos);
int evr_bucket_ls_visit_blob(void *ctx, struct evr_glacier_bucket_blob_stat *stat);

int evr_bucket_ls(struct cli_cfg *cfg){
    printf("%s\n", "ref,flags,last-modified,offset,size,checksum");
    return evr_glacier_walk_bucket(cfg->bucket_file, evr_bucket_ls_visit_bucket, evr_bucket_ls_visit_blob, NULL);
}

int evr_bucket_ls_visit_bucket(void *ctx, size_t last_bucket_pos){
    return evr_ok;
}

int evr_bucket_ls_visit_blob(void *ctx, struct evr_glacier_bucket_blob_stat *stat){
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, stat->ref);
    printf("%s,%d," evr_time_fmt ",%lu,%lu,%d\n", ref_str, stat->flags, stat->last_modified, stat->offset, stat->size, (int)stat->checksum);
    return evr_ok;
}
