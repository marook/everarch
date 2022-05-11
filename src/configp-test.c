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

#include "assert.h"
#include "test.h"
#include "logger.h"
#include "configp.h"

struct cli_arguments {
    char *config_option;
};

static char doc[] = "configp-test demo documentation.";

static char args_doc[] = "";

static struct argp_option options[] = {
    {"config-option", 'o', "O", 0, "Demo config option."},
    {0},
};

static error_t parse_opt(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state)){
    struct cli_arguments *cli_args = (struct cli_arguments*)state->input;
    switch(key){
    default:
        return ARGP_ERR_UNKNOWN;
    case 'o': {
        if(cli_args->config_option){
            free(cli_args->config_option);
        }
        cli_args->config_option = strdup(arg);
        break;
    }
    }
    return 0;
}

static struct configp configp = { options, parse_opt, args_doc, doc };

void test_parse_config(){
#define files_dir "../testing/data/configs/"
    char *files[] = {
        files_dir "no-such-config-file.conf",
        files_dir "a.conf",
        files_dir "b.conf",
        NULL,
    };
#undef files_dir
    struct cli_arguments input;
    input.config_option = NULL;
    assert(configp_parse(&configp, files, &input) == 0);
    assert(is_str_eq(input.config_option, "b"));
    free(input.config_option);
}

int main(){
    run_test(test_parse_config);
    return 0;
}
