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

/*
 * configp.h declares a configuration file parser which takes nearly
 * the same arguments as argp.h. The idea is to declare your command
 * line arguments for argp, do a little wrapping and also have a
 * configuration file parser.
 *
 * There are some differences to argp you should notice:
 * - ARGP_KEY_ARG arguments are not supported.
 * - parser has one extra argument which would be argp_usage if you were
 *   called by argp.
 * - every property of argp_state must not be accessed in the parser
 *   call except: input
 */

#ifndef configp_h
#define configp_h

#include <argp.h>

struct configp {
    const struct argp_option *options;
    error_t (*parser)(int key, char *arg, struct argp_state *state, void (*usage)(const struct argp_state *state));
    const char *args_doc;
    const char *doc;
};

/**
 * configp_parse parses the given file paths in order.
 *
 * Files must be terminated by a NULL pointer. Only the first existing
 * file is parsed.
 *
 * Returns 0 on success. Will eventually not return because exit is
 * called on parse errors.
 */
int configp_parse(struct configp *p, char **files, void *input);

#endif
