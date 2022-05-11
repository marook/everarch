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

#include "configurations.h"

#include <ctype.h>
#include <wordexp.h>

#include "errors.h"
#include "logger.h"

int evr_single_wordexp(char **pathname){
    int ret = evr_error;
    if(*pathname){
        wordexp_t p;
        wordexp(*pathname, &p, 0);
        if(p.we_wordc != 1){
            log_error("Pathname %s must only expand to one file", *pathname);
            goto out_with_free_p;
        }
        replace_string(*pathname, p.we_wordv[0], out_with_free_p);
        ret = evr_ok;
    out_with_free_p:
        wordfree(&p);
    } else {
        ret = evr_ok;
    }
    return ret;
}
