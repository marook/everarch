/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
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

#include "errors.h"

#include <string.h>

int evr_strerror_r(int errnum, char **buf, size_t buflen){
#ifdef __GLIBC__
    *buf = strerror_r(errnum, *buf, buflen);
    return evr_ok;
#else
    if(strerror_r(errnum, *buf, buflen) != 0){
        return evr_error;
    }
    return evr_ok;
#endif
}
