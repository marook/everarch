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

#ifndef __errors_h__
#define __errors_h__

#include "config.h"

#include <stddef.h>

#define evr_ok 0
#define evr_error 1
#define evr_not_found 2
#define evr_temporary_occupied 3
#define evr_end 4
#define evr_user_data_invalid 5
#define evr_exists 6
#define evr_unknown_request 7

/**
 * evr_index_db_corrupt indicates that the evr-glacier-storage
 * index.db is corrupt.
 */
#define evr_glacier_index_db_corrupt 100

/**
 * evr_strerror_r is the superset of the XSI and GNU compliant
 * strerror_r function.
 *
 * The caller must provide a buffer of buflen at *buf. The *buf
 * pointer may have changed after the call and point to a statically
 * allocated string. In that case the provided buffer is not used.
 *
 * *buf points to the error string in any success case after the call.
 *
 * Returns evr_ok if the call was successful.
 */
int evr_strerror_r(int errnum, char **buf, size_t buflen);

#endif
