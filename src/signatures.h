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

/**
 * evr_init_signatures must be called once in the process before any
 * sign operation.
 */
void evr_init_signatures();

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
int evr_sign(struct dynamic_array **dest, const char *s);

/**
 * evr_verify will verify the signature attached to message s. Also it
 * will write the message without signature wrapping into dest.
 */
int evr_verify(struct dynamic_array **dest, const char *s, size_t s_maxlen);

#endif
