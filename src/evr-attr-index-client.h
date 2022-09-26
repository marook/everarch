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

#ifndef evr_attr_index_client_h
#define evr_attr_index_client_h

#include "config.h"

#include "files.h"
#include "auth.h"
#include "keys.h"

int evr_attri_write_auth_token(struct evr_file *f, evr_auth_token t);

int evr_attri_write_list_claims_for_seed(struct evr_file *f, evr_claim_ref seed);

#endif
