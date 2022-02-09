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

#include "assert.h"
#include "signatures.h"
#include "test.h"

void test_hello_world_signature(){
    struct dynamic_array *out = NULL;
    assert_ok(evr_sign(&out, "hello world!"));
    assert_not_null(out);
    assert_str_contains((char*)out->data, "hello world");
    assert_str_contains((char*)out->data, "-----BEGIN PGP SIGNATURE-----");
    free(out);
}

int main(){
    evr_init_signatures();
    run_test(test_hello_world_signature);
    return 0;
}
