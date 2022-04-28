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

#include "assert.h"
#include "signatures.h"
#include "test.h"

void stringify_dynamic_array(struct dynamic_array **da);

void test_hello_world_signature(){
    struct dynamic_array *out = NULL;
    assert(is_ok(evr_sign(&out, "hello world!")));
    assert(out);
    stringify_dynamic_array(&out);
    assert(is_str_in((char*)out->data, "hello world"));
    assert(is_str_in((char*)out->data, "-----BEGIN PGP SIGNATURE-----"));
    free(out);
}

void test_validate_hello_world_signature(){
    struct dynamic_array *sgn = NULL;
    assert(is_ok(evr_sign(&sgn, "hello world!")));
    assert(sgn);
    struct dynamic_array *msg = NULL;
    assert(is_ok(evr_verify(&msg, sgn->data, sgn->size_used)));
    free(sgn);
    stringify_dynamic_array(&msg);
    if(msg->data[msg->size_used - 2] == '\n'){
        msg->data[msg->size_used - 2] = '\0';
    }
    assert(is_str_eq(msg->data, "hello world!"));
    free(msg);
}

void stringify_dynamic_array(struct dynamic_array **da){
    char buf[1];
    *da = write_n_dynamic_array(*da, buf, sizeof(buf));
    assert(*da);
}

int main(){
    evr_init_signatures();
    run_test(test_hello_world_signature);
    run_test(test_validate_hello_world_signature);
    return 0;
}
