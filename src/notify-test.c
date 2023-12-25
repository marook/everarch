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
#include "test.h"
#include "notify.h"
#include "errors.h"

void test_notify_send(void){
    struct evr_notify_ctx *nt = evr_create_notify_ctx(1, 1, 1);
    assert(nt);
    struct evr_queue *msg = evr_notify_register(nt, NULL);
    assert(msg);
    struct evr_queue *msg2 = evr_notify_register(nt, NULL);
    assert(!msg2);
    char receive = 'r';
    assert(evr_queue_take(msg, &receive) == evr_not_found);
    char send = 's';
    assert(is_ok(evr_notify_send(nt, &send, NULL, NULL)));
    receive = 'r';
    assert(is_ok(evr_queue_take(msg, &receive)));
    assert(receive == 's');
    assert(is_ok(evr_notify_unregister(nt, msg)));
    evr_free_notify_ctx(nt);
}

int main(void){
    evr_init_basics();
    run_test(test_notify_send);
    return 0;
}
