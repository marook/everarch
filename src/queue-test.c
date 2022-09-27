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

#include "queue.h"
#include "test.h"
#include "assert.h"
#include "errors.h"

void test_empty_queue_wait(){
    struct evr_queue *q = evr_create_queue(2, 1);
    assert(q);
    assert(evr_queue_take(q, NULL) == evr_not_found);
    assert(q->status == evr_ok);
    evr_queue_end_producing(q);
    int status = evr_error;
    assert(is_ok(evr_free_queue(q, &status)));
    assert(is_ok(status));
}

void test_overflow_queue(){
    struct evr_queue *q = evr_create_queue(1, 1);
    assert(q);
    char a = 'a';
    assert(is_ok(evr_queue_put(q, &a)));
    assert(q->status == evr_ok);
    assert(evr_queue_put(q, &a) == evr_temporary_occupied);
    assert(q->status == evr_temporary_occupied);
    evr_queue_end_producing(q);
    int status = evr_ok;
    assert(is_ok(evr_free_queue(q, &status)));
    assert(status == evr_temporary_occupied);
}

void test_put_take_queue(){
    struct evr_queue *q = evr_create_queue(1, 1);
    assert(q);
    char a = 'a';
    assert(is_ok(evr_queue_put(q, &a)));
    char b = 'x';
    assert(is_ok(evr_queue_take(q, &b)));
    assert_msg(b == 'a', "Got %x %x", b);
    assert(q->status == evr_ok);
    assert(is_ok(evr_queue_put(q, &a)));
    evr_queue_end_producing(q);
    assert(is_ok(evr_free_queue(q, NULL)));
}

int main(){
    evr_init_basics();
    run_test(test_empty_queue_wait);
    run_test(test_overflow_queue);
    run_test(test_put_take_queue);
    return 0;
}
