/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021  Markus Peröbner
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

#include <threads.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "assert.h"
#include "memory.h"
#include "queue.h"
#include "test.h"

void test_single_thread_put_pop(){
    queue_t *q = evr_queue_create(1);
    assert_not_null(q);
    for(int i = 0; i < 10; i++){
        assert_zero(evr_queue_put(q, (void*)1));
        void *p;
        assert_zero(evr_queue_pop(q, &p));
        assert_equal((size_t)p, 1);
    }
    evr_queue_free(q);
}

void test_empty_pop(){
    queue_t *q = evr_queue_create(1);
    assert_not_null(q);
    void *p;
    assert_equal(evr_queue_pop(q, &p), evr_queue_empty);
    evr_queue_free(q);
}

void test_full_put(){
    queue_t *q = evr_queue_create(1);
    assert_not_null(q);
    assert_zero(evr_queue_put(q, (void*)1));
    assert_equal(evr_queue_put(q, (void*)2), evr_queue_full);
    evr_queue_free(q);
}

volatile int test_multi_thread_put_pop_running;

typedef struct {
    int id;
    queue_t *queue;
} test_multi_thread_put_pop_ctx;

void test_multi_thread_put_pop_scenario(long threads_count, size_t queue_capacity, size_t juggled_items_count);
int multi_thread_put_pop_main(void *arg);
void assert_juggled_item_contains(int ctx_id, const char *s, uint8_t *item, int expected);

// TODO make different juggled_item_sizes part of test scenarios
const size_t juggled_item_size = 2*4096; // TODO 2*pagesize

void test_multi_thread_put_pop(){
    const long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    printf("Detected cpu_count %ld.\n", cpu_count);
    test_multi_thread_put_pop_scenario(1, 1, 1);
    if(cpu_count >= 2){
        test_multi_thread_put_pop_scenario(2, 2, 1);
        test_multi_thread_put_pop_scenario(2, 1, 2);
        test_multi_thread_put_pop_scenario(2, 20, 10);
    }
    if(cpu_count > 1){
        const long some_cpu_count = cpu_count - 1;
        test_multi_thread_put_pop_scenario(some_cpu_count, some_cpu_count, 2 * some_cpu_count - 1);
    }
    test_multi_thread_put_pop_scenario(cpu_count * 2, 2, 2);
    // test_multi_thread_put_pop_scenario(cpu_count * 8, cpu_count * 2, cpu_count * 8 + cpu_count * 2 - 2);
}

void test_multi_thread_put_pop_scenario(long threads_count, size_t queue_capacity, size_t juggled_items_count){
    printf("Running scenario with %ld threads, %ld queue capacity and %ld juggled items\n", threads_count, queue_capacity, juggled_items_count);
    // this assertion should prevent a deadlock
    assert_greater_equal(threads_count + queue_capacity, juggled_items_count);
    queue_t *queue = evr_queue_create(queue_capacity);
    assert_not_null(queue);
    // the following test makes sure that reading and writing are
    // aligned to the cache line.
    assert_zero((unsigned long)queue->reading % L1_CACHE_BYTES);
    assert_zero((unsigned long)queue->writing % L1_CACHE_BYTES);
    test_multi_thread_put_pop_running = 1;
    thrd_t threads[threads_count];
    thrd_t *threads_end = &(threads[threads_count]);
    test_multi_thread_put_pop_ctx ctxs[threads_count];
    {
        int next_id = 1;
        test_multi_thread_put_pop_ctx *ctx = ctxs;
        for(thrd_t *t = threads; t != threads_end; t++){
            ctx->id = next_id++;
            ctx->queue = queue;
            assert_equal(thrd_create(t, multi_thread_put_pop_main, ctx), thrd_success);
            ctx++;
        }
    }
    uint8_t *juggled_items[juggled_items_count];
    uint8_t **juggled_items_end = &(juggled_items[juggled_items_count]);
    for(uint8_t **item = juggled_items; item != juggled_items_end; item++){
        *item = (uint8_t*)malloc(juggled_item_size);
        assert_not_null(*item);
        printf("Juggled item at %p (mod %d = %ld)\n", *item, L1_CACHE_BYTES, (unsigned long)*item % L1_CACHE_BYTES);
        memset(*item, 0, juggled_item_size);
        assert_equal(evr_queue_put_blocking(queue, *item), evr_ok);
    }
    {
        struct timespec t = { 60, 0 };
        assert_zero(thrd_sleep(&t, NULL));
    }
    printf("running=0\n");
    test_multi_thread_put_pop_running = 0;
    for(thrd_t *t = threads; t != threads_end; t++){
        int thread_result;
        assert_equal(thrd_join(*t, &thread_result), thrd_success);
        assert_zero(thread_result);
    }
    for(uint8_t **item = juggled_items; item != juggled_items_end; item++){
        assert_juggled_item_contains(-1, "end uniform", *item, **item);
        free(*item);
    }
    evr_queue_free(queue);
}

int multi_thread_put_pop_main(void *arg){
    test_multi_thread_put_pop_ctx *ctx = (test_multi_thread_put_pop_ctx*)arg;
    while(test_multi_thread_put_pop_running){
        void *p;
        int pop_result = evr_queue_pop(ctx->queue, &p);
        if(pop_result == evr_queue_blocked || pop_result == evr_queue_empty){
            continue;
        }
        assert_equal(pop_result, evr_ok);
        assert_not_null(p);
        {
            uint8_t *juggled_item = (uint8_t*)p;
            uint8_t *juggled_item_end = &(juggled_item[juggled_item_size]);
            assert_juggled_item_contains(ctx->id, "uniform", juggled_item, *juggled_item);
            for(uint8_t *i = juggled_item; i != juggled_item_end; i++){
                *i = (uint8_t)ctx->id;
                // TODO try a clflush here with *i
                // TODO make *i a cache line sized pointer
            }
            assert_juggled_item_contains(ctx->id, "a specific value", juggled_item, ctx->id);
        }
        while(test_multi_thread_put_pop_running){
            int put_result = evr_queue_put(ctx->queue, p);
            if(put_result == evr_ok){
                break;
            }
            if(put_result == evr_queue_blocked || put_result == evr_queue_full){
                continue;
            }
            return 1;
        }
    }
    return 0;
}

void assert_juggled_item_contains(int ctx_id, const char *s, uint8_t *item, int expected){
    uint8_t *end = item + juggled_item_size;
    for(uint8_t *p = item; p != end; p++){
        int actual = (uint8_t)*p;
        int pos = (int)(p - item);
        assert_equal_msg(actual, expected, "Expected juggled item %p in ctx id %d at offset %d content to be %s but %d != %d\n", item, ctx_id, pos, s, actual, expected);
    }
}

int main(){
    run_test(test_single_thread_put_pop);
    run_test(test_empty_pop);
    run_test(test_full_put);
    run_test(test_multi_thread_put_pop);
}
