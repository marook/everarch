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

#include <ctype.h>
#include <string.h>

#include "assert.h"
#include "dyn-mem.h"
#include "test.h"

int is_ignored(int c);

void test_fill_dynamic_array(){
    struct dynamic_array *a = alloc_dynamic_array(1);
    assert(a);
    a->size_used = 1;
    *(char*)a->data = 42;
    assert(*(char*)a->data == 42);
    free(a);
}

void test_rtrim_empty_array(){
    struct dynamic_array *a = alloc_dynamic_array(1);
    assert(a);
    rtrim_dynamic_array(a, is_ignored);
    assert(a->size_used == 0);
    free(a);
}

void test_rtrim_end_of_array(){
    struct dynamic_array *a = alloc_dynamic_array(1024);
    assert(a);
    strcpy((char*)a->data, "test   ");
    a->size_used = strlen((char*)a->data) + 1;
    rtrim_dynamic_array(a, is_ignored);
    assert(a->size_used == strlen("test"));
    free(a);
}

void test_grow_dynamic_array_at_least_existing(){
    struct dynamic_array *a = alloc_dynamic_array(1);
    assert(a);
    assert(a->size_allocated == 1);
    a->size_used = 1;
    *(char*)a->data = 42;
    a = grow_dynamic_array_at_least(a, 2);
    assert(a);
    assert(a->size_allocated == 2);
    assert(a->size_used == 1);
    assert(*(char*)a->data == 42);
    free(a);
}

void test_grow_dynamic_array_at_least_null(){
    struct dynamic_array *a = NULL;
    a = grow_dynamic_array_at_least(a, 1);
    assert(a);
    assert(a->size_allocated == 1);
    assert(a->size_used == 0);
    free(a);
}

void test_dynamic_array_remove(){
    struct dynamic_array *a = alloc_dynamic_array(100);
    assert(a);
    for(size_t i = 0; i < a->size_allocated; ++i){
        a->data[i] = i;
    }
    a->size_used = a->size_allocated;
    assert(is_ok(dynamic_array_remove(a, 20, 40)));
    assert(a->data[19] == 19);
    assert(a->data[20] == 60);
    free(a);
}

int is_ignored(int c){
    return c == 0 || isspace(c);
}

void test_allocate_chunk_set(){
    struct chunk_set *cs = evr_allocate_chunk_set(3);
    assert(cs);
    assert(cs->chunks_len == 3);
    // write into every byte of the chunk set to force an error in
    // valgrind if too less memory was allocated.
    for(int i = 0; i < cs->chunks_len; i++){
        char *c = cs->chunks[i];
        memset(c, 42, evr_chunk_size);
    }
    evr_free_chunk_set(cs);
}

void test_llbuf(){
    evr_free_llbuf_chain(NULL, NULL);
    struct evr_llbuf *llb = NULL;
    struct evr_buf_pos bp;
    int v = 42;
    assert(is_ok(evr_llbuf_prepend(&llb, &bp, sizeof(int))));
    evr_push_as(&bp, &v, int);
    assert(llb);
    assert(llb->next == NULL);
    assert(*(int*)llb->data == 42);
    struct evr_llbuf *first_llb = llb;
    v = 123;
    assert(is_ok(evr_llbuf_prepend(&llb, &bp, sizeof(int))));
    evr_push_as(&bp, &v, int);
    assert(llb);
    assert(llb->next == first_llb);
    assert(*(int*)llb->data == 123);
    evr_free_llbuf_chain(llb, NULL);
}

struct a_child {
    int i;
    char c;
};

void test_empty_llbuf_s(){
    struct evr_llbuf_s llb;
    evr_init_llbuf_s(&llb, sizeof(struct a_child));
    assert(!llb.first);
    assert(!llb.last);
    assert(llb.block_count == 0);
    // actual block_child_count depends on system's page size
    assert_msg(llb.block_child_count > 0, "But was %zu with child_size %zu", llb.block_child_count, llb.child_size);
    assert(llb.child_count == 0);
    assert(llb.child_size == sizeof(struct a_child));
    struct evr_llbuf_s_iter it;
    evr_init_llbuf_s_iter(&it, &llb);
    assert(!evr_llbuf_s_iter_next(&it));
    evr_llbuf_s_empty(&llb, NULL);
}

void test_filled_llbuf_s(){
    struct evr_llbuf_s llb;
    evr_init_llbuf_s(&llb, sizeof(struct a_child));
    struct a_child *c;
    assert(is_ok(evr_llbuf_s_append(&llb, (void**)&c)));
    assert(c);
    assert(llb.block_count = 1);
    assert(llb.child_count = 1);
    c->i = 42;
    c->c = 'x';
    struct evr_llbuf_s_iter it;
    evr_init_llbuf_s_iter(&it, &llb);
    c = evr_llbuf_s_iter_next(&it);
    assert(c);
    assert(c->i == 42);
    assert(c->c == 'x');
    assert(evr_llbuf_s_iter_next(&it) == NULL);
    evr_llbuf_s_empty(&llb, NULL);
}

int main(){
    evr_init_basics();
    run_test(test_fill_dynamic_array);
    run_test(test_rtrim_empty_array);
    run_test(test_rtrim_end_of_array);
    run_test(test_grow_dynamic_array_at_least_existing);
    run_test(test_grow_dynamic_array_at_least_null);
    run_test(test_dynamic_array_remove);
    run_test(test_allocate_chunk_set);
    run_test(test_llbuf);
    run_test(test_empty_llbuf_s);
    run_test(test_filled_llbuf_s);
    return 0;
}
