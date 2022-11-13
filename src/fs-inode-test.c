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
#include "fs-inode.h"
#include "test.h"
#include "logger.h"

void test_create_free_inodes(){
    struct evr_inode *inodes = evr_create_inodes(100);
    assert(inodes);
    struct evr_inode *root = &inodes[FUSE_ROOT_ID];
    assert(root->type == evr_inode_type_dir);
    assert(root->data.dir.children_len == 0);
    assert(inodes[FUSE_ROOT_ID + 1].type == evr_inode_type_unlinked);
    evr_free_inodes(inodes);
}

void test_inodes_with_file(){
    size_t inodes_len = 100;
    struct evr_inode *inodes = evr_create_inodes(inodes_len);
    assert(inodes);
    // add first file
    char *name = strdup("my-dir/file.txt");
    assert(name);
    fuse_ino_t f1 = evr_inode_create_file(&inodes, &inodes_len, name);
    free(name);
    assert(f1 != 0);
    struct evr_inode *root = &inodes[FUSE_ROOT_ID];
    assert(root->data.dir.children_len == 1);
    fuse_ino_t dir = root->data.dir.children[0];
    assert(dir != 0);
    struct evr_inode *dir_node = &inodes[dir];
    assert(dir_node->type == evr_inode_type_dir);
    assert(is_str_eq(dir_node->name, "my-dir"));
    assert(dir_node->data.dir.children_len == 1);
    assert(dir_node->data.dir.children[0] == f1);
    struct evr_inode *f1_node = &inodes[f1];
    assert(f1_node->type == evr_inode_type_file);
    assert(is_str_eq(f1_node->name, "file.txt"));
    const char first_seed[] = "sha3-224-10000000000000000000000000000000000000000000000000000000-0000";
    assert(is_ok(evr_parse_claim_ref(f1_node->data.file.seed, first_seed)));
    f1_node->data.file.dependent_seeds_len = 0;
    f1_node->data.file.dependent_seeds = NULL;
    // add second file
    name = strdup("my-dir/other.txt");
    assert(name);
    fuse_ino_t f2 = evr_inode_create_file(&inodes, &inodes_len, name);
    free(name);
    assert(f2 != 0);
    assert(root->data.dir.children_len == 1);
    assert(dir_node->data.dir.children_len == 2);
    assert(dir_node->data.dir.children[0] == f1);
    assert(dir_node->data.dir.children[1] == f2);
    struct evr_inode *f2_node = &inodes[f2];
    const char second_seed[] = "sha3-224-20000000000000000000000000000000000000000000000000000000-0000";
    assert(is_ok(evr_parse_claim_ref(f2_node->data.file.seed, second_seed)));
    f2_node->data.file.dependent_seeds_len = 0;
    f2_node->data.file.dependent_seeds = NULL;
    // remove first file
    {
        evr_claim_ref seed;
        assert(is_ok(evr_parse_claim_ref(seed, first_seed)));
        evr_inode_remove_by_seed(inodes, inodes_len, seed);
    }
    assert(root->data.dir.children_len == 1);
    assert(dir_node->data.dir.children_len == 1);
    assert(dir_node->data.dir.children[0] == f2);
    // remove second file
    {
        evr_claim_ref seed;
        assert(is_ok(evr_parse_claim_ref(seed, second_seed)));
        evr_inode_remove_by_seed(inodes, inodes_len, seed);
    }
    assert(root->data.dir.children_len == 0);
    evr_free_inodes(inodes);
}

void test_grow_inode_set(){
    struct evr_inode_set s;
    assert(is_ok(evr_init_inode_set(&s)));
    const size_t initial_inode_set_len = s.inodes_len;
    char path[32];
    for(size_t i = 0; i < initial_inode_set_len + 1; ++i){
        assert(snprintf(path, sizeof(path), "%zu", i) < (int)sizeof(path));
        fuse_ino_t ino = evr_inode_set_create_file(&s, path);
        assert_msg(ino != 0, "Failed to insert node #%zu", i);
        struct evr_inode *nd = &s.inodes[ino];
        nd->data.file.dependent_seeds_len = 0;
        nd->data.file.dependent_seeds = NULL;
    }
    assert(s.inodes_len >= initial_inode_set_len);
    evr_empty_inode_set(&s);
}

void test_collect_affected_inodes(){
    evr_claim_ref p1_seed;
    assert(is_ok(evr_parse_claim_ref(p1_seed, "sha3-224-10000000000000000000000000000000000000000000000000000000-0000")));
    struct evr_inode_set s;
    assert(is_ok(evr_init_inode_set(&s)));
    fuse_ino_t p1_ino = evr_inode_set_create_file(&s, "p1");
    assert(p1_ino != 0);
    struct evr_inode *p1 = &s.inodes[p1_ino];
    memcpy(p1->data.file.seed, p1_seed, evr_claim_ref_size);
    p1->data.file.dependent_seeds_len = 0;
    p1->data.file.dependent_seeds = NULL;
    {
        struct evr_llbuf_s ai;
        evr_init_llbuf_s(&ai, sizeof(fuse_ino_t));
        assert(is_ok(evr_collect_affected_inodes(&ai, &s, p1_seed)));
        assert_msg(ai.child_count == 1, "But was %zu", ai.child_count);
        struct evr_llbuf_s_iter it;
        evr_init_llbuf_s_iter(&it, &ai);
        fuse_ino_t *ino = evr_llbuf_s_iter_next(&it);
        assert(ino);
        assert_msg(*ino == p1_ino, "%u != %u", (unsigned int)*ino, (unsigned int)p1_ino);
        evr_llbuf_s_empty(&ai, NULL);
    }
    evr_claim_ref dep_seed;
    assert(is_ok(evr_parse_claim_ref(dep_seed, "sha3-224-d0000000000000000000000000000000000000000000000000000000-0000")));
    {
        struct evr_llbuf_s ai;
        evr_init_llbuf_s(&ai, sizeof(fuse_ino_t));
        assert(is_ok(evr_collect_affected_inodes(&ai, &s, dep_seed)));
        // we expect 0 found inodes because the dep_seed is not yet
        // added to any inode.
        assert(ai.child_count == 0);
        evr_llbuf_s_empty(&ai, NULL);
    }
    // add dep_seed as dependent_seeds to p1
    p1->data.file.dependent_seeds_len = 1;
    p1->data.file.dependent_seeds = malloc(evr_claim_ref_size * p1->data.file.dependent_seeds_len);
    assert(p1->data.file.dependent_seeds);
    memcpy(&p1->data.file.dependent_seeds[0], dep_seed, evr_claim_ref_size);
    {
        struct evr_llbuf_s ai;
        evr_init_llbuf_s(&ai, sizeof(fuse_ino_t));
        assert(is_ok(evr_collect_affected_inodes(&ai, &s, dep_seed)));
        // we expect to find p1's seed because p1 references dep_seed
        assert(ai.child_count == 1);
        struct evr_llbuf_s_iter it;
        evr_init_llbuf_s_iter(&it, &ai);
        fuse_ino_t *ino = evr_llbuf_s_iter_next(&it);
        assert(*ino == p1_ino);
        evr_llbuf_s_empty(&ai, NULL);
    }
    evr_empty_inode_set(&s);
}

int main(){
    evr_init_basics();
    run_test(test_create_free_inodes);
    run_test(test_inodes_with_file);
    run_test(test_grow_inode_set);
    run_test(test_collect_affected_inodes);
    return 0;
}
