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
    struct evr_fs_inode *inodes = evr_create_inodes(100);
    assert(inodes);
    struct evr_fs_inode *root = &inodes[FUSE_ROOT_ID];
    assert(root->type == evr_fs_inode_type_dir);
    assert(root->data.dir.children_len == 0);
    assert(inodes[FUSE_ROOT_ID + 1].type == evr_fs_inode_type_unlinked);
    evr_free_inodes(inodes);
}

void test_inodes_with_file(){
    size_t inodes_len = 100;
    struct evr_fs_inode *inodes = evr_create_inodes(inodes_len);
    assert(inodes);
    // add first file
    char *name = strdup("my-dir/file.txt");
    assert(name);
    fuse_ino_t f1 = evr_inode_create_file(&inodes, &inodes_len, name);
    free(name);
    assert(f1 != 0);
    struct evr_fs_inode *root = &inodes[FUSE_ROOT_ID];
    assert(root->data.dir.children_len == 1);
    fuse_ino_t dir = root->data.dir.children[0];
    assert(dir != 0);
    struct evr_fs_inode *dir_node = &inodes[dir];
    assert(dir_node->type == evr_fs_inode_type_dir);
    assert(is_str_eq(dir_node->name, "my-dir"));
    assert(dir_node->data.dir.children_len == 1);
    assert(dir_node->data.dir.children[0] == f1);
    struct evr_fs_inode *file_node = &inodes[f1];
    assert(file_node->type == evr_fs_inode_type_file);
    assert(is_str_eq(file_node->name, "file.txt"));
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
    evr_free_inodes(inodes);
}

void test_grow_inode_set(){
    struct evr_inode_set s;
    assert(is_ok(evr_init_inode_set(&s)));
    const size_t initial_inode_set_len = s.inodes_len;
    char path[32];
    for(size_t i = 0; i < initial_inode_set_len + 1; ++i){
        assert(snprintf(path, sizeof(path), "%zu", i) < sizeof(path));
        assert_msg(evr_inode_set_create_file(&s, path) != 0, "Failed to insert node #%zu", i);
    }
    assert(s.inodes_len >= initial_inode_set_len);
    evr_empty_inode_set(&s);
}

int main(){
    evr_init_basics();
    run_test(test_create_free_inodes);
    run_test(test_inodes_with_file);
    run_test(test_grow_inode_set);
    return 0;
}
