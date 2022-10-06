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

#ifndef fs_inode_h
#define fs_inode_h

#include "config.h"

#include <stddef.h>
#include <fuse_lowlevel.h>

#include "basics.h"
#include "keys.h"

#define evr_fs_inode_type_unlinked 0
#define evr_fs_inode_type_dir 1
#define evr_fs_inode_type_file 2

// TODO drop _fs from name
struct evr_fs_inode_dir {
    size_t children_len;
    fuse_ino_t *children;
};

// TODO drop _fs from name
struct evr_fs_inode_file {
    size_t file_size;
    evr_claim_ref file_ref;
    evr_claim_ref seed;
};

// TODO drop _fs from name
union evr_fs_inode_data {
    struct evr_fs_inode_dir dir;
    struct evr_fs_inode_file file;
};

// TODO drop _fs from name
struct evr_fs_inode {
    fuse_ino_t parent;
    char *name;
    evr_time created;
    evr_time last_modified;
    int type;
    union evr_fs_inode_data data;
};

struct evr_fs_inode *evr_create_inodes(size_t inodes_len);

void evr_free_inodes(struct evr_fs_inode *inodes);

/**
 * evr_inode_remove_by_seed calls evr_inode_remove on every inode with
 * the given seed.
 */
void evr_inode_remove_by_seed(struct evr_fs_inode *inodes, size_t inodes_len, evr_claim_ref seed);

/**
 * evr_inode_create_file creates a file inode and all missing parent
 * directory inodes.
 *
 * Returns 0 on error. Otherwise the created inode.
 */
fuse_ino_t evr_inode_create_file(struct evr_fs_inode **inodes, size_t *inodes_len, char *file_path);

/**
 * evr_inode_remove removes the inode n and all parent inodes which
 * become childless except the root inode 1.
 */
void evr_inode_remove(struct evr_fs_inode *inodes, fuse_ino_t n);

struct evr_inode_set {
    struct evr_fs_inode *inodes;
    size_t inodes_len;
};

int evr_init_inode_set(struct evr_inode_set *s);

#define evr_empty_inode_set(s) evr_free_inodes((s)->inodes)

/**
 * evr_inode_set_create_file creates a file inode and all missing
 * parent directory inodes.
 *
 * Returns 0 on error. Otherwise the created inode.
 */
#define evr_inode_set_create_file(s, file_path) evr_inode_create_file(&(s)->inodes, &(s)->inodes_len, file_path)

#endif
