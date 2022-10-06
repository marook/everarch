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

#include "fs-inode.h"

#include "basics.h"
#include "keys.h"
#include "logger.h"
#include "errors.h"

struct evr_fs_inode *evr_create_inodes(size_t inodes_len){
    if(inodes_len <= FUSE_ROOT_ID){
        evr_panic("inodes_len must be greater than %u", FUSE_ROOT_ID);
        return NULL;
    }
    struct evr_fs_inode *inodes = malloc(sizeof(struct evr_fs_inode) * inodes_len);
    if(!inodes){
        return NULL;
    }
    struct evr_fs_inode *root = &inodes[FUSE_ROOT_ID];
    root->parent = FUSE_ROOT_ID;
    root->name = NULL;
    evr_now(&root->created);
    root->last_modified = root->created;
    root->type = evr_fs_inode_type_dir;
    root->data.dir.children_len = 0;
    root->data.dir.children = NULL;
    for(fuse_ino_t n = FUSE_ROOT_ID + 1; n < inodes_len; ++n){
        inodes[n].type = evr_fs_inode_type_unlinked;
    }
    return inodes;
}


void evr_free_inode_and_children(struct evr_fs_inode *inodes, fuse_ino_t n);

void evr_free_inodes(struct evr_fs_inode *inodes){
    if(inodes){
        evr_free_inode_and_children(inodes, FUSE_ROOT_ID);
        free(inodes);
    }
}

void evr_free_inode_and_children(struct evr_fs_inode *inodes, fuse_ino_t n){
    struct evr_fs_inode *nd = &inodes[n];
    switch(nd->type){
    default:
        evr_panic("Unknown inode type %d discovered", nd->type);
        break;
    case evr_fs_inode_type_dir:
        for(size_t i = 0; i < nd->data.dir.children_len; ++i){
            evr_free_inode_and_children(inodes, nd->data.dir.children[i]);
        }
        free(nd->data.dir.children);
        break;
    case evr_fs_inode_type_file:
        break;
    }
    free(nd->name);
    nd->type = evr_fs_inode_type_unlinked;
}

void evr_inode_remove_by_seed(struct evr_fs_inode *inodes, size_t inodes_len, evr_claim_ref seed){
    struct evr_fs_inode *it;
    for(fuse_ino_t n = FUSE_ROOT_ID + 1; n < inodes_len; ++n){
        it = &inodes[n];
        if(it->type != evr_fs_inode_type_file){
            continue;
        }
        if(evr_cmp_claim_ref(seed, it->data.file.seed) != 0){
            continue;
        }
        evr_inode_remove(inodes, n);
    }
}

fuse_ino_t evr_inode_append_dir(struct evr_fs_inode **inodes, size_t *inodes_len, fuse_ino_t parent, char *name);

fuse_ino_t evr_inode_append_file(struct evr_fs_inode **inodes, size_t *inodes_len, fuse_ino_t parent, char *name);

fuse_ino_t evr_inode_create_file(struct evr_fs_inode **inodes, size_t *inodes_len, char *file_path){
    char *name = file_path;
    char *p_it = name;
    fuse_ino_t n = FUSE_ROOT_ID;
    while(1){
        // TODO add support for escaped paths. for example "my\/file.txt"
        if(*p_it == '/'){
            *p_it = '\0';
            int res = evr_inode_append_dir(inodes, inodes_len, n, name);
            *p_it = '/';
            if(res == 0){
                return 0;
            }
            n = res;
            name = p_it + 1;
        } else if (*p_it == '\0'){
            int res = evr_inode_append_file(inodes, inodes_len, n, name);
            if(res == 0){
                return 0;
            }
            return res;
        }
        ++p_it;
    }
}

fuse_ino_t evr_inode_get_available(struct evr_fs_inode **inodes, size_t *inodes_len);

int evr_inode_add_child(struct evr_fs_inode *inodes, fuse_ino_t parent, fuse_ino_t child);

fuse_ino_t evr_inode_append_dir(struct evr_fs_inode **inodes, size_t *inodes_len, fuse_ino_t parent, char *name){
    fuse_ino_t n = evr_inode_get_available(inodes, inodes_len);
    if(n == 0){
        return 0;
    }
    if(evr_inode_add_child(*inodes, parent, n) != evr_ok){
        return 0;
    }
    struct evr_fs_inode *nd = &(*inodes)[n];
    nd->parent = parent;
    nd->name = strdup(name);
    if(!nd->name){
        return 0;
    }
    nd->type = evr_fs_inode_type_dir;
    nd->data.dir.children_len = 0;
    nd->data.dir.children = NULL;
    return n;
}

fuse_ino_t evr_inode_append_file(struct evr_fs_inode **inodes, size_t *inodes_len, fuse_ino_t parent, char *name){
    fuse_ino_t n = evr_inode_get_available(inodes, inodes_len);
    if(n == 0){
        return 0;
    }
    if(evr_inode_add_child(*inodes, parent, n) != evr_ok){
        return 0;
    }
    struct evr_fs_inode *nd = &(*inodes)[n];
    nd->parent = parent;
    nd->name = strdup(name);
    if(!nd->name){
        return 0;
    }
    nd->type = evr_fs_inode_type_file;
    return n;
}

fuse_ino_t evr_inode_get_available(struct evr_fs_inode **inodes, size_t *inodes_len){
    for(fuse_ino_t n = FUSE_ROOT_ID + 1; n < *inodes_len; ++n){
        if((*inodes)[n].type == evr_fs_inode_type_unlinked){
            return n;
        }
    }
    const size_t old_inodes_len = *inodes_len;
    size_t new_inodes_len = *inodes_len * 2;
    struct evr_fs_inode *new_inodes = realloc(*inodes, sizeof(struct evr_fs_inode) * new_inodes_len);
    if(!new_inodes){
        return 0;
    }
    for(fuse_ino_t n = old_inodes_len; n < new_inodes_len; ++n){
        (*inodes)[n].type = evr_fs_inode_type_unlinked;
    }
    *inodes = new_inodes;
    *inodes_len = new_inodes_len;
    return old_inodes_len;
}

int evr_inode_add_child(struct evr_fs_inode *inodes, fuse_ino_t parent, fuse_ino_t child){
    struct evr_fs_inode *nd = &inodes[parent];
    fuse_ino_t *new_children = realloc(nd->data.dir.children, sizeof(fuse_ino_t) * (nd->data.dir.children_len + 1));
    if(!new_children){
        return evr_error;
    }
    new_children[nd->data.dir.children_len] = child;
    nd->data.dir.children = new_children;
    ++nd->data.dir.children_len;
    return evr_ok;
}

void evr_inode_remove(struct evr_fs_inode *inodes, fuse_ino_t n){
    if(n == FUSE_ROOT_ID){
        // the root node will always stay even if empty
        return;
    }
    evr_free_inode_and_children(inodes, n);
    fuse_ino_t p = inodes[n].parent;
    struct evr_fs_inode *np = &inodes[p];
    for(size_t i = 0; i < np->data.dir.children_len - 1; ++i){
        if(np->data.dir.children[i] == n){
            np->data.dir.children[i] = np->data.dir.children[np->data.dir.children_len];
        }
    }
    if(np->data.dir.children_len <= 1){
        np->data.dir.children_len = 0;
        free(np->data.dir.children);
        np->data.dir.children = NULL;
        evr_inode_remove(inodes, p);
    } else {
        np->data.dir.children_len -= 1;
        np->data.dir.children = realloc(np->data.dir.children, sizeof(fuse_ino_t) * np->data.dir.children_len);
        if(!np->data.dir.children){
            evr_panic("Shrinking dir inode children array not possible.");
        }
    }
}

int evr_init_inode_set(struct evr_inode_set *s){
    const size_t inodes_len = 1024;
    struct evr_fs_inode *ino = evr_create_inodes(inodes_len);
    if(!ino){
        return evr_error;
    }
    s->inodes_len = inodes_len;
    s->inodes = ino;
    return evr_ok;
}
