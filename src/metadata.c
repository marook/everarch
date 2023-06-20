/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
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

#include "metadata.h"

#include <fcntl.h>

#include "errors.h"

int evr_meta_open(struct evr_file *meta, char *path){
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 00600);
    if(fd < 0){
        return evr_error;
    }
    evr_file_bind_fd(meta, fd);
    return evr_ok;
}

static char *evr_meta_key_labels[] = {
    "signed-by",
};

int evr_meta_write_str(struct evr_file *meta, int meta_key, char *value){
    if(!meta){
        return evr_ok;
    }
    if(!value){
        value = "";
    }
    char *key_label = evr_meta_key_labels[meta_key];
    size_t key_len = strlen(key_label);
    size_t value_len = strlen(value);
    char buf[key_len + 1 + value_len + 1];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    evr_push_n(&bp, key_label, key_len);
    evr_push_n(&bp, "=", 1);
    evr_push_n(&bp, value, value_len);
    evr_push_n(&bp, "\n", 1);
    return write_n(meta, buf, sizeof(buf));
}
