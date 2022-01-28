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

#ifndef __files_h__
#define __files_h__

#include "dynamic_array.h"

/**
 * read_file reads the file content at a given path.
 *
 * *buffer must point to an existing buffer. *buffer may be null if
 * read_file returns with != 0.
 */
int read_file(dynamic_array **buffer, const char *path, size_t max_size);

/**
 * read_file_str reads a file just like read_file and \0 terminates
 * the string.
 */
int read_file_str(dynamic_array **buffer, const char *path, size_t max_size);

#endif
