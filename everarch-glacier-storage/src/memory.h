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
 *
 *
 * The names L1_CACHE_BYTES, SMP_CACHE_BYTES and ____cacheline_aligned
 * are taken from various cache.h files from the linux kernel source.
 */

#ifndef __memory_h__
#define __memory_h__

/**
 * L1_CACHE_BYTES is the size of the CPU's cache line in bytes.
 *
 * Can be determined using:
 * 
 * $ grep cache_alignment /proc/cpuinfo
 */
#define L1_CACHE_BYTES	64

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

#endif
