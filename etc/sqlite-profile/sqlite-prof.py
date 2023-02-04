#!/usr/bin/python3
#
# everarch - the hopefully ever lasting archive
# Copyright (C) 2023  Markus Peröbner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# sqlite-prof.py scans evr-glacier-storage and evr-attr-index log
# output for sqlite profiling information. These profiling information
# is aggregated and reported to stdout.
#
# Check out the --enable-profile-sql-statements option to the
# configure script.

import sys

import logparser

raw_stmt_sum = {}
exp_stmt_max = {}

for line in sys.stdin:
    m = logparser.parse_line(line)
    if m is None:
        continue
    if m.profile == 'raw':
        c, s = raw_stmt_sum[m.sql] if m.sql in raw_stmt_sum else (0, 0)
        raw_stmt_sum[m.sql] = (c + 1, s + m.duration)
    elif m.profile == 'exp':
        mx = exp_stmt_max[m.sql] if m.sql in exp_stmt_max else 0
        if m.duration > mx:
            exp_stmt_max[m.sql] = m.duration

def print_stmt_durations(stmts_dict):
    for sql, duration in sorted(stmts_dict.items(), key=lambda i: -i[1])[:20]:
        print(f'{duration}ns: {sql}')

print('raw duration sum:')
for sql, dur in sorted(raw_stmt_sum.items(), key=lambda i: -i[1][1] / i[1][0]):
    c, s = dur
    print(f'{round(s/c)}ns {s}ns {c}: {sql}')

print('\nexp duration max:')
for sql, duration in sorted(exp_stmt_max.items(), key=lambda i: -i[1])[:20]:
    print(f'{duration}ns: {sql}')
