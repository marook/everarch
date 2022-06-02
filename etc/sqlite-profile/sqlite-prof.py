#!/usr/bin/python3
#
# sqlite-prof.py scans evr-glacier-storage and evr-attr-index log
# output for sqlite profiling information. These profiling information
# is aggregated and reported to stdout.
#
# Check out the --enable-profile-sql-statements option to the
# configure script.
#
import re
import sys

# matches lines like:
# 2022-06-02T15:35:42 iD sqlite statement duration exp 1822328ns: select rowid, val_str, valid_until, trunc from attr where seed = x'4fd0082672bdc4c4b6e63db7d9774ca07b0a69923c9609a3863182e00000' and key = 'charset' and valid_from <= 1654167365093 order by valid_from desc
profile_pattern = re.compile('^[^ ]+ .D sqlite statement duration ([^ ]+) ([0-9]+)ns: (.*)$')

raw_stmt_sum = {}
exp_stmt_max = {}

for line in sys.stdin:
    m = profile_pattern.match(line.strip())
    if not m:
        continue
    profile = m.group(1)
    duration = int(m.group(2))
    sql = m.group(3)
    if profile == 'raw':
        c, s = raw_stmt_sum[sql] if sql in raw_stmt_sum else (0, 0)
        raw_stmt_sum[sql] = (c + 1, s + duration)
    elif profile == 'exp':
        m = exp_stmt_max[sql] if sql in exp_stmt_max else 0
        if duration > m:
            exp_stmt_max[sql] = duration

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
