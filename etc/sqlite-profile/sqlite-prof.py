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
# 2022-08-09T20:34:36 iD db duration step_stmt 89769ns raw insert into bucket (bucket_index) values (?)
# 2022-08-09T20:34:36 D db duration step_stmt 89769ns exp insert into bucket (bucket_index) values (1)
profile_pattern = re.compile('^[^ ]+ (?:.)?D db duration step_stmt ([0-9]+)ns ([^ ]+) (.*)$')

raw_stmt_sum = {}
exp_stmt_max = {}

for line in sys.stdin:
    m = profile_pattern.match(line.strip())
    if not m:
        continue
    duration = int(m.group(1))
    profile = m.group(2)
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
