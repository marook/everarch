#!/usr/bin/python3
#
# profile-aggregate.py scans evr-glacier-storage and evr-attr-index
# log output for profiling information. These profiling information is
# aggregated and reported to stdout.
#
# Check out the --enable-profile-sql-statements and
# --enable-profile-glacier options to the configure script.
#
import re
import sys

# matches lines like:
# 2022-08-09T20:34:36 iD db duration step_stmt 89769ns raw insert into bucket (bucket_index) values (?)
# 2022-08-09T20:34:36 D db duration step_stmt 89769ns exp insert into bucket (bucket_index) values (1)
profile_pattern = re.compile('^[^ ]+ (?:.)?D (.+) ([0-9]+)ns(?:.*)$')

def format_ns(ns):
    if ns > 5 * 1000000:
        return f'{round(ns / 1000000)}ms'
    return f'{round(ns)}ns'

class Probe(object):
    def __init__(self):
        self.duration_sum = 0
        self.duration_count = 0
        self.duration_max = 0

    @property
    def avg(self):
        return self.duration_sum / self.duration_count

    def __str__(self):
        return f'avg {format_ns(self.avg)} max {format_ns(self.duration_max)} count {self.duration_count}'

probes = {}

for line in sys.stdin:
    m = profile_pattern.match(line.strip())
    if not m:
        continue
    probe_name = m.group(1)
    duration = int(m.group(2))
    if probe_name in probes:
        probe = probes[probe_name]
    else:
        probe = Probe()
        probes[probe_name] = probe
    probe.duration_sum += duration
    probe.duration_count += 1
    if duration > probe.duration_max:
        probe.duration_max = duration

for probe_name, probe in sorted(probes.items(), key=lambda i: i[0]):
    print(f'{probe_name} {probe}')
