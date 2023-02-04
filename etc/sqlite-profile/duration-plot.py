#!/usr/bin/env python3
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

# duration-plot.py parses evr-glacier-storage and evr-attr-index log
# output, aggregates the sqlite profiling output and plots it.
#
# Usage
# $ ./duration-plot 'a sql regexp pattern' < evr-glacier-storage.log

import datetime
import matplotlib.pyplot as plt
import re
import sys

import logparser

sql_pattern = re.compile(sys.argv[1])

aggregations_by_hour = {}

aggregation_key_date_pattern = '%Y%m%d%H'

class Aggregation(object):
    def __init__(self):
        self.duration_min = None
        self.duration_max = None
        self.duration_sum = 0
        self.count = 0

    @property
    def duration_avg(self):
        return self.duration_sum / self.count if self.count > 0 else None

    def __str__(self):
        avg = self.duration_avg
        avg_str = '-' if avg is None else f'{avg}ns'
        return f'{self.duration_min}ns-{self.duration_max}ns {avg_str} ({self.count})'

for line in sys.stdin:
    m = logparser.parse_line(line)
    if m is None:
        continue
    if not sql_pattern.match(m.sql):
        continue
    key = m.timestamp.strftime(aggregation_key_date_pattern)
    if key in aggregations_by_hour:
        agg = aggregations_by_hour[key]
    else:
        agg = Aggregation()
        aggregations_by_hour[key] = agg
    d = m.duration
    if agg.duration_min is None or d < agg.duration_min:
        agg.duration_min = d
    if agg.duration_max is None or d > agg.duration_max:
        agg.duration_max = d
    agg.duration_sum += d
    agg.count += 1

min_key = None
max_key = None
for key in aggregations_by_hour.keys():
    if min_key is None or key < min_key:
        min_key = key
    if max_key is None or key > max_key:
        max_key = key

t_min = datetime.datetime.strptime(min_key, aggregation_key_date_pattern)
t_max = datetime.datetime.strptime(max_key, aggregation_key_date_pattern)

x = []
y_avg = []
y_min = []
y_max = []

t = t_min
while t <= t_max:
    key = t.strftime(aggregation_key_date_pattern)
    if key in aggregations_by_hour:
        agg = aggregations_by_hour[key]
    else:
        agg = Aggregation()
    x.append(t)
    y_avg.append(agg.duration_avg)
    y_min.append(agg.duration_min)
    y_max.append(agg.duration_max)
    t += datetime.timedelta(hours=1)

plt.plot_date(x, y_avg, fmt='k-o', label='avg (ns)')
plt.plot_date(x, y_min, fmt='b--o', label='min (ns)')
plt.plot_date(x, y_max, fmt='r--o', label='max (ns)')
plt.tick_params(axis='x', which='major', labelsize=6)
plt.tight_layout()
plt.legend()
plt.yscale('log')
plt.show()
