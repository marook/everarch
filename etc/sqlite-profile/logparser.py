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
#

# logparser.py can parse evr-glacier-storage logfiles for sqlite query
# profiling information.

import datetime
import re

# matches lines like:
# 2022-08-09T20:34:36 iD db duration step_stmt 89769ns raw insert into bucket (bucket_index) values (?)
# 2022-08-09T20:34:36 D db duration step_stmt 89769ns exp insert into bucket (bucket_index) values (1)
profile_pattern = re.compile('^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}) (?:.)?D db duration step_stmt ([0-9]+)ns ([^ ]+) (.*)$')

log_date_pattern = '%Y-%m-%dT%H:%M:%S'

class Measurement(object):
    def __init__(self, timestamp, duration, profile, sql):
        self._timestamp = timestamp
        self.duration = duration
        self.profile = profile
        self.sql = sql

    @property
    def timestamp(self):
        return datetime.datetime.strptime(self._timestamp, log_date_pattern)

def parse_line(line):
    m = profile_pattern.match(line.strip())
    if not m:
        return None
    timestamp = m.group(1)
    duration = int(m.group(2))
    profile = m.group(3)
    sql = m.group(4)
    return Measurement(timestamp, duration, profile, sql)
