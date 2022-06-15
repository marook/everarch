# everarch - the hopefully ever lasting archive
# Copyright (C) 2021-2022  Markus Peröbner
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
# evr.py is a wrapper around the evr command line interface for more
# python convenience.
#
# Provided functions you might care about are get_blob, get_verify and
# watch.

import subprocess

def get_blob(ref):
    """get_blob is a wrapper around 'evr get' shell command.

get_blob yields the blob's content as multiple buffers.
"""
    args = ['evr', 'get', ref]
    return _evr(args)

def get_verify(ref):
    """get_verify is a wrapper around 'evr get-verify' shell command.

get_verify yields the blob's content as multiple buffers.

This command is most likely being used to fetch a claim-set. You can
use ElementTree to parse the retrieved claim-set XML:

import xml.etree.ElementTree as et
doc = et.fromstringlist(evr.get_verify('sha3-224-9a974826c9b0b66aff5205db87956f398582e0209603414defa9aa39'))

    """
    args = ['evr', 'get-verify', ref]
    return _evr(args)

class ModifiedBlob(object):
    def __init__(self, seed_ref, last_modified, watch_flags):
        self.seed_ref = seed_ref
        self.last_modified = last_modified
        self.watch_flags = watch_flags

    def __str__(self):
        return f'{self.seed_ref} {self.last_modified} {self.watch_flags}'

def watch(flags=0, last_modified_after=None, blobs_sort_order=None):
    """watch is a wrapper around the 'evr watch' shell command.

watch yields ModifiedBlob objects and will only terminate on errors.

flags and last_modified_after are expected to be integers.
"""
    args = [
        'evr', 'watch',
        '--flags-filter', str(flags),
    ]
    if last_modified_after is not None:
        args += ['--last-modified-after', str(last_modified_after)]
    if blobs_sort_order is not None:
        args += ['--blobs-sort-order', blobs_sort_order]
    for line in _evr(args, encoding='UTF-8'):
        seed_ref, last_modified, watch_flags = line.split(' ')
        yield ModifiedBlob(seed_ref, int(last_modified), int(watch_flags))

def _evr(args, encoding=None):
    with subprocess.Popen(args, stdout=subprocess.PIPE, encoding=encoding) as p:
        for chunk in p.stdout:
            yield chunk
