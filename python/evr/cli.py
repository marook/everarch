# everarch - the hopefully ever lasting archive
# Copyright (C) 2021-2024  Markus Peröbner
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

import subprocess

default_encoding = 'UTF-8'

def get_blob(ref):
    """get_blob is a wrapper around 'evr get' shell command.

get_blob yields the blob's content as multiple buffers.
"""
    args = ['evr', 'get', ref]
    return _evr(args)

def get_verify(ref, annotate=False):
    """get_verify is a wrapper around the 'evr get-verify' shell command.

get_verify yields the blob's content as multiple buffers.

This command is most likely being used to fetch a claim-set. You can
use ElementTree to parse the retrieved claim-set XML:

import xml.etree.ElementTree as et
doc = et.fromstringlist(evr.get_verify('sha3-224-9a974826c9b0b66aff5205db87956f398582e0209603414defa9aa39'))

    """
    args = ['evr', 'get-verify']
    if annotate:
        args.append('--annotate')
    args.append(ref)
    return _evr(args)

def get_file(claim_ref):
    """get_file is a wrapper around the 'evr get-file' shell command.

get_file yields the blob's content as multiple buffers.
    """
    return _evr(['evr', 'get-file', claim_ref])

def post_file(path, title=None):
    """post_file is a wrapper around 'evr post-file' shell command.

post_file returns the posted file's claim ref.
"""
    args = ['evr', 'post-file']
    if title is not None:
        args += ['--title', title]
    args.append(path)
    return _read_ref(_evr(args, encoding=default_encoding))

def sign_put(data, flags=None):
    """sign_put is a wrapper around 'evr sign-put' shell command.

sign_put expects data string to be the signed and put buffer. The put
blob's ref is returned.

flags are the provided blob flags. Should be an integer.
    """
    args = ['evr', 'sign-put']
    if flags is not None:
        args += ['-f', str(flags)]
    return _read_ref(_evr(args, send=data, encoding=default_encoding))

def _read_ref(lines):
    return next(lines).strip()

class ModifiedBlob(object):
    def __init__(self, ref, last_modified, watch_flags):
        # initially the ref was just provided as 'seed_ref'. the name
        # is very missleading as the blob may contain a claim that
        # references another seed. so the seed_ref property here is
        # deprecated.
        self.seed_ref = ref
        self.ref = ref
        self.last_modified = last_modified
        self.watch_flags = watch_flags

    @property
    def end_of_batch(self):
        '''end_of_batch flags if the current blob is the last one in a
        batch of blobs retrieved.

        Further blobs may follow even if this blob was the end of
        batch.
        '''
        return self.watch_flags & 0x01

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
    p = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE, encoding=default_encoding)
    try:
        for line in p.stdout:
            seed_ref, last_modified, watch_flags = line.split(' ')
            yield ModifiedBlob(seed_ref, int(last_modified), int(watch_flags))
    finally:
        p.terminate()

class SearchResult(object):
    def __init__(self, seed, attrs):
        self.seed = seed
        self.attrs = attrs

    def __str__(self):
        return f'{self.seed} {self.attrs}'

def search(query, limit=None):
    """search is a wrapper around the 'evr search' shell command.

limit is expected to be an integer.
"""
    args = [
        'evr', 'search',
    ]
    if limit is not None:
        args += ['--limit', str(limit)]
    args.append(query)
    seed = None
    attrs = []
    for line in _evr(args, encoding=default_encoding):
        if line[0] == '\t':
            if seed is None:
                raise Exception('Unexpected attribute response')
            sep = line.index('=', 1)
            key = line[1:sep]
            val = line[sep+1:-1]
            attrs.append((key, val))
        else:
            if seed is not None:
                yield SearchResult(seed, attrs)
            seed = line[:-1]
            attrs = []
    if seed is not None:
        yield SearchResult(seed, attrs)

def _evr(args, send=None, encoding=None):
    stdin = None if send is None else subprocess.PIPE
    with subprocess.Popen(args, stdin=stdin, stdout=subprocess.PIPE, encoding=encoding) as p:
        if send is not None:
            p.stdin.write(send)
            p.stdin.close()
        for chunk in p.stdout:
            yield chunk
