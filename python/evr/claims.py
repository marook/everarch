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

def parse_file_claim(claim_element):
    if claim_element.tag != '{https://evr.ma300k.de/claims/}file':
        raise InvalidClaim()
    return FileClaim(claim_element)

class FileClaim(object):
    def __init__(self, element):
        self._el = element

    @property
    def claim_ref(self):
        return self._el.attrib['claim-ref']

    @property
    def seed(self):
        return self._el.attrib['seed']

    @property
    def slices(self):
        body = self._el.find('{https://evr.ma300k.de/claims/}body')
        for child in body:
            yield FileSlice(child)

    @property
    def size(self):
        size_sum = 0
        for sl in self.slices:
            size_sum += sl.size
        return size_sum

class FileSlice(object):
    def __init__(self, element):
        self._el = element

    @property
    def size(self):
        return int(self._el.attrib['size'])

class InvalidClaim(Exception):
    '''InvalidClaim indicates that a claim parse function saw a claim
    from another type.'''
    pass
