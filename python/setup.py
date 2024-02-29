#!/usr/bin/env python3
#
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

from distutils.core import setup

setup(name='evr',
      version='0.1.0',
      description='Python wrapper around the evr cli application.',
      author='Markus Peröbner',
      author_email='markus.peroebner@gmail.com',
      url='https://github.com/marook/everarch',
      license='AGPL-3.0',
      packages=['evr'],
      install_requires=[],
      classifiers=[],
)
