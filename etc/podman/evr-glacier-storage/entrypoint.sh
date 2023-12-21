#!/bin/sh
#
# everarch - the hopefully ever lasting archive
# Copyright (C) 2021-2023  Markus Peröbner
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
set -e

ORIG_PATH="${PATH}"
PATH="/opt/evr/entrypoint:${PATH}"

prepare_tls_cert 'evr-glacier-storage'

if [ ! -e '/data/evr-glacier-storage.conf' ]
then
    echo 'host=0.0.0.0' > '/data/evr-glacier-storage.conf.tmp'

    echo "key=/data/evr-glacier-storage-key.pem" >> '/data/evr-glacier-storage.conf.tmp'
    echo "cert=/pub/evr-glacier-storage-cert.pem" >> '/data/evr-glacier-storage.conf.tmp'

    prepare_auth_token 'evr-glacier-storage'
    auth_token=`cat "/pub/evr-glacier-storage-auth-token"`
    echo "auth-token=${auth_token}" >> '/data/evr-glacier-storage.conf.tmp'

    echo "Preparing buckets directory..."
    mkdir -p '/data/buckets'
    echo "bucket-dir=/data/buckets" >> '/data/evr-glacier-storage.conf.tmp'

    mv '/data/evr-glacier-storage.conf.tmp' '/data/evr-glacier-storage.conf'
fi

export PATH="/opt/evr/bin:${ORIG_PATH}"
cd /data
exec /opt/evr/evr-glacier-storage -f
