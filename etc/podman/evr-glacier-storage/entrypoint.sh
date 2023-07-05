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

tls_key='/data/evr-glacier-storage-key.pem'
tls_cert='/pub/evr-glacier-storage-cert.pem'

if [ ! -e '/data/evr-glacier-storage.conf' ]
then
    echo 'host=0.0.0.0' > '/data/evr-glacier-storage.conf'
fi

if [ ! -e "${tls_key}" ]
then
    echo "Creating TLS certificate pair..."
    mkdir -p `dirname "${tls_key}"`
    openssl genrsa -out "${tls_key}" 4096
    openssl req -new -key "${tls_key}" -out '/opt/cert.csr' -config '/opt/cert.conf'
    openssl x509 -req -days 3650 -in '/opt/cert.csr' -signkey "${tls_key}" -out "${tls_cert}"
    rm '/opt/cert.csr'
    echo "key=${tls_key}" >> '/data/evr-glacier-storage.conf'
    echo "cert=${tls_cert}" >> '/data/evr-glacier-storage.conf'
fi

if [ ! -e "/pub/auth-token" ]
then
    echo "Generating auth-token..."
    openssl rand -hex 32 > "/pub/auth-token"
    chmod a-w "/pub/auth-token"
    auth_token=`cat "/pub/auth-token"`
    echo "auth-token=${auth_token}" >> '/data/evr-glacier-storage.conf'
fi

if [ ! -e '/data/buckets' ]
then
    echo "Preparing buckets directory..."
    mkdir '/data/buckets'
    echo "bucket-dir=/data/buckets" >> '/data/evr-glacier-storage.conf'
fi

cat '/data/evr-glacier-storage.conf'

cd /data
exec /opt/evr-glacier-storage -f
