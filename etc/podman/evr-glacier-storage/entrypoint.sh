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
    echo 'host=0.0.0.0' > '/data/evr-glacier-storage.conf.tmp'

    if [ ! -e "${tls_key}" ]
    then
        echo "Creating TLS certificate pair..."
        mkdir -p `dirname "${tls_key}"`
        openssl genrsa -out "${tls_key}" 4096
        openssl req -new -key "${tls_key}" -out '/opt/evr/cert.csr' -config '/opt/evr/cert.conf'
        openssl x509 -req -days 3650 -in '/opt/evr/cert.csr' -signkey "${tls_key}" -out "${tls_cert}"
        rm '/opt/evr/cert.csr'
    fi
    echo "key=${tls_key}" >> '/data/evr-glacier-storage.conf.tmp'
    echo "cert=${tls_cert}" >> '/data/evr-glacier-storage.conf.tmp'
    
    if [ ! -e "/pub/evr-glacier-auth-token" ]
    then
        echo "Generating auth-token..."
        openssl rand -hex 32 > "/pub/evr-glacier-auth-token.tmp"
        mv "/pub/evr-glacier-auth-token.tmp" "/pub/evr-glacier-auth-token"
        chmod a-w "/pub/evr-glacier-auth-token"
    fi
    auth_token=`cat "/pub/evr-glacier-auth-token"`
    echo "auth-token=${auth_token}" >> '/data/evr-glacier-storage.conf.tmp'

    echo "Preparing buckets directory..."
    mkdir -p '/data/buckets'
    echo "bucket-dir=/data/buckets" >> '/data/evr-glacier-storage.conf.tmp'

    mv '/data/evr-glacier-storage.conf.tmp' '/data/evr-glacier-storage.conf'
fi

cd /data
exec /opt/evr/evr-glacier-storage -f
