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

tls_key='/data/evr-attr-index-key.pem'
tls_cert='/pub/evr-attr-index-cert.pem'

prepare_gpg_key 'evr-attr-index'

if [ ! -e '/data/evr.conf' ]
then
    echo -n '' > '/data/evr.conf.tmp'

    echo "Configure glacier..."
    if [ -z "${EVR_GLACIER_STORAGE_HOST}" ]
    then
        echo "evr-glacier-storage hostname must be provided via environment variable EVR_GLACIER_STORAGE_HOST"
        exit 1
    fi
    echo "storage-host=${EVR_GLACIER_STORAGE_HOST}" >> '/data/evr.conf.tmp'
    echo "ssl-cert=${EVR_GLACIER_STORAGE_HOST}:2361:/pub/evr-glacier-storage-cert.pem" >> '/data/evr.conf.tmp'
    echo "Waiting for glacier auth-token..."
    wait_for_file "/pub/evr-glacier-auth-token"
    storage_auth_token=`cat "/pub/evr-glacier-auth-token"`
    echo "auth-token=${EVR_GLACIER_STORAGE_HOST}:2361:${storage_auth_token}" >> '/data/evr.conf.tmp'

    for fpr in `gpg --list-public-keys --with-colons | grep '^fpr:.*$' | sed 's/fpr:[:]*\([^:]*\):[:]*/\1/'`
    do
        echo "accepted-gpg-key=${fpr}" >> '/data/evr.conf.tmp'
    done

    for fpr in `gpg --list-secret-keys --with-colons | grep '^fpr:.*$' | sed 's/fpr:[:]*\([^:]*\):[:]*/\1/'`
    do
        # take the first secret key we find for signing
        echo "signing-gpg-key=${fpr}" >> '/data/evr.conf.tmp'
        break
    done

    mv '/data/evr.conf.tmp' '/data/evr.conf'
fi

if [ ! -e '/data/evr-attr-index.conf' ]
then
    echo 'host=0.0.0.0' > '/data/evr-attr-index.conf.tmp'

    if [ ! -e "${tls_key}" ]
    then
        echo "Creating TLS certificate pair..."
        mkdir -p `dirname "${tls_key}"`
        openssl genrsa -out "${tls_key}" 4096
        openssl req -new -key "${tls_key}" -out '/opt/evr/cert.csr' -config '/opt/evr/cert.conf'
        openssl x509 -req -days 3650 -in '/opt/evr/cert.csr' -signkey "${tls_key}" -out "${tls_cert}"
        rm '/opt/evr/cert.csr'
    fi
    echo "key=${tls_key}" >> '/data/evr-attr-index.conf.tmp'
    echo "cert=${tls_cert}" >> '/data/evr-attr-index.conf.tmp'

    if [ ! -e "/pub/evr-attr-index-auth-token" ]
    then
        echo "Generating auth-token..."
        openssl rand -hex 32 > "/pub/evr-attr-index-auth-token.tmp"
        mv "/pub/evr-attr-index-auth-token.tmp" "/pub/evr-attr-index-auth-token"
        chmod a-w "/pub/evr-attr-index-auth-token"
    fi
    auth_token=`cat "/pub/evr-attr-index-auth-token"`
    echo "auth-token=${auth_token}" >> '/data/evr-attr-index.conf.tmp'

    echo "Configure glacier..."
    if [ -z "${EVR_GLACIER_STORAGE_HOST}" ]
    then
        echo "evr-glacier-storage hostname must be provided via environment variable EVR_GLACIER_STORAGE_HOST"
        exit 1
    fi
    echo "storage-host=${EVR_GLACIER_STORAGE_HOST}" >> '/data/evr-attr-index.conf.tmp'
    echo "ssl-cert=${EVR_GLACIER_STORAGE_HOST}:2361:/pub/evr-glacier-storage-cert.pem" >> '/data/evr-attr-index.conf.tmp'
    echo "Waiting for glacier auth-token..."
    wait_for_file "/pub/evr-glacier-auth-token"
    storage_auth_token=`cat "/pub/evr-glacier-auth-token"`
    echo "storage-auth-token=${storage_auth_token}" >> '/data/evr-attr-index.conf.tmp'

    if [ "${EVR_WITH_UPLOAD_HTTPD}" == '1' ]
    then
        echo "Importing upload httpd GPG keys..."
        wait_for_file "/pub/evr-upload-httpd-identity.pub.gpg"
        gpg --import "/pub/evr-upload-httpd-identity.pub.gpg"
    fi

    if [ "${EVR_WITH_WEBSOCKET_SERVER}" == '1' ]
    then
        echo "Importing websocket server GPG keys..."
        wait_for_file "/pub/evr-websocket-server-identity.pub.gpg"
        gpg --import "/pub/evr-websocket-server-identity.pub.gpg"
    fi

    if [ "${EVR_WITH_UPLOAD_HTTPD}" == '1' -o "${EVR_WITH_WEBSOCKET_SERVER}" == '1' ]
    then
        for fpr in `gpg --list-public-keys --with-colons | grep '^fpr:.*$' | sed 's/fpr:[:]*\([^:]*\):[:]*/\1/'`
        do
            echo "${fpr}:6:" | gpg --import-ownertrust
            echo "accepted-gpg-key=${fpr}" >> '/data/evr-attr-index.conf.tmp'
        done
    fi

    echo "Preparing state directory..."
    mkdir -p '/data/evr-attr-index'
    echo "state-dir=/data/evr-attr-index" >> '/data/evr-attr-index.conf.tmp'

    mv '/data/evr-attr-index.conf.tmp' '/data/evr-attr-index.conf'
fi

export PATH="/opt/evr/bin:${ORIG_PATH}"
cd /data
/opt/evr/attr-spec/install_attr_spec
exec /opt/evr/evr-attr-index -f
