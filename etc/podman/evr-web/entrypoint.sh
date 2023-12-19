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

if [ ! -e '/data/evr-upload-httpd.conf' ]
then
    echo 'host=0.0.0.0' > '/data/evr-upload-httpd.conf.tmp'

    if [ ! -e "/pub/evr-upload-httpd-auth-token" ]
    then
        echo "Generating auth-token..."
        openssl rand -hex 32 > "/pub/evr-upload-httpd-auth-token.tmp"
        mv "/pub/evr-upload-httpd-auth-token.tmp" "/pub/evr-upload-httpd-auth-token"
        chmod a-w "/pub/evr-upload-httpd-auth-token"
    fi
    auth_token=`cat "/pub/evr-upload-httpd-auth-token"`
    echo "auth-token=${auth_token}" >> '/data/evr-upload-httpd.conf.tmp'
    
    mv '/data/evr-upload-httpd.conf.tmp' '/data/evr-upload-httpd.conf'
fi

if [ -e "/data/evr-upload-httpd-identity.sec.gpg" ]
then
    echo "Importing upload httpd GPG keys..."
    gpg --import "/pub/evr-upload-httpd-identity.pub.gpg"
    gpg --import "/data/evr-upload-httpd-identity.sec.gpg"
    gpg --import-ownertrust < '/data/evr-upload-httpd-ownertrust.sec.txt'
else
    echo "Generating upload httpd GPG key..."
    gpg --quick-gen-key --batch --passphrase '' 'evr-upload-httpd@example.org' 'default' 'default' '3650d'
    gpg --export --output "/pub/evr-upload-httpd-identity.pub.gpg"
    gpg --export-secret-keys --output "/data/evr-upload-httpd-identity.sec.gpg"
    gpg --export-ownertrust > '/data/evr-upload-httpd-ownertrust.sec.txt'
fi

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

cd /data
export PATH="/opt/evr/bin:${ORIG_PATH}"
exec /opt/evr/evr-upload-httpd -f
