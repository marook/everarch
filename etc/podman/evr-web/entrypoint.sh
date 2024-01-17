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

mkdir -p /var/cache/nginx/.gnupg
chmod go= /var/cache/nginx/.gnupg
chown nginx:nginx /var/cache/nginx/.gnupg

if [ "${EVR_WITH_UPLOAD_HTTPD}" == '1' ]
then
    echo "Importing upload httpd GPG keys..."
    wait_for_file "/pub/evr-upload-httpd-identity.pub.gpg"
    runuser -u nginx -- gpg --import "/pub/evr-upload-httpd-identity.pub.gpg"
fi

if [ "${EVR_WITH_WEBSOCKET_SERVER}" == '1' ]
then
    echo "Importing websocket server GPG keys..."
    wait_for_file "/pub/evr-websocket-server-identity.pub.gpg"
    runuser -u nginx -- gpg --import "/pub/evr-websocket-server-identity.pub.gpg"
fi

if [ "${EVR_WITH_ATTR_INDEX}" == '1' ]
then
    echo "Importing attr index GPG keys..."
    wait_for_file "/pub/evr-attr-index-identity.pub.gpg"
    runuser -u nginx -- gpg --import "/pub/evr-attr-index-identity.pub.gpg"
fi

if [ "${EVR_WITH_UPLOAD_HTTPD}" == '1' -o "${EVR_WITH_WEBSOCKET_SERVER}" == '1' -o "${EVR_WITH_ATTR_INDEX}" == '1' ]
then
    for fpr in `runuser -u nginx -- gpg --list-public-keys --with-colons | grep '^fpr:.*$' | sed 's/fpr:[:]*\([^:]*\):[:]*/\1/'`
    do
        echo "${fpr}:6:" | runuser -u nginx -- gpg --import-ownertrust
    done
fi

if [ ! -e '/data/evr-glacier-fs.conf' ]
then
    echo -n '' > '/data/evr-glacier-fs.conf.tmp'

    echo "Configure evr-glacier-fs..."
    if [ -z "${EVR_GLACIER_STORAGE_HOST}" ]
    then
        echo "evr-glacier-storage hostname must be provided via environment variable EVR_GLACIER_STORAGE_HOST"
        exit 1
    fi
    echo "storage-host=${EVR_GLACIER_STORAGE_HOST}" >> '/data/evr-glacier-fs.conf.tmp'
    echo "ssl-cert=${EVR_GLACIER_STORAGE_HOST}:2361:/pub/evr-glacier-storage-cert.pem" >> '/data/evr-glacier-fs.conf.tmp'
    echo "Waiting for glacier auth-token..."
    wait_for_file "/pub/evr-glacier-storage-auth-token"
    storage_auth_token=`cat "/pub/evr-glacier-storage-auth-token"`
    echo "auth-token=${EVR_GLACIER_STORAGE_HOST}:2361:${storage_auth_token}" >> '/data/evr-glacier-fs.conf.tmp'

    for fpr in `runuser -u nginx -- gpg --list-public-keys --with-colons | grep '^fpr:.*$' | sed 's/fpr:[:]*\([^:]*\):[:]*/\1/'`
    do
        echo "accepted-gpg-key=${fpr}" >> '/data/evr-glacier-fs.conf.tmp'
    done

    mv '/data/evr-glacier-fs.conf.tmp' '/data/evr-glacier-fs.conf'
fi

mkdir -p '/mnt/evr-glacier-fs'
chown nginx:nginx '/mnt/evr-glacier-fs'

cd /data
export PATH="/opt/evr/bin:${ORIG_PATH}"
exec /opt/evr/evr-parallel --user nginx /opt/evr/evr-glacier-fs -s -f /mnt/evr-glacier-fs \; /docker-entrypoint.sh nginx -g 'daemon off;' \; /opt/evr/finally umount /mnt/evr-glacier-fs
