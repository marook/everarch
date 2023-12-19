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

PATH="/opt/evr/entrypoint:${PATH}"

token_ops=

if [ "${EVR_WITH_UPLOAD_HTTPD}" == '1' ]
then
    wait_for_file "/pub/evr-upload-httpd-auth-token"
    auth_token=`cat "/pub/evr-upload-httpd-auth-token"`
    token_ops="${token_ops}/u${auth_token}"
fi

if [ "${EVR_WITH_ATTR_INDEX}" == '1' ]
then
    wait_for_file "/pub/evr-attr-index-auth-token"
    auth_token=`cat "/pub/evr-attr-index-auth-token"`
    token_ops="${token_ops}/i${auth_token}"
fi

cat <<EOF
************************************************************************
 everarch successfully started

 You can join the instance with your browser now:
 http://localhost:${EVR_WEB_PORT}/join/#j${token_ops}

    (keep this link a secret if you don't
     want someone else to access your data)

************************************************************************
EOF
