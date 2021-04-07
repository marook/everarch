#!/bin/bash
set -e

for module in everarch-glacier-storage
do
    echo "Testing module ${module}…"
    ( cd "${module}" && ./test.sh )
done
