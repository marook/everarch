#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd "${script_dir}"
. 'test.conf'

echo "Run unit and integration tests…"
make check

if [[ "${HAS_VALGRIND}" == 'true' ]]
then
   echo ''
   echo "Run unit tests with valgrind…"
   for test_bin in src/*-test
   do
       test_name=`basename "${test_bin}"`
       if [[ "${test_name}" == "concurrent-glacier-test" ]]
       then
           # the tests above are currently excluded from the valgrind
           # runs because they run too slow.
           continue
       fi
       echo "Testing ${test_name}…"
       ( cd src && valgrind --quiet --leak-check=yes --error-exitcode=1 "./${test_name}" )
   done
fi

echo ''
echo SUCCESS
