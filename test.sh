#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd "${script_dir}"
. 'test.conf'

echo "Run unit tests…"
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
echo 'Run integration tests…'
rm -f "testing/suite/put-parallel/glacier-benchmark.log"
echo -n '' > "${script_dir}/test.log"
for test_suite in testing/suite/*
do
    if [[ ! -d "${test_suite}" ]]
    then
        continue
    fi
    test_name=`basename "${test_suite}"`
    echo "Run integration test ${test_name}…"
    test_error=0
    ( cd "${test_suite}" && ./run-suite ) &>> "${script_dir}/test.log" || test_error=1
    if [[ "${test_error}" == '1' ]]
    then
        tail "${script_dir}/test.log" >&2
        echo "

For complete failure details see ${script_dir}/test.log" >&2
        exit 1
    fi
done

"${script_dir}/etc/profile-aggregate/profile-aggregate.py" < "${script_dir}/test.log"
cat "testing/suite/put-parallel/glacier-benchmark.log"

echo SUCCESS
