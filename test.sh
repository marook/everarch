#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd "${script_dir}"

echo "Start testing…"
for test_bin in src/*-test
do
    test_name=`basename "${test_bin}"`
    echo "Testing ${test_name}…"
    "./${test_bin}"
done

echo ''
echo "Start valgrind testing…"
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
    valgrind --quiet --leak-check=yes "./${test_bin}"
done
