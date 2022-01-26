#!/bin/bash
set -e

ctest

echo "Start valgrind testing…"
for test in *-test
do
    if [[ "${test}" == "concurrent-glacier-test" ]]
    then
        # the tests above are currently excluded from the valgrind
        # runs because they run too slow.
        continue
    fi
    echo "Testing ${test}…"
    valgrind --quiet --leak-check=yes "./${test}"
done
