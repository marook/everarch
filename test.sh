#!/bin/bash
set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd "${script_dir}"

echo "Run unit tests…"
for test_bin in src/*-test
do
    test_name=`basename "${test_bin}"`
    echo "Testing ${test_name}…"
    "./${test_bin}"
done

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
    valgrind --quiet --leak-check=yes --error-exitcode=1 "./${test_bin}"
done

echo ''
echo 'Run integration tests…'
for test_suite in testing/suite/*
do
    if [[ ! -d "${test_suite}" ]]
    then
        continue
    fi
    test_name=`basename "${test_suite}"`
    echo "Run integration test ${test_name}…"
    ( cd "${test_suite}" && ./run-suite )
done

echo SUCCESS
