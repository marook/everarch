#!/bin/bash
set -e

ctest

echo "Start valgrind testing…"
for test in *-test
do
    echo "Testing ${test}…"
    valgrind --quiet --leak-check=yes "./${test}"
done
