#!/bin/bash
set -e
emacs -batch -l ert -l templar.el -l templar-test.el -f ert-run-tests-batch-and-exit
