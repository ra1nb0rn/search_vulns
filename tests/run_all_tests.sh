#!/bin/bash

# https://stackoverflow.com/a/246128
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo '[+] Running test_cve_completeness.py'
python3 "${SCRIPT_DIR}/test_cve_completeness.py"
EXIT_1=$?
echo '[+] Running test_cve_attr_completeness.py'
python3 "${SCRIPT_DIR}/test_cve_attr_completeness.py"
EXIT_2=$?
echo '[+] Running test_exploit_completeness.py'
python3 "${SCRIPT_DIR}/test_exploit_completeness.py"
EXIT_3=$?
echo '[+] Running test_related_queries.py'
python3 "${SCRIPT_DIR}/test_related_queries.py"
EXIT_4=$?

# https://stackoverflow.com/a/16358989
! (( $EXIT_1 || $EXIT_2 || $EXIT_3 || $EXIT_4 ))
