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
echo '[+] Running cpe_search/test_cpes.py'
python3 "${SCRIPT_DIR}/../cpe_search/test_cpes.py"
EXIT_4=$?
echo '[+] Running test_debian_queries.py'
python3 "${SCRIPT_DIR}/test_debian_queries.py"
EXIT_5=$?
echo '[+] Running test_ubuntu_queries.py'
python3 "${SCRIPT_DIR}/test_ubuntu_queries.py"
EXIT_6=$?
echo '[+] Running cpe_search/test_cpe_suggestions.py'
python3 "${SCRIPT_DIR}/../cpe_search/test_cpe_suggestions.py"
EXIT_7=$?

# https://stackoverflow.com/a/16358989
! (( $EXIT_1 || $EXIT_2 || $EXIT_3 || $EXIT_4 || $EXIT_5 | $EXIT_6 || $EXIT_7))
