#!/bin/bash

# https://stackoverflow.com/a/246128
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo '[+] Running test_cve_completeness.py'
python3 "${SCRIPT_DIR}/test_cve_completeness.py"
echo '[+] Running test_cve_attr_completeness.py'
python3 "${SCRIPT_DIR}/test_cve_attr_completeness.py"
echo '[+] Running test_exploit_completeness.py'
python3 "${SCRIPT_DIR}/test_exploit_completeness.py"
echo '[+] Running test_related_queries.py'
python3 "${SCRIPT_DIR}/test_related_queries.py"
