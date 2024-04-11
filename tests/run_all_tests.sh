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

# create temporary symlink for cpe_search tests
CPE_DICT_LOCATION="${SCRIPT_DIR}/../$(cat ${SCRIPT_DIR}/../config.json | jq -r '.cpe_search.DATABASE_NAME')"
ln -s ${CPE_DICT_LOCATION} ${SCRIPT_DIR}/../cpe_search/cpe-search-dictionary.db3 &>/dev/null
CREATED_SYMLINK=$?

echo '[+] Running cpe_search/test_cpes.py'
python3 "${SCRIPT_DIR}/../cpe_search/test_cpes.py"
EXIT_4=$?
echo '[+] Running cpe_search/test_cpe_suggestions.py'
python3 "${SCRIPT_DIR}/../cpe_search/test_cpe_suggestions.py"
EXIT_5=$?

# remove temporary symlink if one was created
if [ $CREATED_SYMLINK -eq 0 ]; then
    rm "${SCRIPT_DIR}/../cpe_search/cpe-search-dictionary.db3"
fi

# https://stackoverflow.com/a/16358989
! (( $EXIT_1 || $EXIT_2 || $EXIT_3 || $EXIT_4 || $EXIT_5 ))
