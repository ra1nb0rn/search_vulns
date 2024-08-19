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
echo '[+] Running test_debian_queries.py'
python3 "${SCRIPT_DIR}/test_debian_queries.py"
EXIT_4=$?
echo '[+] Running test_ubuntu_queries.py'
python3 "${SCRIPT_DIR}/test_ubuntu_queries.py"
EXIT_5=$?
echo '[+] Running test_redhat_queries.py'
python3 "${SCRIPT_DIR}/test_redhat_queries.py"
EXIT_6=$?
echo '[+] Running test_version_considered_equal.py'
python3 "${SCRIPT_DIR}/test_version_considered_equal.py"
EXIT_7=$?
echo '[+] Running test_version_comparison.py'
python3 "${SCRIPT_DIR}/test_version_comparison.py"
EXIT_8=$?

# don't run cpe_search tests for now, b/c search_vulns appends to CPE DB
# and because the test pipeline of cpe_search should ensure correct working by itself

# create temporary symlink for cpe_search tests
# CPE_DICT_LOCATION="${SCRIPT_DIR}/../$(cat "${SCRIPT_DIR}/../config.json" | jq -r '.cpe_search.DATABASE_NAME')"
# ln -s ${CPE_DICT_LOCATION} ${SCRIPT_DIR}/../cpe_search/cpe-search-dictionary.db3 &>/dev/null
# CREATED_SYMLINK=$?

# echo '[+] Running cpe_search/test_cpes.py'
# python3 "${SCRIPT_DIR}/../cpe_search/test_cpes.py"
# EXIT_5=$?
# echo '[+] Running cpe_search/test_cpe_suggestions.py'
# python3 "${SCRIPT_DIR}/../cpe_search/test_cpe_suggestions.py"
# EXIT_6=$?

# # remove temporary symlink if one was created
# if [ $CREATED_SYMLINK -eq 0 ]; then
#     rm "${SCRIPT_DIR}/../cpe_search/cpe-search-dictionary.db3"
# fi

echo '[+] Running test_eol_date.py'
python3 "${SCRIPT_DIR}/test_eol_date.py"
EXIT_9=$?

# https://stackoverflow.com/a/16358989
! (( $EXIT_1 || $EXIT_2 || $EXIT_3 || $EXIT_4 || $EXIT_5 | $EXIT_6 || $EXIT_7 || $EXIT_8 || $EXIT_9 ))
