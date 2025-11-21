#!/bin/bash

# colors (from: https://stackoverflow.com/a/5947802)
ORANGE='\033[0;33m'
GREEN="\033[0;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
SANE="\033[0m"

printf "${ORANGE}[!] Warning, this script will be deprecated in the future.\\n    Please use 'pip install . && search_vulns --full-install'\\n${SANE}"

# parse arguments if any
QUIET=0
FULL_RESOURCE_INSTALL=0
SKIP_RESOURCE_INSTALL=0
if [ $# -gt 0 ]; then
    for arg in "$@"
    do
        if [ $arg == "-q" ]; then
            QUIET=1
        elif [ $arg == "--full" ]; then
            FULL_RESOURCE_INSTALL=1
        elif [ $arg == "--no-resources" ]; then
            SKIP_RESOURCE_INSTALL=1
        fi
    done
fi

# begin install
printf "${GREEN}[+] Building and installing basic search_vulns Python package\\n${SANE}"
ORIG_DIR="${pwd}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $SCRIPT_DIR
pip3 install .
if [ $? != 0 ]; then
    pip3 install . --break-system-packages
fi

printf "${GREEN}[+] Performing full install of search_vulns\\n${SANE}"
cd $ORIG_DIR
search_vulns --full-install
if [ $SKIP_RESOURCE_INSTALL == 0 ]; then
    printf "${GREEN}[+] Creating local databases (this may take some time)\\n${SANE}"
    if [ $FULL_RESOURCE_INSTALL != 0 ]; then
        search_vulns --full-update
    else
        search_vulns -u
    fi
else
    printf "${GREEN}[-] Skipping install of vulnerability and software database\\n${SANE}"
fi
