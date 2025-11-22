#!/bin/bash

QUIET=0
LINUX_PACKAGE_MANAGER="apt-get"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_linux_packages() {
    # Check if script is run as root
    if [[ "$EUID" -ne 0 ]]; then
        SUDO="sudo"
    else
        SUDO=""
    fi

    # Install required packages
    PACKAGES="sudo git wget curl sqlite3 libsqlite3-dev libmariadb-dev jq"
    which ${LINUX_PACKAGE_MANAGER} &> /dev/null
    if [ $? != 0 ]; then
        printf "${RED}Could not find ${LINUX_PACKAGE_MANAGER} command.\\nPlease specify your package manager via environment variable LINUX_PACKAGE_MANAGER.\\n${SANE}"
        exit 1
    fi

    if [ $QUIET != 1 ]; then
        ${SUDO} ${LINUX_PACKAGE_MANAGER} update
    else
        ${SUDO} ${LINUX_PACKAGE_MANAGER} update >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    if [ ${QUIET} != 1 ]; then
        ${SUDO} ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES}
    else
        ${SUDO} ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES} >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    pip3 install "search_vulns[all]"
    if [ $? != 0 ]; then
        pip3 install "search_vulns[all]" --break-system-packages
    fi
}

run_module_installs() {
    # find all modules and run their 'install' function
    WORKING_DIR=$(pwd)
    find "${SCRIPT_DIR}/modules" -type f -name 'search_vulns_*.py' | while read -r MODULE_FILE; do
        MODULE_SCRIPT_DIR=$(dirname "$MODULE_FILE")
        MODULE_SCRIPT_NAME=$(basename "$MODULE_FILE")
        python3 - <<EOF
import os
import runpy
import sys

try:
    globals_dict = runpy.run_path("${MODULE_FILE}")
    os.chdir("${MODULE_SCRIPT_DIR}")
    if 'install' in globals_dict and callable(globals_dict['install']):
        print('${BLUE}[+] Installing module at ${MODULE_FILE}${SANE}')
        globals_dict['install']()
except Exception as e:
    print(f"Error in ${MODULE_SCRIPT_NAME}: {e}", file=sys.stderr)
EOF

        cd $WORKING_DIR
    done
}


#################################
########## Entry point ##########
#################################

# colors (from: https://stackoverflow.com/a/5947802)
GREEN="\033[0;32m"
SANE="\033[0m"

# run script
printf "${GREEN}[+] Installing system ${LINUX_PACKAGE_MANAGER} & Python packages\\n${SANE}"
install_linux_packages

printf "${GREEN}[+] Running installation scripts of modules ...\\n${SANE}"
run_module_installs
