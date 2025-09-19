#!/bin/bash

QUIET=0
FULL_RESOURCE_INSTALL=0
SKIP_RESOURCE_INSTALL=0
LINUX_PACKAGE_MANAGER="apt-get"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEARCH_VULNS_PATH="$SCRIPT_DIR/search_vulns.py"


install_linux_packages() {
    # Install required packages
    PACKAGES="git python3 python3-pip wget curl sqlite3 libsqlite3-dev libmariadb-dev jq"
    which ${LINUX_PACKAGE_MANAGER} &> /dev/null
    if [ $? != 0 ]; then
        printf "${RED}Could not find ${LINUX_PACKAGE_MANAGER} command.\\nPlease specify your package manager at the start of the script.\\n${SANE}"
        exit 1
    fi

    if [ $QUIET != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} update
    else
        sudo ${LINUX_PACKAGE_MANAGER} update >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    if [ ${QUIET} != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES}
    else
        sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES} >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    pip3 install -r requirements.txt
    if [ $? != 0 ]; then
        pip3 install -r requirements.txt --break-system-packages
    fi

    pip3 install mariadb==1.1.12
    if [ $? != 0 ]; then
        pip3 install mariadb==1.1.12 --break-system-packages
    fi
}

run_module_installs() {
    # find all modules and run their 'install' function
    WORKING_DIR=$(pwd)
    find modules -type f -name 'search_vulns_*.py' | while read -r MODULE_FILE; do
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

create_local_databases() {
    if [ $FULL_RESOURCE_INSTALL != 0 ]; then
        "${SEARCH_VULNS_PATH}" --full-update
    else
        "${SEARCH_VULNS_PATH}" -u
    fi

    if [ $? != 0 ]; then
        echo -e "${RED}Could not create local databases.${SANE}"
        exit 1
    fi
}


#################################
########## Entry point ##########
#################################

# colors (from: https://stackoverflow.com/a/5947802)
GREEN="\033[0;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
SANE="\033[0m"

# parse arguments if any
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


# run script
printf "${GREEN}[+] Installing core ${LINUX_PACKAGE_MANAGER} & Python packages\\n${SANE}"
install_linux_packages

printf "${GREEN}[+] Setting up git submodules\\n${SANE}"
git submodule init
git submodule update

printf "${GREEN}[+] Running installation scripts of modules ...\\n${SANE}"
run_module_installs

if [ $SKIP_RESOURCE_INSTALL == 0 ]; then
    printf "${GREEN}[+] Creating local databases (this may take some time)\\n${SANE}"
    create_local_databases
else
    printf "${GREEN}[-] Skipping install of vulnerability and software database\\n${SANE}"
fi

sudo ln -sf "$(pwd -P)/search_vulns.py" /usr/local/bin/search_vulns
