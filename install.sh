#!/bin/bash

QUIET=0
FULL_RESOURCE_INSTALL=0
SKIP_RESOURCE_INSTALL=0
LINUX_PACKAGE_MANAGER="apt-get"

install_linux_packages() {
    # Install required packages
    PACKAGES="python3 python3-pip wget curl sqlite3 libsqlite3-dev cmake gcc libmariadb-dev mariadb-client jq"
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

    pip3 install mariadb
    if [ $? != 0 ]; then
        pip3 install mariadb --break-system-packages
    fi
}

setup_create_db() {
    ## configure submodules of SQLiteCpp for create_db
    cd "db_build/core/build_source_cpp/SQLiteCpp"
    if [ $QUIET != 1 ]; then
        git submodule init
        git submodule update
    else
        git submodule --quiet init
        git submodule --quiet update
    fi
    cd ".."

    ## configure submodules of mariadb-connector-cpp for create_db
    cd "mariadb-connector-cpp"
    if [ $QUIET != 1 ]; then
        git submodule init
        git submodule update
    else
        git submodule --quiet init
        git submodule --quiet update
    fi
    cd ".."

    ## get C++ JSON parser from https://github.com/nlohmann/json for create_db
    mkdir -p "json/single_include/nlohmann"
    cd json/single_include/nlohmann
    if [ $QUIET != 1 ]; then
        wget https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp -O json.hpp
    else
        wget https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp -q -O json.hpp
    fi
    cd "../../../"

    ## build create_db
    rm -rf build
    mkdir -p build
    cd "build"
    if [ $QUIET != 1 ]; then
        cmake ..
        make
    else
        cmake --quiet ..
        make --quiet
    fi
    cp create_db ../../
    cd "../../../../"
}

create_vuln_and_software_db() {
    if [ -f resources/vulndb.db3 ]; then
        rm resources/vulndb.db3
    fi

    if [ $FULL_RESOURCE_INSTALL != 0 ]; then
        ./search_vulns.py --full-update
    else
        ./search_vulns.py -u
    fi

    if [ $? != 0 ]; then
        echo -e "${RED}Could not create vulnerability database"
        exit 1
    fi
}

setup_cpe_search() {
    cd "cpe_search"
    if [ $QUIET != 1 ]; then
        git submodule init
        git submodule update
    else
        git submodule --quiet init
        git submodule --quiet update
    fi

    pip3 install -r requirements.txt
    if [ $? != 0 ]; then
        pip3 install -r requirements.txt --break-system-packages
    fi

    cd ..
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
printf "${GREEN}[+] Installing ${LINUX_PACKAGE_MANAGER} packages\\n${SANE}"
install_linux_packages
printf "${GREEN}[+] Setting up cpe_search tool\\n${SANE}"
setup_cpe_search
printf "${GREEN}[+] Setting up vulnerability database creation tool\\n${SANE}"
setup_create_db
if [ $SKIP_RESOURCE_INSTALL == 0 ]; then
    printf "${GREEN}[+] Creating vulnerability and software database (this may take some time)\\n${SANE}"
    create_vuln_and_software_db
else
    printf "${GREEN}[-] Skipping install of vulnerability and software database\\n${SANE}"
fi


sudo ln -sf "$(pwd -P)/search_vulns.py" /usr/local/bin/search_vulns
