#!/bin/bash

if [[ -z $LINUX_PACKAGE_MANAGER ]]; then
    LINUX_PACKAGE_MANAGER='apt-get'
fi

install_linux_packages() {
    # Install required packages
    PACKAGES="cmake gcc libmariadb-dev mariadb-client"
    which ${LINUX_PACKAGE_MANAGER} &> /dev/null
    if [ $? != 0 ]; then
        printf "${RED}Could not find ${LINUX_PACKAGE_MANAGER} command.\\nPlease specify your package manager at the start of the script.\\n${SANE}"
        exit 1
    fi

    sudo ${LINUX_PACKAGE_MANAGER} update
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES}
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi
}

setup_create_db() {
    ## configure submodules of SQLiteCpp for create_db
    cd "create_db_source/SQLiteCpp"
    git submodule init
    git submodule update
    cd ".."

    ## configure submodules of mariadb-connector-cpp for create_db
    cd "mariadb-connector-cpp"
    git submodule init
    git submodule update
    cd ".."

    ## get C++ JSON parser from https://github.com/nlohmann/json for create_db
    mkdir -p "json/single_include/nlohmann"
    cd json/single_include/nlohmann
    wget https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp -O json.hpp
    cd "../../../"

    ## build create_db
    rm -rf build
    mkdir -p build
    cd "build"
    cmake ..
    make
    cp create_db ../../
    cd "../../../../"
}

# Save original working directory and change dir
ORIG_DIR=$(pwd)
cd "$(dirname "$0")"

printf "${GREEN}[+] Installing ${LINUX_PACKAGE_MANAGER} packages\\n${SANE}"
install_linux_packages
printf "${GREEN}[+] Setting up vulnerability database creation tool\\n${SANE}"
setup_create_db

# Return to the original directory
cd "$ORIG_DIR"
