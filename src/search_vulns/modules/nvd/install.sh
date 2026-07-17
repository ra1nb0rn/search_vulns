#!/bin/bash

if [[ -z $LINUX_PACKAGE_MANAGER ]]; then
    LINUX_PACKAGE_MANAGER='apt-get'
fi

install_linux_packages() {
    # Install required packages
    PACKAGES="git cmake gcc libmariadb-dev mariadb-client"
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
    cd "create_db_source/"

    ## download SQLiteCpp for create_db
    git clone --depth 1 "https://github.com/SRombauts/SQLiteCpp"
    cd SQLiteCpp
    git fetch --depth 1 origin "a6537fe4c90a7e83b91fc899aa1fb43b979c0c93"
    git checkout "a6537fe4c90a7e83b91fc899aa1fb43b979c0c93"
    git submodule init
    git submodule update
    cd ..

    ## download mariadb-connector-cpp for create_db
    git clone --depth 1 "https://github.com/mariadb-corporation/mariadb-connector-cpp"
    cd mariadb-connector-cpp
    git fetch --depth 1 origin "7a289771f92f2f625a26d6d69da9b586dcd815bf"
    git checkout "7a289771f92f2f625a26d6d69da9b586dcd815bf"
    git submodule init
    git submodule update
    cd ..

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
