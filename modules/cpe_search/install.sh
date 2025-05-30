#!/bin/bash

# Save original working directory and change dir
ORIG_DIR=$(pwd)
cd "$(dirname "$0")"
cd cpe_search

git submodule init
git submodule update

pip3 install -r requirements.txt
if [ $? != 0 ]; then
    pip3 install -r requirements.txt --break-system-packages
fi

# Return to the original directory
cd "$ORIG_DIR"

