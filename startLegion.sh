#!/bin/bash

echo "Strap yourself in, we're starting Legion..."

# Set everything we might need as executable
chmod a+x -R ./deps/*
chmod a+x -R ./scripts/*

# Determine OS, version and if WSL
source ./deps/detectOs.sh

# Determine and set the Python and Pip paths
source ./deps/detectPython.sh

# Figure if fist run or recloned and install deps 
if [ ! -f ".initialized" ] | [ -f ".justcloned" ]
then
    echo "First run here (or you did a pull to update). Let's try to automatically install all the dependancies..."
    if [ ! -d "tmp" ]
    then
        mkdir tmp
    fi

    # Setup WSL bits if needed
    if [ ! -z $ISWSL ]
    then
        echo "WSL Setup..."
        bash ./deps/setupWsl.sh
    fi

    # Install dependancies from package manager
    echo "Installing Packages from APT..."
    ./deps/installDeps.sh

    # Install python dependancies
    echo "Installing Python Libraries..."
    ./deps/installPythonLibs.sh

    # Determine if additional Sparta scripts are installed
    bash ./deps/detectScripts.sh

    touch .initialized
    rm .justcloned -f
fi

if [[ $1 != 'setup' ]]
then
    # Starts the web interface; pass any legion.py options through (e.g. ./startLegion.sh --web-port 8080).
    /usr/bin/env python3 legion.py --web "$@"
fi
