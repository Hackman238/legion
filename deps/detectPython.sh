#!/bin/bash

# macOS: no apt/bc. Legion requires Python >= 3.12 (.python-version pins
# 3.15). Prefer a compatible project .venv, then newest Homebrew Python.
if [ "$(uname -s)" = "Darwin" ]; then
    _legion_py_ok() {
        command -v "$1" >/dev/null 2>&1 || return 1
        "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null
    }
    export PYTHON3BIN=""
    if [ -x ".venv/bin/python" ] && _legion_py_ok ".venv/bin/python"; then
        export PYTHON3BIN=".venv/bin/python"
    else
        for _legion_py_candidate in python3.15 python3.14 python3.13 python3.12 python3; do
            if _legion_py_ok "$_legion_py_candidate"; then
                export PYTHON3BIN="$(command -v "$_legion_py_candidate")"
                break
            fi
        done
    fi
    if [ -z "$PYTHON3BIN" ]; then
        echo "Python 3.12+ not found. Install it with: brew install python@3.15" >&2
        return 1 2>/dev/null || exit 1
    fi
    export PIP3BIN="$PYTHON3BIN -m pip"
    echo "PYTHON3BIN is set to $PYTHON3BIN ($($PYTHON3BIN --version 2>&1))"
    return 0 2>/dev/null || exit 0
fi

echo "Checking Apt..."
# runAptGetUpdate
apt-get update -m

echo "Installing bcs..."
export DEBIAN_FRONTEND="noninteractive"
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install bc

# Check if python or python3 is installed
if command -v python &> /dev/null || command -v python3 &> /dev/null
then
    # Get the python or python3 version and path
    if command -v python &> /dev/null
    then
        python_version=$(python --version | awk -F '[ ]' '{print $2}' | awk -F '[.]' '{print $1"."$2}')
        python_path=$(which python)
    else
        python_version=$(python3 --version | awk -F '[ ]' '{print $2}' | awk -F '[.]' '{print $1"."$2}')
        python_path=$(which python3)
    fi
    echo "Python version: $python_version"
    echo "Python path: $python_path"

    # Check if the python version is 3.8 or later
    if (( $(echo "$python_version >= 3.8" |bc -l) ))
    then
        export PYTHON3BIN=$python_path
        echo "PYTHON3BIN is set to $PYTHON3BIN"
    else
        echo "Your Python version is below 3.8, which may cause compatibility issues with some packages."
    fi
else
    echo "Python is not installed."
fi

# Check if pip or pip3 is installed
if command -v pip &> /dev/null || command -v pip3 &> /dev/null
then
    # Get the pip or pip3 version and path
    if command -v pip &> /dev/null
    then
        pip_version=$(pip --version)
        pip_path=$(which pip)
    else
        pip_version=$(pip3 --version)
        pip_path=$(which pip3)
    fi
    echo "Pip version: $pip_version"
    echo "Pip path: $pip_path"

    export PIP3BIN=$pip_path
    echo "PIP3BIN is set to $PIP3BIN"
else
    echo "Pip is not installed."
fi

