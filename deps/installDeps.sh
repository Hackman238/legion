#!/bin/bash

# macOS: external scan tools come from Homebrew (optional, resolved via PATH).
# Only formulae that exist in homebrew-core are listed; whatweb/wapiti/hping3
# have no formula (install manually if needed). xsltproc ships with macOS.
# NOTE: homebrew's `medusa` is a smart-contract fuzzer, NOT the Foofus login
# bruteforcer Legion's snmp-brute action expects - do not install it here.
if [ "$(uname -s)" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
        for tool in nmap nikto hydra sqlmap sslscan dnsmap; do
            brew install "$tool" 2>/dev/null || \
                echo "Optional tool $tool failed to install; Legion still runs without it."
        done
    else
        echo "Homebrew not found; install scan tools manually (brew install nmap nikto ...)."
    fi
    exit 0
fi

source ./deps/apt.sh

# Install deps
 echo "Checking Apt..."

# runAptGetUpdate
apt-get update -m

echo "Installing deps..."
export DEBIAN_FRONTEND="noninteractive"
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install sra-toolkit sslscan
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install nmap finger hydra nikto nbtscan nfs-common rpcbind smbclient ldap-utils rwho x11-apps featherpad xvfb imagemagick eog hping3 sqlmap libqt5core5a python3-pip ruby perl urlscan git xsltproc hping3
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install libgl1-mesa-glx libegl-mesa0 libegl1 libxcb-cursor0 libxcb-icccm4 python3-xvfbwrapper python3-selenium libxcb-image0  libxcb-keysyms1  libxcb-render-util0  libxcb-xkb1 libxkbcommon-x11-0
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install dnsmap
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install wapiti
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install python3-impacket
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install whatweb
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install medusa

# Check and install EyeWitness and its dependencies
./checkEyewitness.sh

# Check and install Geckodriver needed for Eyewitness
./checkGeckodriver.sh
