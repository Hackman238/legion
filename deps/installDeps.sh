#!/bin/bash

source ./deps/apt.sh

# Install deps
 echo "Checking Apt..."

# runAptGetUpdate
apt-get update -m

echo "Installing deps..."
export DEBIAN_FRONTEND="noninteractive"
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install sslscan
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install nmap finger hydra nikto nbtscan nfs-common rpcbind smbclient ldap-utils rwho imagemagick hping3 sqlmap python3-pip ruby perl urlscan git xsltproc hping3
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install python3-selenium
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install dnsmap
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install wapiti
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install python3-impacket
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install whatweb
apt-get -yqqqm --allow-unauthenticated -o DPkg::Options::="--force-overwrite" -o DPkg::Options::="--force-confdef" install medusa

# Check and install EyeWitness and its dependencies
./checkEyewitness.sh

# Check and install Geckodriver needed for Eyewitness
./checkGeckodriver.sh
