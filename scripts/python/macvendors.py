#!/usr/bin/env python3
import requests
import sys

class macvendorsScript():
    def __init__(self):
        self.dbHost = None
        self.session = None

    def setDbHost(self, dbHost):
        self.dbHost = dbHost

    def setSession(self, session):
        self.session = session

    def run(self):
        if not self.dbHost or not hasattr(self.dbHost, "macaddr"):
            print("No dbHost or macaddr provided.")
            return "unknown"
        mac = str(self.dbHost.macaddr)
        return self.lookup(mac)

    def lookup(self, mac):
        url = "https://api.macvendors.com/" + mac
        try:
            r = requests.get(url, timeout=10)
            result = str(r.text)
            if not result or "error" in result.lower():
                result = "unknown"
            if self.dbHost and self.session:
                self.dbHost.vendor = result
                self.session.add(self.dbHost)
                self.session.commit()
                self.session.close()
            print(result)
            return result
        except Exception as e:
            print(f"Error: {e}")
            return "unknown"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: macvendors.py <MAC_ADDRESS>")
        sys.exit(1)
    mac = sys.argv[1]
    script = macvendorsScript()
    script.lookup(mac)
