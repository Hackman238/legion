#!/usr/bin/env python3
from pyShodan import PyShodan
import sys

class PyShodanScript():
    def __init__(self):
        self.dbHost = None
        self.session = None

    def setDbHost(self, dbHost):
        self.dbHost = dbHost

    def setSession(self, session):
        self.session = session

    def run(self):
        if not self.dbHost or not hasattr(self.dbHost, "ipv4"):
            print("No dbHost or ipv4 provided.")
            return {}
        ip = str(self.dbHost.ipv4)
        return self.lookup(ip)

    def lookup(self, ip):
        try:
            pyShodanObj = PyShodan()
            pyShodanObj.apiKey = "REMOVED-SHODAN-KEY"
            pyShodanObj.createSession()
            pyShodanResults = pyShodanObj.searchIp(ip, allData=True)
            if isinstance(pyShodanResults, dict) and pyShodanResults:
                if self.dbHost and self.session:
                    self.dbHost.latitude = pyShodanResults.get('latitude', 'unknown')
                    self.dbHost.longitude = pyShodanResults.get('longitude', 'unknown')
                    self.dbHost.asn = pyShodanResults.get('asn', 'unknown')
                    self.dbHost.isp = pyShodanResults.get('isp', 'unknown')
                    self.dbHost.city = pyShodanResults.get('city', 'unknown')
                    self.dbHost.countryCode = pyShodanResults.get('country_code', 'unknown')
                    self.session.add(self.dbHost)
                print(pyShodanResults)
                return pyShodanResults
            else:
                print("No results found or error in response.")
                return {}
        except Exception as e:
            print(f"Error: {e}")
            return {}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: pyShodan.py <IP_ADDRESS>")
        sys.exit(1)
    ip = sys.argv[1]
    script = PyShodanScript()
    script.lookup(ip)
