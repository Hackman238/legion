#!/usr/bin/python
from db.entities.cve import cve

__author__ =  'ketchup'
__version__=  '0.1'
__modified_by = 'ketchup'

import parsers.CVE as CVE
from pyExploitDb import PyExploitDb

class Script:
    scriptId = ''
    output = ''

    def __init__(self, ScriptNode):
        if not (ScriptNode is None):
            self.scriptId = ScriptNode.getAttribute('id')
            self.output = ScriptNode.getAttribute('output')

    def processShodanScriptOutput(self, shodanOutput):
        output = shodanOutput.replace('\t\t\t','\t')
        output = output.replace('\t\t','\t')
        output = output.replace('\t',';')
        output = output.replace('\n;','\n')
        output = output.replace(' ','')
        output = output.split('\n')
        output = [entry for entry in output if len(entry) > 1]
        print(str(output))


    def processVulnersScriptOutput(self, vulnersOutput):
        import re

        pyExploitDb = PyExploitDb()
        pyExploitDb.debug = False
        pyExploitDb.autoUpdate = False
        pyExploitDb.openFile()

        resultsDict = {}
        current_product = None
        current_version = None
        current_source = None
        cve_list = []

        # Split into lines and process
        lines = vulnersOutput.splitlines()
        for line in lines:
            line = line.rstrip()
            # CPE line (e.g. "  cpe:/a:openbsd:openssh:8.4p1:")
            cpe_match = re.match(r'^\s*cpe:/[a-z]:([^:]+):([^:]+):([^:]+):?$', line)
            if cpe_match:
                # Save previous product's CVEs
                if current_product and cve_list:
                    resultsDict[current_product] = cve_list
                # Start new CPE/product
                current_product = cpe_match.group(2)
                current_version = cpe_match.group(3)
                current_source = cpe_match.group(1)
                cve_list = []
                continue
            # CVE or exploit line (indented with tab)
            if line.startswith('\t') or line.startswith('    '):
                fields = line.strip().split('\t')
                if len(fields) >= 3 and fields[0].startswith("CVE-"):
                    cve_dict = {
                        'id': fields[0],
                        'severity': fields[1],
                        'url': fields[2],
                        'type': 'cve',
                        'version': current_version,
                        'source': current_source,
                        'product': current_product
                    }
                    exploitResults = pyExploitDb.searchCve(fields[0])
                    if exploitResults:
                        cve_dict['exploitId'] = exploitResults['edbid']
                        cve_dict['exploit'] = exploitResults['exploit']
                        cve_dict['exploitUrl'] = "https://www.exploit-db.com/exploits/{0}".format(cve_dict['exploitId'])
                    cve_list.append(cve_dict)
                continue
        # Save last product's CVEs
        if current_product and cve_list:
            resultsDict[current_product] = cve_list

        return resultsDict

    def getCves(self):
        cveOutput = self.output
        cveObjects = []

        if len(cveOutput) > 0:
           cvesResults = self.processVulnersScriptOutput(cveOutput)
           print("NEW CVERESULTS: {0}".format(cvesResults))

           for product in cvesResults:
               serviceCpes = cvesResults[product]
               for cveData in serviceCpes:
                   print("NEW CVE ENTRY: {0}".format(cveData))
                   cveObj = CVE.CVE(cveData)
                   cveObjects.append(cveObj)
           return cveObjects
        return None

    def scriptSelector(self, host):
        scriptId = str(self.scriptId).lower()
        results = []
        if 'vulners' in scriptId:
            print("------------------------VULNERS")
            cveResults = self.getCves()
            for cveEntry in cveResults:
                t_cve = cve(name=cveEntry.name, url=cveEntry.url, source=cveEntry.source,
                            severity=cveEntry.severity, product=cveEntry.product, version=cveEntry.version,
                            hostId=host.id, exploitId=cveEntry.exploitId, exploit=cveEntry.exploit,
                            exploitUrl=cveEntry.exploitUrl)
                results.append(t_cve)
            return results
        elif 'shodan-api' in scriptId:
            print("------------------------SHODAN")
            self.processShodanScriptOutput(self.output)
            return results
        else:
            print("-----------------------*{0}".format(scriptId))
            return results
