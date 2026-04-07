#!/usr/bin/python
from db.entities.cve import cve

__author__ =  'ketchup'
__version__=  '0.1'
__modified_by = 'ketchup'

import parsers.CVE as CVE

try:
    from pyexploitdb import PyExploitDb
except ImportError:
    try:
        from pyExploitDb import PyExploitDb
    except Exception as import_error:
        PyExploitDb = None
        PY_EXPLOIT_DB_IMPORT_ERROR = import_error
else:
    PY_EXPLOIT_DB_IMPORT_ERROR = None

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

        pyExploitDb = None
        if PyExploitDb is None:
            print("[PyExploitDb] Module unavailable: {0}".format(PY_EXPLOIT_DB_IMPORT_ERROR))
        else:
            try:
                pyExploitDb = PyExploitDb()
                pyExploitDb.debug = False
                pyExploitDb.autoUpdate = False
                pyExploitDb.openFile()
            except Exception as exc:
                print("[PyExploitDb] Failed to initialise: {0}".format(exc))
                pyExploitDb = None

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
                    if pyExploitDb:
                        try:
                            exploitResults = pyExploitDb.searchCve(fields[0])
                        except Exception as exc:
                            print("[PyExploitDb] Lookup failed for {0}: {1}".format(fields[0], exc))
                            exploitResults = None
                        if isinstance(exploitResults, dict) and exploitResults:
                            exploit_id = exploitResults.get('edbid') or exploitResults.get('id')
                            if exploit_id:
                                cve_dict['exploitId'] = exploit_id
                                cve_dict['exploitUrl'] = "https://www.exploit-db.com/exploits/{0}".format(exploit_id)
                            exploit_summary = exploitResults.get('exploit') or exploitResults.get('description') or exploitResults.get('file')
                            if exploit_summary:
                                cve_dict['exploit'] = exploit_summary
                        elif exploitResults:
                            print("[PyExploitDb] Unexpected lookup result for {0}: {1}".format(fields[0], type(exploitResults)))
                cve_list.append(cve_dict)
                continue
        # Save last product's CVEs
        if current_product and cve_list:
            resultsDict[current_product] = cve_list

        return resultsDict

    def getCves(self):
        cveOutput = self.output
        cveObjects = []

        if not cveOutput:
            return None

        try:
            cvesResults = self.processVulnersScriptOutput(cveOutput)
        except Exception as exc:
            print("[Vulners] Failed to process script output: {0}".format(exc))
            return []
        print("NEW CVERESULTS: {0}".format(cvesResults))

        for product in cvesResults:
            serviceCpes = cvesResults[product]
            for cveData in serviceCpes:
                print("NEW CVE ENTRY: {0}".format(cveData))
                cveObj = CVE.CVE(cveData)
                cveObjects.append(cveObj)
        return cveObjects

    def scriptSelector(self, host):
        scriptId = str(self.scriptId).lower()
        results = []
        if 'vulners' in scriptId:
            print("------------------------VULNERS")
            cveResults = self.getCves()
            if not cveResults:
                return results
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
