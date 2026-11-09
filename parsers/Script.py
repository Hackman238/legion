#!/usr/bin/env python3
from db.entities.cve import cve

__author__ =  'ketchup'
__version__=  '0.1'
__modified_by = 'ketchup'

import parsers.CVE as CVE

import csv
import re
import importlib.util
import json
import os
import threading
import time

# The exploit-db package installs as "pyexploitdb" (current PyPI releases) or "pyExploitDb" (older releases,
# e.g. Kali's package). Only its bundled data files are used: every version's openFile()/updateDb() clones or
# pulls the exploit-database git repository (and some crawl exploit-db.com), which must never happen in the
# middle of an nmap import. Run primeExploitDb.py to fetch/refresh that data out of band.
_PY_EXPLOIT_DB_MODULE_NAMES = ("pyexploitdb", "pyExploitDb")
PY_EXPLOIT_DB_IMPORT_ERROR = None

_PY_EXPLOIT_DB_LOCK = threading.Lock()
_PY_EXPLOIT_DB_INSTANCE = None
_PY_EXPLOIT_DB_INIT_ATTEMPTED = False  # True once loaded, or once the module is known to be unavailable
_PY_EXPLOIT_DB_RETRY_AFTER = 0.0       # monotonic time before which a failed load is not retried
_PY_EXPLOIT_DB_RETRY_SECONDS = 60.0


def _find_exploit_db_package_dir():
    """Directory of the installed exploit-db package (without importing it), or None."""
    for name in _PY_EXPLOIT_DB_MODULE_NAMES:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            spec = None
        if spec is not None and spec.origin:
            return os.path.dirname(os.path.abspath(spec.origin))
    return None


class LocalExploitDb:
    """Offline CVE -> exploit-db lookups from the package's bundled data (no network access)."""

    def __init__(self, package_dir):
        self.package_dir = package_dir
        with open(os.path.join(package_dir, "cveToEdbid.json"), encoding="utf-8") as handle:
            raw = json.load(handle)
        self.cve_to_edbids = {
            str(cve_id).upper(): [str(edb_id) for edb_id in (edb_ids or [])]
            for cve_id, edb_ids in (raw.items() if isinstance(raw, dict) else [])
        }
        # Only the first exploit per CVE is ever looked up, and only its description and file are used.
        wanted_edbids = {edb_ids[0] for edb_ids in self.cve_to_edbids.values() if edb_ids}
        self.exploits_by_edbid = {}  # edb id -> (description, file)
        csv_path = os.path.join(package_dir, "exploit-database", "files_exploits.csv")
        if os.path.isfile(csv_path):  # present once primeExploitDb.py has fetched the exploit-database repo
            with open(csv_path, encoding="utf-8", newline="") as handle:
                reader = csv.reader(handle)
                next(reader, None)
                for row in reader:
                    if row and row[0] in wanted_edbids:
                        self.exploits_by_edbid[row[0]] = (
                            row[2] if len(row) > 2 else "",
                            row[1] if len(row) > 1 else "",
                        )

    def searchCve(self, cve_id):
        """Return {'id', 'description', 'file'} for the first known exploit for cve_id, or {}."""
        edb_ids = self.cve_to_edbids.get(str(cve_id or "").upper(), [])
        if not edb_ids:
            return {}
        edb_id = edb_ids[0]
        description, file_path = self.exploits_by_edbid.get(edb_id, ("", ""))
        return {"id": edb_id, "description": description, "file": file_path}


def getPyExploitDb():
    """Return a lazily-initialised, process-wide exploit lookup (or None if the package is unavailable).

    Loading the data is expensive, so it is done once and shared by every vulners script. A failed load
    (e.g. unreadable data files) is retried after a short cooldown instead of disabling exploit enrichment
    for the rest of the process.
    """
    global _PY_EXPLOIT_DB_INSTANCE, _PY_EXPLOIT_DB_INIT_ATTEMPTED, _PY_EXPLOIT_DB_RETRY_AFTER
    if _PY_EXPLOIT_DB_INIT_ATTEMPTED or time.monotonic() < _PY_EXPLOIT_DB_RETRY_AFTER:
        return _PY_EXPLOIT_DB_INSTANCE
    with _PY_EXPLOIT_DB_LOCK:
        if _PY_EXPLOIT_DB_INIT_ATTEMPTED or time.monotonic() < _PY_EXPLOIT_DB_RETRY_AFTER:
            return _PY_EXPLOIT_DB_INSTANCE
        package_dir = _find_exploit_db_package_dir()
        if package_dir is None:
            print("[PyExploitDb] Module unavailable: install pyexploitdb for exploit-db references.")
            _PY_EXPLOIT_DB_INIT_ATTEMPTED = True
            return None
        try:
            instance = LocalExploitDb(package_dir)
        except FileNotFoundError as exc:
            # The package ships no CVE map (it is not a transient condition): disable enrichment once.
            print("[PyExploitDb] Exploit data not found ({0}); exploit references are disabled.".format(exc))
            _PY_EXPLOIT_DB_INIT_ATTEMPTED = True
            return None
        except Exception as exc:
            print("[PyExploitDb] Failed to load exploit data from {0}: {1}".format(package_dir, exc))
            _PY_EXPLOIT_DB_RETRY_AFTER = time.monotonic() + _PY_EXPLOIT_DB_RETRY_SECONDS
            return None
        _PY_EXPLOIT_DB_INSTANCE = instance
        _PY_EXPLOIT_DB_INIT_ATTEMPTED = True
        return instance

_VULNERS_CPE_LINE = re.compile(r'^\s*cpe:/[a-z]:([^:]+):([^:]+):([^:]+):?$')
# vulners.nse falls back to "<product> <version>:" headers when the service has no CPE
_VULNERS_SOFTWARE_LINE = re.compile(r'^\s{1,3}(?!cpe:/)(\S.*?)\s+(\S+):\s*$')


def _vulners_header(line):
    """(source, product, version) for a vulners section header line, or None."""
    match = _VULNERS_CPE_LINE.match(line)
    if match:
        return match.group(1), match.group(2), match.group(3)
    match = _VULNERS_SOFTWARE_LINE.match(line)
    if match:
        return 'software', match.group(1), match.group(2)
    return None


class Script:
    scriptId = ''
    output = ''

    @staticmethod
    def vulnersProductVersions(output):
        """(product, version) pairs named by a vulners script's output; product is lower-cased."""
        pairs = set()
        for line in str(output or "").splitlines():
            header = _vulners_header(line.rstrip())
            if header:
                pairs.add((header[1].lower(), header[2]))
        return pairs

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
        pyExploitDb = getPyExploitDb()

        resultsDict = {}
        current_product = None
        current_version = None
        current_source = None
        cve_list = []

        # Split into lines and process
        lines = vulnersOutput.splitlines()
        for line in lines:
            line = line.rstrip()
            # Section header: "  cpe:/a:openbsd:openssh:8.4p1:" or, without a CPE, "  nginx 1.14.0:"
            header = _vulners_header(line)
            if header:
                # Save previous product's CVEs
                if current_product and cve_list:
                    resultsDict[current_product] = cve_list
                # Start new CPE/product
                current_source, current_product, current_version = header
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
