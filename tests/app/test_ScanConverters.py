import json
import os
import tempfile
import unittest

GNMAP = """# Nmap 7.94 scan initiated Tue Nov  5 10:00:00 2026 as: nmap -sV -oG scan.gnmap 10.0.0.0/30
Host: 10.0.0.1 (gw.example.test)\tStatus: Up
Host: 10.0.0.1 (gw.example.test)\tPorts: 22/open/tcp//ssh//OpenSSH 9.6/, 80/open/tcp//http//nginx 1.24/, 53/open|filtered/udp//domain///\tOS: Linux 5.X
Host: 10.0.0.2 ()\tStatus: Down
# Nmap done at Tue Nov  5 10:00:05 2026 -- 4 IP addresses (1 host up) scanned in 5.00 seconds
"""

MASSCAN_LIST = """#masscan
open tcp 443 198.51.100.7 1762000000
open tcp 80 198.51.100.7 1762000000
banner tcp 80 198.51.100.7 1762000001 http.server nginx/1.24
open tcp 22 198.51.100.9 1762000000
# end
"""

MASSCAN_XML = """<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1762000000" version="1.3.2" xmloutputversion="1.03">
<host endtime="1762000000"><address addr="203.0.113.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="54"/></port></ports></host>
<host endtime="1762000001"><address addr="203.0.113.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open" reason="response" reason_ttl="54"/><service name="http.server" banner="Jetty"/></port></ports></host>
<runstats><finished time="1762000002" timestr="x" elapsed="2"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


class ScanConverterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def _hosts(self, xml_path):
        from parsers.Parser import parseNmapReport

        report = parseNmapReport(xml_path)
        return {host.ip: host for host in report.getAllHosts()}

    def test_detects_each_format(self):
        from app.importers import scan_converters as sc

        self.assertEqual(sc.FORMAT_GNMAP, sc.detect_scan_format(self._write("a.gnmap", GNMAP)))
        self.assertEqual(sc.FORMAT_MASSCAN_LIST, sc.detect_scan_format(self._write("b.list", MASSCAN_LIST)))
        self.assertEqual(sc.FORMAT_MASSCAN_XML, sc.detect_scan_format(self._write("c.xml", MASSCAN_XML)))
        masscan_json = json.dumps([{"ip": "10.9.9.9", "timestamp": "1", "ports": [{"port": 445, "proto": "tcp", "status": "open"}]}])
        self.assertEqual(sc.FORMAT_MASSCAN_JSON, sc.detect_scan_format(self._write("d.json", masscan_json)))
        self.assertEqual(sc.FORMAT_NMAP_XML, sc.detect_scan_format("tests/parsers/nmap-fixtures/valid-nmap-report.xml"))
        self.assertEqual(sc.FORMAT_UNKNOWN, sc.detect_scan_format(self._write("e.txt", "hello\nworld\n")))

    def test_nmap_xml_is_returned_unchanged(self):
        from app.importers.scan_converters import convert_report_to_nmap_xml

        path, detected = convert_report_to_nmap_xml("tests/parsers/nmap-fixtures/valid-nmap-report.xml")
        self.assertEqual("tests/parsers/nmap-fixtures/valid-nmap-report.xml", path)
        self.assertEqual("nmap_xml", detected)

    def test_gnmap_round_trips_through_the_nmap_parser(self):
        from app.importers.scan_converters import convert_report_to_nmap_xml

        xml_path, detected = convert_report_to_nmap_xml(self._write("scan.gnmap", GNMAP), output_dir=self.tmp.name)
        self.assertEqual("gnmap", detected)
        hosts = self._hosts(xml_path)
        self.assertEqual({"10.0.0.1", "10.0.0.2"}, set(hosts))
        gateway = hosts["10.0.0.1"]
        self.assertEqual("up", gateway.status)
        self.assertEqual("gw.example.test", gateway.hostname)
        self.assertEqual("down", hosts["10.0.0.2"].status)
        self.assertEqual({"22", "80"}, set(gateway.getPorts("tcp", "open")))
        self.assertEqual(["53"], gateway.getPorts("udp", "open|filtered"))
        self.assertEqual("http", gateway.getService("tcp", "80").name)
        self.assertEqual("nginx 1.24", gateway.getService("tcp", "80").product)

    def test_masscan_list_and_xml_convert_with_banners(self):
        from app.importers.scan_converters import convert_report_to_nmap_xml

        xml_path, _ = convert_report_to_nmap_xml(self._write("m.list", MASSCAN_LIST), output_dir=self.tmp.name)
        hosts = self._hosts(xml_path)
        self.assertEqual({"198.51.100.7", "198.51.100.9"}, set(hosts))
        self.assertEqual({"80", "443"}, set(hosts["198.51.100.7"].getPorts("tcp", "open")))
        self.assertEqual("http.server", hosts["198.51.100.7"].getService("tcp", "80").name)
        self.assertIn("nginx/1.24", hosts["198.51.100.7"].getService("tcp", "80").extrainfo)

        xml_path, _ = convert_report_to_nmap_xml(self._write("m.xml", MASSCAN_XML), output_dir=self.tmp.name)
        hosts = self._hosts(xml_path)
        self.assertEqual(["203.0.113.5"], list(hosts))
        self.assertEqual(["8080"], hosts["203.0.113.5"].getPorts("tcp", "open"))
        self.assertIn("Jetty", hosts["203.0.113.5"].getService("tcp", "8080").extrainfo)

    def test_same_named_reports_convert_to_distinct_files(self):
        from app.importers.scan_converters import convert_report_to_nmap_xml

        first_dir = os.path.join(self.tmp.name, "a")
        second_dir = os.path.join(self.tmp.name, "b")
        os.makedirs(first_dir)
        os.makedirs(second_dir)
        for folder in (first_dir, second_dir):
            with open(os.path.join(folder, "scan.gnmap"), "w", encoding="utf-8") as handle:
                handle.write(GNMAP)
        out_dir = os.path.join(self.tmp.name, "running")
        os.makedirs(out_dir)
        first, _ = convert_report_to_nmap_xml(os.path.join(first_dir, "scan.gnmap"), output_dir=out_dir)
        second, _ = convert_report_to_nmap_xml(os.path.join(second_dir, "scan.gnmap"), output_dir=out_dir)
        self.assertNotEqual(first, second)
        self.assertTrue(os.path.isfile(first) and os.path.isfile(second))

    def test_unknown_format_is_rejected(self):
        from app.importers.scan_converters import convert_report_to_nmap_xml

        with self.assertRaises(ValueError):
            convert_report_to_nmap_xml(self._write("notes.txt", "just some notes\n"))

    def test_import_entry_point_accepts_gnmap(self):
        from app.ProjectManager import ProjectManager
        from app.importers.nmap_runner import import_nmap_xml_into_project
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory

        project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            import_nmap_xml_into_project(project=project, xml_path=self._write("scan.gnmap", GNMAP))
            hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
            self.assertIn("10.0.0.1", [host.ip for host in hosts])
            converted = [name for name in os.listdir(project.properties.runningFolder) if ".converted-gnmap-" in name and name.endswith(".xml")]
            self.assertEqual(1, len(converted))
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
