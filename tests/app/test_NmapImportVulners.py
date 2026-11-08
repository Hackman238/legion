import os
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import quoteattr

import app.ProjectManager as pm_module
from app.ProjectManager import ProjectManager, tempDirectory as PROJECT_MANAGER_TEMP
from app.cli_utils import import_targets
from app.importers.nmap_runner import import_nmap_xml_into_project
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.cve import cve
from db.entities.host import hostObj
from db.entities.note import note

FIXTURE = os.path.join("tests", "parsers", "nmap-fixtures", "vulners-nmap-report.xml")


class NmapImportVulnersTest(unittest.TestCase):
    def setUp(self):
        self.tempdir_obj = tempfile.TemporaryDirectory()
        self._original_pm_temp_dir = PROJECT_MANAGER_TEMP
        pm_module.tempDirectory = self.tempdir_obj.name
        self.project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        # Avoid loading the exploit-db CSV in tests.
        patcher = patch("parsers.Script.getPyExploitDb", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Never touch the real /etc/hosts.
        hosts_patcher = patch("app.importers.NmapImporter.add_temporary_host_alias", return_value=(False, "test"))
        hosts_patcher.start()
        self.addCleanup(hosts_patcher.stop)

    def tearDown(self):
        self.project.database.dispose()
        pm_module.tempDirectory = self._original_pm_temp_dir
        self.tempdir_obj.cleanup()

    def _session(self):
        return self.project.database.session()

    def test_vulners_cves_are_stored_once(self):
        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)
        # Re-importing replaces the host's CVEs rather than duplicating them.
        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)
        session = self._session()
        try:
            names = sorted(row.name for row in session.query(cve).all())
        finally:
            session.close()
        self.assertEqual(["CVE-2021-41617", "CVE-2023-38408"], names)

    def test_added_by_nmap_note_references_host_id(self):
        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)
        session = self._session()
        try:
            host = session.query(hostObj).filter_by(ip="10.0.0.5").one()
            notes = session.query(note).all()
            self.assertEqual(1, len(notes))
            self.assertEqual(host.id, notes[0].hostId)
            self.assertEqual("Added by nmap", notes[0].text)
        finally:
            session.close()

    def test_existing_host_with_unknown_fields_is_filled(self):
        session = self._session()
        try:
            added = import_targets(session, self.project.repositoryContainer.hostRepository, ["10.0.0.5"])
        finally:
            session.close()
        self.assertEqual(["10.0.0.5"], added)

        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)

        session = self._session()
        try:
            host = session.query(hostObj).filter_by(ip="10.0.0.5").one()
            self.assertEqual("AA:BB:CC:DD:EE:FF", host.macaddr)
            self.assertEqual("Acme", host.vendor)
            self.assertEqual("1", str(host.distance))
            self.assertEqual("up", host.status)
        finally:
            session.close()

    def test_adopted_hostname_placeholder_does_not_keep_the_name_as_ipv4(self):
        from types import SimpleNamespace
        from app.importers.NmapImporter import NmapImporter

        session = self._session()
        try:
            import_targets(session, self.project.repositoryContainer.hostRepository, ["web.example.com"])
        finally:
            session.close()
        importer = NmapImporter(None, self.project.repositoryContainer.hostRepository)
        importer.setDB(self.project.database)
        # an IPv6-only scan result for that hostname
        h = SimpleNamespace(ip="2001:db8::10", hostname="web.example.com", ipv4="", ipv6="2001:db8::10")

        session = self.project.database.new_session()
        try:
            row = importer._adoptHostnamePlaceholder(session, h)
            self.assertIsNotNone(row)
            session.commit()
            self.assertEqual("2001:db8::10", row.ip)
            self.assertEqual("2001:db8::10", row.ipv6)
            self.assertEqual("", row.ipv4)   # not "web.example.com"
        finally:
            session.close()

    def test_inferred_os_gets_a_numeric_accuracy(self):
        # The fixture has no <os> block: the OS is inferred from the service inventory, and the host's
        # default accuracy 'NaN' must be replaced rather than kept.
        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)
        session = self._session()
        try:
            host = session.query(hostObj).filter_by(ip="10.0.0.5").one()
            self.assertEqual("Linux", host.osMatch)
            self.assertEqual("85", host.osAccuracy)
        finally:
            session.close()

    def test_hostname_target_is_updated_with_the_resolved_address_instead_of_duplicated(self):
        session = self._session()
        try:
            # a hostname target is stored with ip == hostname == 'vulnhost'
            self.assertEqual(["vulnhost"], import_targets(session, self.project.repositoryContainer.hostRepository,
                                                          ["vulnhost"]))
        finally:
            session.close()

        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)

        session = self._session()
        try:
            hosts = session.query(hostObj).all()
            self.assertEqual(1, len(hosts))
            self.assertEqual(("10.0.0.5", "10.0.0.5", "vulnhost"), (hosts[0].ip, hosts[0].ipv4, hosts[0].hostname))
            self.assertEqual("AA:BB:CC:DD:EE:FF", hosts[0].macaddr)
        finally:
            session.close()

    def _write_vulners_scan(self, name, ports):
        """Write a one-host nmap XML report; ports maps port id -> (service product, cpe, [CVE ids])."""
        port_nodes = []
        for port_id, (product, cpe, cve_ids) in ports.items():
            output = "\n  {0}: \n".format(cpe) + "".join(
                "    \t{0}\t7.5\thttps://vulners.com/cve/{0}\n".format(cve_id) for cve_id in cve_ids
            )
            port_nodes.append(
                '<port protocol="tcp" portid="{0}"><state state="open" reason="syn-ack"/>'
                '<service name="svc{0}" product="{1}" method="probed" conf="10"/>'
                '<script id="vulners" output={2}/></port>'.format(port_id, product, quoteattr(output))
            )
        xml_path = os.path.join(self.tempdir_obj.name, name)
        with open(xml_path, "w", encoding="utf-8") as handle:
            handle.write(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<nmaprun scanner="nmap" args="nmap --script vulners" start="1700000000" version="7.94" '
                'xmloutputversion="1.05"><host><status state="up" reason="syn-ack"/>'
                '<address addr="10.0.0.7" addrtype="ipv4"/><ports>{0}</ports></host>'
                '<runstats><finished time="1700000010" summary="Nmap done"/>'
                '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'.format("".join(port_nodes))
            )
        return xml_path

    def _cves_by_product(self):
        session = self._session()
        try:
            rows = session.query(cve).all()
        finally:
            session.close()
        result = {}
        for row in rows:
            result.setdefault(row.product, []).append(row.name)
        return {product: sorted(names) for product, names in result.items()}

    def test_partial_vulners_rescan_keeps_cves_of_ports_not_rescanned(self):
        ssh = ("OpenSSH", "cpe:/a:openbsd:openssh:8.4p1", ["CVE-2023-38408", "CVE-2021-41617"])
        full_scan = self._write_vulners_scan("full.xml", {
            "22": ssh,
            "80": ("Apache httpd", "cpe:/a:apache:http_server:2.4.41", ["CVE-2021-41773", "CVE-2021-42013"]),
        })
        # e.g. `nmap -p80 --script vulners`: port 22 is not part of this scan
        http_only_scan = self._write_vulners_scan("http-only.xml", {
            "80": ("Apache httpd", "cpe:/a:apache:http_server:2.4.41", ["CVE-2021-42013", "CVE-2022-22720"]),
        })

        import_nmap_xml_into_project(project=self.project, xml_path=full_scan)
        import_nmap_xml_into_project(project=self.project, xml_path=http_only_scan)

        self.assertEqual({
            "openssh": ["CVE-2021-41617", "CVE-2023-38408"],
            "http_server": ["CVE-2021-42013", "CVE-2022-22720"],
        }, self._cves_by_product())

    def test_rescan_of_one_port_keeps_the_same_products_cves_on_another_port(self):
        # Two OpenSSH instances with different versions; only port 22 is re-scanned.
        both = self._write_vulners_scan("both.xml", {
            "22": ("OpenSSH", "cpe:/a:openbsd:openssh:8.4p1", ["CVE-2023-38408"]),
            "2222": ("OpenSSH", "cpe:/a:openbsd:openssh:7.2p2", ["CVE-2016-6210"]),
        })
        port22_only = self._write_vulners_scan("p22.xml", {
            "22": ("OpenSSH", "cpe:/a:openbsd:openssh:8.4p1", ["CVE-2023-38408", "CVE-2021-41617"]),
        })

        import_nmap_xml_into_project(project=self.project, xml_path=both)
        import_nmap_xml_into_project(project=self.project, xml_path=port22_only)

        self.assertEqual({"openssh": ["CVE-2016-6210", "CVE-2021-41617", "CVE-2023-38408"]}, self._cves_by_product())

    def test_manually_added_cve_survives_a_vulners_rescan_of_its_product(self):
        scan = self._write_vulners_scan("scan.xml", {
            "22": ("OpenSSH", "cpe:/a:openbsd:openssh:8.4p1", ["CVE-2023-38408"]),
        })
        import_nmap_xml_into_project(project=self.project, xml_path=scan)
        session = self._session()
        try:
            host_id = session.query(hostObj).filter_by(ip="10.0.0.7").one().id
            # what the web UI's "add CVE" stores: product as typed, no version
            session.add(cve(name="CVE-2099-0001", url="", product="OpenSSH", hostId=str(host_id), severity="9.0"))
            session.commit()
        finally:
            session.close()

        import_nmap_xml_into_project(project=self.project, xml_path=scan)

        self.assertEqual({"openssh": ["CVE-2023-38408"], "OpenSSH": ["CVE-2099-0001"]}, self._cves_by_product())

    def test_product_replaced_on_a_rescanned_port_loses_its_cves(self):
        apache = self._write_vulners_scan("apache.xml", {
            "80": ("Apache httpd", "cpe:/a:apache:http_server:2.4.41", ["CVE-2021-41773"]),
        })
        nginx = self._write_vulners_scan("nginx.xml", {
            "80": ("nginx", "cpe:/a:nginx:nginx:1.25.0", ["CVE-2024-7347"]),
        })

        import_nmap_xml_into_project(project=self.project, xml_path=apache)
        import_nmap_xml_into_project(project=self.project, xml_path=nginx)

        self.assertEqual({"nginx": ["CVE-2024-7347"]}, self._cves_by_product())

    def test_rescan_after_upgrade_drops_the_old_versions_cves(self):
        old = self._write_vulners_scan("old.xml", {
            "22": ("OpenSSH", "cpe:/a:openbsd:openssh:7.2p2", ["CVE-2016-6210", "CVE-2016-10009"]),
        })
        upgraded = self._write_vulners_scan("new.xml", {
            "22": ("OpenSSH", "cpe:/a:openbsd:openssh:9.6p1", ["CVE-2024-6387"]),
        })

        import_nmap_xml_into_project(project=self.project, xml_path=old)
        import_nmap_xml_into_project(project=self.project, xml_path=upgraded)

        self.assertEqual({"openssh": ["CVE-2024-6387"]}, self._cves_by_product())

    def test_nmap_hostname_replaces_target_ip_stored_as_hostname(self):
        session = self._session()
        try:
            import_targets(session, self.project.repositoryContainer.hostRepository, ["10.0.0.5"])
        finally:
            session.close()

        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)

        session = self._session()
        try:
            host = session.query(hostObj).filter_by(ip="10.0.0.5").one()
            self.assertEqual("vulnhost", host.hostname)
        finally:
            session.close()

    def test_highest_percent_is_stored_for_process(self):
        process_repo = self.project.repositoryContainer.processRepository
        process_id = process_repo.storeScreenshot("10.0.0.5", "22", "x.png")
        process_repo.storeProcessPercent(process_id, "0")

        repo = self.project.repositoryContainer.hostRepository
        from app.importers.NmapImporter import NmapImporter
        importer = NmapImporter(None, repo)
        importer.setDB(self.project.database)
        importer.setFilename(FIXTURE)
        importer.processId = process_id
        importer.run()

        self.assertEqual("87.25", process_repo.getFieldByProcessId("percent", process_id))

    def test_highest_percent_survives_a_duplicate_session_reimport(self):
        repo = self.project.repositoryContainer.hostRepository
        import_nmap_xml_into_project(project=self.project, xml_path=FIXTURE)  # stores the nmap session row
        process_repo = self.project.repositoryContainer.processRepository
        process_id = process_repo.storeScreenshot("10.0.0.5", "22", "x.png")
        process_repo.storeProcessPercent(process_id, "0")

        from app.importers.NmapImporter import NmapImporter
        importer = NmapImporter(None, repo)
        importer.setDB(self.project.database)
        importer.setFilename(FIXTURE)          # same filename: the nmap session insert hits IntegrityError
        importer.processId = process_id
        importer.run()

        self.assertEqual("87.25", process_repo.getFieldByProcessId("percent", process_id))


if __name__ == "__main__":
    unittest.main()
