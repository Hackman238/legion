import os
import shutil
import tempfile
import unittest

import app.ProjectManager as pm_module
from app.ProjectManager import ProjectManager, tempDirectory as PROJECT_MANAGER_TEMP
from app.importers.nmap_runner import import_nmap_xml_into_project
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


class NmapImportRunnerTest(unittest.TestCase):
    def setUp(self):
        self.tempdir_obj = tempfile.TemporaryDirectory()
        self.tempdir = self.tempdir_obj.name
        self._original_pm_temp_dir = PROJECT_MANAGER_TEMP
        pm_module.tempDirectory = self.tempdir

        shell = DefaultShell()
        repository_factory = RepositoryFactory(getDbLogger())
        self.project_manager = ProjectManager(shell, repository_factory, getAppLogger())

    def tearDown(self):
        pm_module.tempDirectory = self._original_pm_temp_dir
        self.tempdir_obj.cleanup()

    def _create_project(self):
        return self.project_manager.createNewProject(projectType="legion", isTemp=True)

    def test_import_valid_fixture_populates_host_ports_and_services(self):
        project = self._create_project()
        xml_path = os.path.join("tests", "parsers", "nmap-fixtures", "valid-nmap-report.xml")

        import_nmap_xml_into_project(project=project, xml_path=xml_path)

        hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
        self.assertEqual(1, len(hosts))
        self.assertEqual("192.168.1.1", hosts[0].ip)
        self.assertEqual("coolhost", hosts[0].hostname)
        self.assertEqual("macos", hosts[0].osMatch)

        ports = project.repositoryContainer.portRepository.getPortsByHostId(hosts[0].id)
        self.assertEqual(5, len(ports))
        self.assertEqual({"53", "80", "139", "443", "445"}, {str(item.portId) for item in ports})

        service_names = set()
        for port in ports:
            if not getattr(port, "serviceId", None):
                continue
            service = project.repositoryContainer.serviceRepository.getServiceById(port.serviceId)
            if service:
                service_names.add(str(service.name))
        self.assertTrue({"domain", "http", "netbios-ssn", "https", "msft"}.issubset(service_names))

    def test_import_malformed_fixture_creates_no_hosts(self):
        project = self._create_project()
        xml_path = os.path.join("tests", "parsers", "nmap-fixtures", "malformed-nmap-report.xml")

        import_nmap_xml_into_project(project=project, xml_path=xml_path)

        hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
        self.assertEqual(0, len(hosts))

    def test_importer_finds_xml_in_subdirectory_when_primary_path_is_missing(self):
        project = self._create_project()
        fixture = os.path.join("tests", "parsers", "nmap-fixtures", "valid-nmap-report.xml")
        missing_parent = os.path.join(self.tempdir, "missing-primary")
        os.makedirs(missing_parent, exist_ok=True)
        relocated_dir = os.path.join(missing_parent, "relocated")
        os.makedirs(relocated_dir, exist_ok=True)

        basename = "scan.xml"
        relocated_xml = os.path.join(relocated_dir, basename)
        shutil.copyfile(fixture, relocated_xml)
        missing_xml = os.path.join(missing_parent, basename)

        import_nmap_xml_into_project(project=project, xml_path=missing_xml)

        hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
        self.assertEqual(1, len(hosts))
        self.assertEqual("192.168.1.1", hosts[0].ip)


if __name__ == "__main__":
    unittest.main()
