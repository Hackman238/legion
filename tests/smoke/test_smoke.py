"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.
"""
import os
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from PyQt6 import QtWidgets

from app.ProjectManager import ProjectManager, tempDirectory as PROJECT_MANAGER_TEMP
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.host import hostObj
from db.SqliteDbAdapter import DatabaseIntegrityError
from app.importers.NmapImporter import NmapImporter


class DummyProgress:
    def __init__(self):
        self.started = False
        self.finished_called = False
        self.updates = []

    def start(self):
        self.started = True

    def finished(self):
        self.finished_called = True

    def updateProgress(self, percent, label):
        self.updates.append((percent, label))


class SmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure a Qt application exists for signal/slot usage during smoke tests.
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls._qt_app = QtWidgets.QApplication.instance()
        if cls._qt_app is None:
            cls._qt_app = QtWidgets.QApplication([])

    def setUp(self):
        self.tempdir_obj = tempfile.TemporaryDirectory()
        self.tempdir = self.tempdir_obj.name
        self._original_pm_temp_dir = PROJECT_MANAGER_TEMP

        # Ensure ProjectManager uses our isolated temporary directory.
        import app.ProjectManager as pm_module
        self.pm_module = pm_module
        self.pm_module.tempDirectory = self.tempdir

        self.shell = DefaultShell()
        self.repository_factory = RepositoryFactory(getDbLogger())
        self.project_manager = ProjectManager(self.shell, self.repository_factory, getAppLogger())

    def tearDown(self):
        # Restore original ProjectManager temp directory and clean resources.
        self.pm_module.tempDirectory = self._original_pm_temp_dir
        self.tempdir_obj.cleanup()

    def _create_project(self):
        project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        return project

    def test_project_save_and_load_roundtrip(self):
        project = self._create_project()
        host_repository = project.repositoryContainer.hostRepository

        session = project.database.session()
        session.add(hostObj(ip="10.0.0.1", ipv4="10.0.0.1", hostname="smoke-host"))
        session.commit()
        session.close()

        destination = os.path.join(self.tempdir, "smoke-project")
        saved_project = self.project_manager.saveProjectAs(project, destination, replace=1, projectType="legion")

        self.assertTrue(os.path.isfile(f"{destination}.legion"))
        hosts = saved_project.repositoryContainer.hostRepository.getAllHostObjs()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "10.0.0.1")

        # Ensure cleanup succeeds.
        self.project_manager.setStoreWordListsOnExit(saved_project, False)
        self.project_manager.closeProject(saved_project)

    def test_credential_repository_roundtrip(self):
        project = self._create_project()
        repo = project.repositoryContainer.credentialRepository
        repo.storeCapture('responder', 'eth0', 'Sample capture line', username='test', hash_value='deadbeef')
        captures = repo.getAllCaptures()
        self.assertTrue(any(cap['tool'] == 'responder' for cap in captures))
        self.project_manager.closeProject(project)

    def test_nmap_importer_smoke(self):
        project = self._create_project()
        host_repo = project.repositoryContainer.hostRepository

        xml_path = os.path.join(self.tempdir, "sample-nmap.xml")
        with open(xml_path, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent("""\
                <?xml version="1.0" encoding="UTF-8"?>
                <nmaprun scanner="nmap" args="nmap -oX -" start="0" startstr="Thu Jan  1 00:00:00 1970" version="7.92" xmloutputversion="1.05">
                  <scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>
                  <verbose level="0"/>
                  <debugging level="0"/>
                  <host>
                    <status state="up" reason="syn-ack" reason_ttl="0"/>
                    <address addr="192.168.1.10" addrtype="ipv4"/>
                    <hostnames>
                      <hostname name="nmap-smoke" type="user"/>
                    </hostnames>
                    <ports>
                      <port protocol="tcp" portid="22">
                        <state state="open" reason="syn-ack" reason_ttl="0"/>
                        <service name="ssh" method="table" conf="10"/>
                      </port>
                    </ports>
                  </host>
                  <runstats>
                    <finished time="0" timestr="Thu Jan  1 00:00:01 1970" summary="Nmap done"/>
                    <hosts up="1" down="0" total="1"/>
                  </runstats>
                </nmaprun>
            """))

        progress = DummyProgress()
        importer = NmapImporter(progress, host_repo)
        importer.setDB(project.database)
        importer.setHostRepository(host_repo)
        importer.setFilename(xml_path)
        importer.setOutput("")

        importer.run()

        hosts = host_repo.getAllHostObjs()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "192.168.1.10")

        # Confirm ports were stored without raising exceptions.
        ports = project.repositoryContainer.portRepository.getPortsByHostId(hosts[0].id)
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0].portId, "22")

        self.project_manager.closeProject(project)

    def test_controller_handles_corrupted_project(self):
        controller = ControllerDouble()
        with patch.object(QtWidgets.QMessageBox, "critical") as mock_critical:
            result = controller.openExistingProject("corrupted.legion", "legion")

        self.assertFalse(result)
        mock_critical.assert_called_once()
        self.assertTrue(controller.view.closed)
        self.assertTrue(controller.logic.temp_project_created)
        controller.start.assert_called_once()


class ControllerDouble:
    """
    Lightweight controller replacement that reuses Controller.openExistingProject
    logic without requiring the full GUI initialisation pipeline.
    """
    def __init__(self):
        from controller.controller import Controller  # Local import to reuse implementation details.

        self.__controller = Controller.__new__(Controller)
        self.logic = LogicDouble()
        self.view = ViewDouble()
        self.__controller.logic = self.logic
        self.__controller.view = self.view
        self.__controller.start = MagicMock()

    def __getattr__(self, item):
        return getattr(self.__controller, item)


class LogicDouble:
    def __init__(self):
        self.temp_project_created = False

    def openExistingProject(self, filename, projectType):
        raise DatabaseIntegrityError("test corruption detected")

    def createNewTemporaryProject(self):
        self.temp_project_created = True


class ViewDouble:
    def __init__(self):
        self.closed = False
        self.ui = SimpleNamespace(centralwidget=object())
        self.viewState = SimpleNamespace(lazy_update_tools=False)

    def closeProject(self):
        self.closed = True

    def restoreToolTabs(self):
        pass

    def hostTableClick(self):
        pass

    def refreshToolsTableModel(self):
        pass

    def responderProcessFinished(self, db_id):
        pass

    def updateResponderResultsTable(self):
        pass
