import os
import tempfile
import unittest
from unittest.mock import MagicMock

import app.ProjectManager as pm_module
from app.ProjectManager import ProjectManager, tempDirectory as PROJECT_MANAGER_TEMP
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.process import process


class ProjectManagerSaveAsReopenTest(unittest.TestCase):
    def setUp(self):
        self.tempdir_obj = tempfile.TemporaryDirectory()
        self.tempdir = self.tempdir_obj.name
        self._original_pm_temp_dir = PROJECT_MANAGER_TEMP
        pm_module.tempDirectory = self.tempdir
        self.shell = DefaultShell()
        self.project_manager = ProjectManager(self.shell, RepositoryFactory(getDbLogger()), getAppLogger())

    def tearDown(self):
        pm_module.tempDirectory = self._original_pm_temp_dir
        self.tempdir_obj.cleanup()

    def test_temporary_project_is_reopened_before_its_file_is_removed(self):
        project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        source_db_file = project.properties.projectName
        events = []
        original_open = self.project_manager.openExistingProject
        self.project_manager.openExistingProject = MagicMock(
            side_effect=lambda *a, **k: (events.append("reopen"), original_open(*a, **k))[1]
        )
        original_remove_file = self.shell.remove_file
        self.shell.remove_file = MagicMock(
            side_effect=lambda path: (events.append(("remove_file", path)), original_remove_file(path))
        )

        target = os.path.join(self.tempdir, "saved.legion")
        saved = self.project_manager.saveProjectAs(project, target, replace=1, projectType="legion")
        self.addCleanup(saved.database.dispose)
        self.addCleanup(project.database.dispose)

        self.assertIsNot(saved, project)
        self.assertEqual(target, saved.properties.projectName)
        self.assertEqual(["reopen", ("remove_file", source_db_file)], events)
        self.assertFalse(os.path.exists(source_db_file))
        self.assertEqual([], saved.repositoryContainer.hostRepository.getAllHostObjs())

    def test_source_repositories_stay_usable_after_save_as(self):
        # Work started before the save may still hold the old project's repositories.
        project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        saved = self.project_manager.saveProjectAs(
            project, os.path.join(self.tempdir, "copy.legion"), replace=1, projectType="legion"
        )
        self.addCleanup(saved.database.dispose)
        self.addCleanup(project.database.dispose)

        self.assertEqual([], project.repositoryContainer.hostRepository.getAllHostObjs())
        self.assertFalse(project.repositoryContainer.processRepository.isKilledProcess("1"))


class ProjectManagerInterruptedProcessesTest(unittest.TestCase):
    """Process rows left Running/Waiting by an earlier session are marked when a project is opened."""

    setUp = ProjectManagerSaveAsReopenTest.setUp
    tearDown = ProjectManagerSaveAsReopenTest.tearDown

    def _project_with_running_process(self):
        project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        self.addCleanup(project.database.dispose)
        repo = project.repositoryContainer.processRepository
        session = project.database.session()
        try:
            row = process("0", name="nmap", tabTitle="nmap", hostIp="10.0.0.1", status="Waiting")
            session.add(row)
            session.commit()
            process_id = row.id
        finally:
            session.close()
        repo.storeProcessRunningStatus(process_id, 4242)
        return project, process_id

    def test_opening_a_project_marks_stale_running_processes_interrupted(self):
        project, process_id = self._project_with_running_process()

        opened = self.project_manager.openExistingProject(project.properties.projectName, "legion")
        self.addCleanup(opened.database.dispose)

        self.assertEqual("Crashed", opened.repositoryContainer.processRepository.getStatusByProcessId(process_id))

    def test_save_as_reopen_keeps_running_processes(self):
        project, process_id = self._project_with_running_process()

        saved = self.project_manager.saveProjectAs(
            project, os.path.join(self.tempdir, "saved.legion"), replace=1, projectType="legion"
        )
        self.addCleanup(saved.database.dispose)

        # The process started before the save keeps running and updates its row in the saved project.
        self.assertEqual("Running", saved.repositoryContainer.processRepository.getStatusByProcessId(process_id))


class LogicRetiredDatabaseTest(unittest.TestCase):
    def test_save_as_retires_previous_database_until_disposed(self):
        from app.logic import Logic

        project_manager = MagicMock()
        old_project, new_project = MagicMock(), MagicMock()
        project_manager.saveProjectAs.return_value = new_project
        logic = Logic(MagicMock(), project_manager, MagicMock())
        logic.activeProject = old_project

        self.assertTrue(logic.saveProjectAs("/tmp/copy.legion", 1))
        old_project.database.dispose.assert_not_called()   # earlier work may still use it
        self.assertTrue(logic.hasRetiredDatabases())

        self.assertEqual(1, logic.disposeRetiredDatabases())
        old_project.database.dispose.assert_called_once_with()
        self.assertFalse(logic.hasRetiredDatabases())

    def test_refused_save_as_retires_nothing(self):
        from app.logic import Logic

        project_manager = MagicMock()
        project_manager.saveProjectAs.return_value = None
        logic = Logic(MagicMock(), project_manager, MagicMock())
        logic.activeProject = MagicMock()

        self.assertFalse(logic.saveProjectAs("/tmp/existing.legion", 0))
        self.assertFalse(logic.hasRetiredDatabases())


if __name__ == "__main__":
    unittest.main()
