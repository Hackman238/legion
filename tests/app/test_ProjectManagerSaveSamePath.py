import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock


class ProjectManagerSaveSamePathTest(unittest.TestCase):
    def test_save_project_as_same_path_is_noop(self):
        from app.ProjectManager import ProjectManager

        shell = MagicMock()
        repo_factory = MagicMock()
        logger = MagicMock()
        manager = ProjectManager(shell, repo_factory, logger)

        project = SimpleNamespace(
            properties=SimpleNamespace(
                projectName="/tmp/demo.legion",
                outputFolder="/tmp/demo-tool-output",
                isTemporary=False,
            ),
            database=MagicMock(),
        )
        project.database.verify_integrity = MagicMock()
        project.database.backup_to = MagicMock()

        manager.openExistingProject = MagicMock()

        saved = manager.saveProjectAs(project, "/tmp/demo.legion", replace=1, projectType="legion")
        self.assertIs(saved, project)
        project.database.verify_integrity.assert_not_called()
        project.database.backup_to.assert_not_called()
        manager.openExistingProject.assert_not_called()

    def test_save_project_as_same_db_new_output_folder_repoints_project(self):
        import os
        import tempfile
        from app.Project import ProjectProperties
        from app.ProjectManager import ProjectManager

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "demo.legion")
            old_output = os.path.join(tmpdir, "old-tool-output")
            os.makedirs(old_output)
            open(db_path, "w").close()
            with open(os.path.join(old_output, "scan.txt"), "w") as handle:
                handle.write("data")

            shell = MagicMock()
            manager = ProjectManager(shell, MagicMock(), MagicMock())
            manager.openExistingProject = MagicMock()
            properties = ProjectProperties(
                projectName=db_path, workingDirectory=tmpdir, projectType="legion", isTemporary=True,
                outputFolder=old_output, runningFolder=tmpdir, usernamesWordList=None,
                passwordWordList=None, storeWordListsOnExit=False,
            )
            project = SimpleNamespace(properties=properties, database=MagicMock())

            # replace=0: the "existing" target is the project's own file, which is not a conflict.
            saved = manager.saveProjectAs(project, db_path, replace=0, projectType="legion")

            self.assertIs(saved, project)
            new_output = os.path.join(tmpdir, "demo-tool-output")
            self.assertEqual(new_output, saved.properties.outputFolder)
            self.assertTrue(os.path.isfile(os.path.join(new_output, "scan.txt")))
            shell.remove_directory.assert_called_once_with(old_output)
            project.database.backup_to.assert_not_called()
            manager.openExistingProject.assert_not_called()
            self.assertFalse(saved.properties.isTemporary)
            self.assertEqual(os.path.join(new_output, "legion-usernames.txt"),
                             saved.properties.usernamesWordList.filename)
            self.assertEqual(os.path.join(new_output, "legion-passwords.txt"),
                             saved.properties.passwordWordList.filename)

    def test_temporary_project_saved_onto_its_own_path_survives_close(self):
        # The web UI used to pre-fill Save As with the temporary project's own path.
        import os
        import tempfile
        import app.ProjectManager as pm_module
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory

        with tempfile.TemporaryDirectory() as tmpdir:
            original_temp_dir = pm_module.tempDirectory
            pm_module.tempDirectory = tmpdir
            self.addCleanup(setattr, pm_module, "tempDirectory", original_temp_dir)
            manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
            project = manager.createNewProject(projectType="legion", isTemp=True)
            self.addCleanup(project.database.dispose)
            db_path = project.properties.projectName
            temp_output = project.properties.outputFolder
            project.properties.usernamesWordList.add("alice")

            saved = manager.saveProjectAs(project, db_path, replace=0, projectType="legion")

            self.assertIs(saved, project)
            self.assertFalse(saved.properties.isTemporary)
            new_output = saved.properties.outputFolder
            self.assertNotEqual(temp_output, new_output)
            self.assertFalse(os.path.exists(temp_output))  # the copied temporary original is no longer used
            self.assertEqual(os.path.join(new_output, "legion-usernames.txt"),
                             saved.properties.usernamesWordList.filename)
            with open(saved.properties.usernamesWordList.filename) as handle:
                self.assertEqual("alice\n", handle.read())

            manager.closeProject(saved)

            self.assertTrue(os.path.isfile(db_path))
            self.assertTrue(os.path.isdir(new_output))
            self.assertTrue(os.path.isfile(os.path.join(new_output, "legion-usernames.txt")))

    def test_temporary_project_saved_onto_its_own_path_and_output_folder_is_kept(self):
        from app.Project import ProjectProperties
        from app.ProjectManager import ProjectManager

        shell = MagicMock()
        manager = ProjectManager(shell, MagicMock(), MagicMock())
        manager.openExistingProject = MagicMock()
        properties = ProjectProperties(
            projectName="/tmp/demo.legion", workingDirectory="/cwd/", projectType="legion", isTemporary=True,
            outputFolder="/tmp/demo-tool-output", runningFolder="/tmp/demo-running", usernamesWordList=None,
            passwordWordList=None, storeWordListsOnExit=True,
        )
        project = SimpleNamespace(properties=properties, database=MagicMock())

        saved = manager.saveProjectAs(project, "/tmp/demo.legion", replace=0, projectType="legion")

        self.assertIs(saved, project)
        self.assertFalse(saved.properties.isTemporary)
        self.assertEqual("/tmp/demo-tool-output", saved.properties.outputFolder)
        manager.openExistingProject.assert_not_called()

        manager.closeProject(saved)
        shell.remove_file.assert_not_called()
        shell.remove_directory.assert_called_once_with("/tmp/demo-running")


if __name__ == "__main__":
    unittest.main()
