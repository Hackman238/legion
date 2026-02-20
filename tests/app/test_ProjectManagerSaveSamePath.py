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


if __name__ == "__main__":
    unittest.main()
