import os
import unittest
from unittest.mock import MagicMock

from app.tools.ToolCoordinator import ToolCoordinator


class SavedOutputFolderTest(unittest.TestCase):
    def test_nmap_parent_folder_is_kept_and_other_files_go_to_the_output_folder(self):
        self.assertEqual(os.path.join("/out", "nmap"),
                         ToolCoordinator.savedOutputFolder("/out", "/tmp/run/nmap/scan1"))
        self.assertEqual("/out", ToolCoordinator.savedOutputFolder("/out", "/tmp/run/20250101-nmapstage1"))

    def test_save_tool_output_uses_the_same_rule(self):
        shell = MagicMock()
        shell.directoryOrFileExists.return_value = False
        shell.isFile.return_value = False
        coordinator = ToolCoordinator(shell, MagicMock())
        with unittest.mock.patch("app.tools.ToolCoordinator.fileExists", return_value=True):
            coordinator.saveToolOutput("/out", "/tmp/run/nmap/scan1.xml")
        shell.move.assert_called_once_with("/tmp/run/nmap/scan1.xml", os.path.join("/out", "nmap"))


if __name__ == "__main__":
    unittest.main()
