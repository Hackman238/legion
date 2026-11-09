import os
import tempfile
import unittest
from unittest.mock import patch

from PyQt6.QtWidgets import QApplication


class ConfigDialogPathsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._app = QApplication.instance() or QApplication([])

    def test_config_editor_reads_legion_home_override(self):
        from ui.configDialog import Config

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "legion.conf"), "w", encoding="utf-8") as handle:
                handle.write("[GeneralSettings]\nmarker-from-legion-home=1\n")

            with patch.dict(os.environ, {"LEGION_HOME": tmpdir}, clear=False):
                editor = Config(qss="")
            self.addCleanup(editor.close)

            self.assertIn("marker-from-legion-home", editor.toPlainText())


if __name__ == "__main__":
    unittest.main()
