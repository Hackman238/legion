import os
import tempfile
import unittest
from unittest.mock import patch


class PathsTest(unittest.TestCase):
    def test_legion_home_functions_honor_override(self):
        from app.paths import (
            get_legion_home,
            get_legion_conf_path,
            get_legion_backup_dir,
            get_legion_autosave_dir,
            get_scheduler_config_path,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_home = os.path.join(tmpdir, "legion-side-by-side")
            with patch.dict(os.environ, {"LEGION_HOME": custom_home}, clear=False):
                self.assertEqual(custom_home, get_legion_home())
                self.assertEqual(os.path.join(custom_home, "legion.conf"), get_legion_conf_path())
                self.assertEqual(os.path.join(custom_home, "backup"), get_legion_backup_dir())
                self.assertEqual(os.path.join(custom_home, "autosave"), get_legion_autosave_dir())
                self.assertEqual(os.path.join(custom_home, "scheduler-ai.json"), get_scheduler_config_path())

    def test_app_settings_uses_legion_home_override(self):
        from app.settings import AppSettings

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_home = os.path.join(tmpdir, "legion-side-by-side")
            with patch.dict(os.environ, {"LEGION_HOME": custom_home}, clear=False):
                settings = AppSettings()

            conf_path = str(settings.actions.fileName() or "")
            self.assertEqual(os.path.join(custom_home, "legion.conf"), conf_path)
            self.assertTrue(os.path.isfile(conf_path))


if __name__ == "__main__":
    unittest.main()
