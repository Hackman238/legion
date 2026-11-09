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

    def test_darwin_keeps_legacy_local_share_home_when_config_exists(self):
        import app.paths as paths

        with tempfile.TemporaryDirectory() as tmpdir:
            legacy_home = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(legacy_home, exist_ok=True)
            with open(os.path.join(legacy_home, "legion.conf"), "w", encoding="utf-8") as handle:
                handle.write("[GeneralSettings]\n")

            env = dict(os.environ)
            env.pop("LEGION_HOME", None)
            env["HOME"] = tmpdir
            with patch.dict(os.environ, env, clear=True):
                with patch("app.paths.sys.platform", "darwin"):
                    self.assertEqual(legacy_home, paths.get_legion_home())

    def test_fresh_darwin_default_home_uses_library_application_support(self):
        import app.paths as paths

        with tempfile.TemporaryDirectory() as tmpdir:
            env = dict(os.environ)
            env.pop("LEGION_HOME", None)
            env["HOME"] = tmpdir
            with patch.dict(os.environ, env, clear=True):
                with patch("app.paths.sys.platform", "darwin"):
                    expected = os.path.join(tmpdir, "Library", "Application Support", "legion")
                    self.assertEqual(expected, paths.get_legion_home())

    def test_default_legion_home_falls_back_when_default_path_is_not_writable(self):
        import app.paths as paths

        with tempfile.TemporaryDirectory() as tmpdir:
            expected_home = os.path.join(tmpdir, "legion-home", "fallback-user")
            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                os.environ.pop("LEGION_HOME", None)
                default_home = os.path.abspath(os.path.expanduser(paths._default_legion_home()))

            def fake_is_writable(path: str) -> bool:
                normalized = os.path.abspath(os.path.expanduser(path))
                if normalized == default_home:
                    return False
                if normalized == expected_home:
                    os.makedirs(normalized, exist_ok=True)
                    return True
                return True

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                os.environ.pop("LEGION_HOME", None)
                with patch("app.paths.tempfile.gettempdir", return_value=tmpdir):
                    with patch("app.paths._current_user_token", return_value="fallback-user"):
                        with patch("app.paths._is_writable_directory", side_effect=fake_is_writable):
                            self.assertEqual(expected_home, paths.get_legion_home())
                            self.assertEqual(
                                os.path.join(expected_home, "legion.conf"),
                                paths.get_legion_conf_path(),
                            )


if __name__ == "__main__":
    unittest.main()
