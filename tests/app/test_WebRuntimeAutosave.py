import os
import unittest
from types import SimpleNamespace


class WebRuntimeAutosaveTest(unittest.TestCase):
    def test_get_autosave_interval_seconds_uses_config_minutes(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime.settings = SimpleNamespace(general_notes_autosave_minutes="2")
        self.assertEqual(120, runtime._get_autosave_interval_seconds())

        runtime.settings = SimpleNamespace(general_notes_autosave_minutes="0")
        self.assertEqual(0, runtime._get_autosave_interval_seconds())

        runtime.settings = SimpleNamespace(general_notes_autosave_minutes="bad")
        self.assertEqual(120, runtime._get_autosave_interval_seconds())

    def test_resolve_autosave_target_path_for_temp_and_non_temp_projects(self):
        from app.web.runtime import WebRuntime
        from app.paths import get_legion_autosave_dir

        runtime = WebRuntime.__new__(WebRuntime)

        temp_project = SimpleNamespace(
            properties=SimpleNamespace(
                projectName="/tmp/legion-temp.legion",
                isTemporary=True,
            )
        )
        non_temp_project = SimpleNamespace(
            properties=SimpleNamespace(
                projectName="/opt/projects/client-a.legion",
                isTemporary=False,
            )
        )

        temp_path = runtime._resolve_autosave_target_path(temp_project)
        non_temp_path = runtime._resolve_autosave_target_path(non_temp_project)

        self.assertTrue(temp_path.endswith(".autosave.legion"))
        self.assertIn(get_legion_autosave_dir(), temp_path)
        self.assertEqual("/opt/projects/client-a.autosave.legion", non_temp_path)


if __name__ == "__main__":
    unittest.main()
