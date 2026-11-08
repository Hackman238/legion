import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

_LEGION_JS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "app", "web", "static", "js", "legion.js"
)


@unittest.skipUnless(shutil.which("node"), "node is required to run legion.js snippets")
class LegionJsProjectSavePathTest(unittest.TestCase):
    def _render_project(self, project, current_save_path=""):
        with open(_LEGION_JS, "r", encoding="utf-8") as handle:
            source = handle.read()
        match = re.search(r"^function renderProject\(project\) \{\n.*?^\}\n", source, re.S | re.M)
        self.assertIsNotNone(match, "renderProject() not found in legion.js")
        script = "\n".join([
            "const values = {'project-save-path': %s};" % json.dumps(current_save_path),
            "function setText() {}",
            "function getValue(id) { return values[id] ?? ''; }",
            "function setValue(id, value) { values[id] = value; }",
            match.group(0),
            "renderProject(%s);" % json.dumps(project),
            "process.stdout.write(JSON.stringify(values['project-save-path']));",
        ])
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "render_project.js")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write(script)
            completed = subprocess.run(["node", script_path], capture_output=True, text=True, timeout=30)
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_temporary_project_path_is_not_prefilled_as_save_destination(self):
        temp_project = {"name": "/tmp/legion-abc123.legion", "is_temporary": True}

        self.assertEqual("", self._render_project(temp_project))
        # A stale copy of the temp path is cleared; a destination the user typed is kept.
        self.assertEqual("", self._render_project(temp_project, "/tmp/legion-abc123.legion"))
        self.assertEqual("/home/user/engagement.legion", self._render_project(temp_project, "/home/user/engagement.legion"))

    def test_saved_project_path_is_prefilled_as_save_destination(self):
        saved_project = {"name": "/home/user/engagement.legion", "is_temporary": False}

        self.assertEqual("/home/user/engagement.legion", self._render_project(saved_project))
        self.assertEqual("/home/user/other.legion", self._render_project(saved_project, "/home/user/other.legion"))


if __name__ == "__main__":
    unittest.main()
