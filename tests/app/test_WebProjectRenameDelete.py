import os
import tempfile
import threading
import unittest
from types import SimpleNamespace


class _Runtime:
    def __init__(self, current_path=""):
        self._lock = threading.RLock()
        self.current_path = current_path
        self.logic = SimpleNamespace(activeProject=None)
        self._autosave_last_saved_at = ""
        self._autosave_last_path = ""
        self._autosave_last_error = ""


class ProjectRenameDeleteTest(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = os.path.join(self.tmp.name, "engagement.legion")
        with open(self.project, "wb") as handle:
            handle.write(b"sqlite")
        self.output_dir = os.path.join(self.tmp.name, "engagement-tool-output")
        os.makedirs(os.path.join(self.output_dir, "screenshots"))
        with open(os.path.join(self.output_dir, "legion-usernames.txt"), "w") as handle:
            handle.write("admin\n")
        self.runtime = _Runtime()
        # project_metadata reads the active project; pretend none is open unless a test says otherwise
        self._meta = patch("app.web.runtime_projects.project_metadata", side_effect=lambda runtime: {"name": runtime.current_path})
        self._meta.start()
        self.addCleanup(self._meta.stop)

    def test_rename_moves_file_and_tool_output_folder(self):
        from app.web.runtime_projects import rename_project

        row = rename_project(self.runtime, self.project, "client-a")
        renamed = os.path.join(self.tmp.name, "client-a.legion")
        self.assertEqual(renamed, row["path"])
        self.assertEqual("client-a.legion", row["name"])
        self.assertEqual(self.project, row["previous_path"])
        self.assertTrue(os.path.isfile(renamed))
        self.assertFalse(os.path.exists(self.project))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp.name, "client-a-tool-output", "legion-usernames.txt")))
        self.assertFalse(os.path.exists(self.output_dir))

    def test_rename_rejects_paths_bad_names_and_collisions(self):
        from app.web.runtime_projects import rename_project

        with self.assertRaises(ValueError):
            rename_project(self.runtime, self.project, "../escape")
        with self.assertRaises(ValueError):
            rename_project(self.runtime, self.project, "bad;name")
        with open(os.path.join(self.tmp.name, "taken.legion"), "wb") as handle:
            handle.write(b"x")
        with self.assertRaises(FileExistsError):
            rename_project(self.runtime, self.project, "taken")
        with self.assertRaises(FileNotFoundError):
            rename_project(self.runtime, os.path.join(self.tmp.name, "missing.legion"), "x")
        self.assertTrue(os.path.isfile(self.project))

    def test_rename_refuses_when_target_tool_output_folder_exists(self):
        from app.web.runtime_projects import rename_project

        os.makedirs(os.path.join(self.tmp.name, "client-a-tool-output"))
        with self.assertRaises(FileExistsError):
            rename_project(self.runtime, self.project, "client-a")
        # nothing moved: the project and its own output folder are untouched
        self.assertTrue(os.path.isfile(self.project))
        self.assertTrue(os.path.isdir(self.output_dir))

    def test_open_project_cannot_be_renamed_or_deleted(self):
        from app.web.runtime_projects import delete_project, rename_project

        self.runtime.current_path = self.project
        with self.assertRaises(RuntimeError):
            rename_project(self.runtime, self.project, "other")
        with self.assertRaises(RuntimeError):
            delete_project(self.runtime, self.project)
        self.assertTrue(os.path.isfile(self.project))

    def test_delete_removes_file_and_tool_output(self):
        from app.web.runtime_projects import delete_project

        result = delete_project(self.runtime, self.project)
        self.assertTrue(result["deleted"])
        self.assertIn(self.output_dir, result["removed"])
        self.assertFalse(os.path.exists(self.project))
        self.assertFalse(os.path.exists(self.output_dir))


class _RouteRuntime:
    def __init__(self):
        self.calls = []

    def rename_project(self, path, new_name):
        self.calls.append(("rename_project", path, new_name))
        if new_name == "taken":
            raise FileExistsError("exists")
        return {"name": f"{new_name}.legion", "path": f"/tmp/{new_name}.legion"}

    def delete_project(self, path):
        self.calls.append(("delete_project", path))
        if path.endswith("open.legion"):
            raise RuntimeError("That project is open right now.")
        return {"deleted": True, "path": path, "removed": [path]}


class ProjectRenameDeleteRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = _RouteRuntime()
        self.client = create_app(self.runtime).test_client()

    def test_rename_route(self):
        ok = self.client.post("/api/project/rename", json={"path": "/tmp/a.legion", "new_name": "b"})
        self.assertEqual(200, ok.status_code)
        self.assertEqual("b.legion", ok.json["project"]["name"])
        self.assertEqual(409, self.client.post("/api/project/rename", json={"path": "/tmp/a.legion", "new_name": "taken"}).status_code)
        self.assertEqual(400, self.client.post("/api/project/rename", json={"path": "/tmp/a.legion"}).status_code)

    def test_delete_route(self):
        ok = self.client.post("/api/project/delete", json={"path": "/tmp/a.legion"})
        self.assertEqual(200, ok.status_code)
        self.assertTrue(ok.json["deleted"])
        self.assertEqual(409, self.client.post("/api/project/delete", json={"path": "/tmp/open.legion"}).status_code)
        self.assertEqual(400, self.client.post("/api/project/delete", json={}).status_code)


if __name__ == "__main__":
    unittest.main()
