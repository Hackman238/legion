import os
import subprocess
import sys
import tempfile
import unittest


class LegionLogPathsTest(unittest.TestCase):
    """The log directory is resolved once at import and never stops Legion from starting."""

    def test_log_directory_exists_and_holds_the_log_paths(self):
        from app.logging import legionLog

        self.assertTrue(os.path.isdir(legionLog.cache_path))
        self.assertEqual(legionLog.cache_path, os.path.dirname(legionLog.log_path))

    def test_unwritable_log_directory_falls_back_instead_of_crashing_at_import(self):
        # A directory that cannot be created: a path below a regular file.
        with tempfile.NamedTemporaryFile() as blocker:
            env = dict(os.environ)
            env["LEGION_LOG_DIR"] = os.path.join(blocker.name, "log")
            result = subprocess.run(
                [sys.executable, "-c", "from app.logging import legionLog; print(legionLog.cache_path)"],
                capture_output=True, text=True, env=env, cwd=os.getcwd(), timeout=60,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        fallback = result.stdout.strip()
        self.assertTrue(fallback.startswith(tempfile.gettempdir()), fallback)
        self.assertTrue(os.path.isdir(fallback))

    def test_log_directory_override_is_honoured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wanted = os.path.join(tmpdir, "legion-logs")
            env = dict(os.environ)
            env["LEGION_LOG_DIR"] = wanted
            result = subprocess.run(
                [sys.executable, "-c", "from app.logging import legionLog; print(legionLog.cache_path)"],
                capture_output=True, text=True, env=env, cwd=os.getcwd(), timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(wanted, result.stdout.strip())
            self.assertTrue(os.path.isdir(wanted))


if __name__ == "__main__":
    unittest.main()
