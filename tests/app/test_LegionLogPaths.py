import os
import subprocess
import sys
import tempfile
import unittest


class LegionLogImportTest(unittest.TestCase):
    """The loggers are console-only: importing them needs no writable home or cache directory."""

    def test_import_and_logger_creation_need_no_writable_home(self):
        # HOME below a regular file: nothing under it can be created.
        with tempfile.NamedTemporaryFile() as blocker:
            env = dict(os.environ)
            env["HOME"] = os.path.join(blocker.name, "home")
            env["XDG_CACHE_HOME"] = os.path.join(blocker.name, "cache")
            result = subprocess.run(
                [sys.executable, "-c",
                 "from app.logging.legionLog import getAppLogger, getDbLogger, getStartupLogger; "
                 "getAppLogger().info('x'); getDbLogger(); getStartupLogger(); print('ok')"],
                capture_output=True, text=True, env=env, cwd=os.getcwd(), timeout=60,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("ok", result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
