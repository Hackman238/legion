import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class HeadlessNmapFailureTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "uses a shell-script stand-in for nmap")
    def test_failed_nmap_scan_is_reported_and_export_still_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            fake_nmap = os.path.join(bin_dir, "nmap")
            with open(fake_nmap, "w") as handle:
                handle.write("#!/bin/sh\necho 'nmap: simulated failure' >&2\nexit 1\n")
            os.chmod(fake_nmap, os.stat(fake_nmap).st_mode | stat.S_IEXEC)
            targets = os.path.join(tmpdir, "targets.txt")
            with open(targets, "w") as handle:
                handle.write("10.0.0.9\n")
            output_file = os.path.join(tmpdir, "out.json")
            env = dict(
                os.environ,
                PATH=bin_dir + os.pathsep + os.environ.get("PATH", ""),
                LEGION_HOME=os.path.join(tmpdir, "home"),
                LEGION_TMPDIR=os.path.join(tmpdir, "tmp"),
                QT_QPA_PLATFORM="offscreen",
            )

            result = subprocess.run(
                [sys.executable, "legion.py", "--headless", "--input-file", targets, "--discovery",
                 "--output-file", output_file],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=180,
            )

            self.assertEqual(1, result.returncode, result.stderr[-2000:])
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn("nmap scan failed", result.stderr)
            with open(output_file, encoding="utf-8") as handle:
                exported = json.load(handle)
            self.assertEqual(["10.0.0.9"], [host["ip"] for host in exported["hosts"]])


class HeadlessLegionExportCleanupTest(unittest.TestCase):
    def test_legion_export_leaves_no_running_folder_behind(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            targets = os.path.join(tmpdir, "targets.txt")
            with open(targets, "w") as handle:
                handle.write("10.0.0.9\n")
            legion_tmp = os.path.join(tmpdir, "tmp")
            output_file = os.path.join(tmpdir, "out.legion")
            env = dict(
                os.environ,
                LEGION_HOME=os.path.join(tmpdir, "home"),
                LEGION_TMPDIR=legion_tmp,
                QT_QPA_PLATFORM="offscreen",
            )

            result = subprocess.run(
                [sys.executable, "legion.py", "--headless", "--input-file", targets, "--output-file", output_file],
                cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=180,
            )

            self.assertEqual(0, result.returncode, result.stderr[-2000:])
            self.assertTrue(os.path.isfile(output_file))
            self.assertTrue(os.path.isdir(os.path.join(tmpdir, "out-tool-output")))
            # Neither the temporary source project nor the reopened saved project may leave its
            # legion-*-running folder (or the temporary database) behind.
            self.assertEqual([], sorted(os.listdir(legion_tmp)))


if __name__ == "__main__":
    unittest.main()
