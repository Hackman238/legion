import os
import re
import shutil
import subprocess
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))


class LegionConfScriptsTest(unittest.TestCase):
    """Every bundled script the shipped legion.conf runs exists, so an action never fails with 'No such file'."""

    def _referenced_scripts(self):
        with open(os.path.join(REPO, "legion.conf"), encoding="utf-8") as handle:
            text = handle.read()
        return sorted(set(re.findall(r"(?<![\w\[])\.?/?scripts/[A-Za-z0-9_./-]+", text)))

    def test_every_unconditionally_referenced_script_exists(self):
        with open(os.path.join(REPO, "legion.conf"), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        missing = []
        for line in lines:
            for ref in re.findall(r"(?<![\w\[])\.?/?scripts/[A-Za-z0-9_./-]+", line):
                path = os.path.join(REPO, ref.lstrip("./"))
                # A guarded reference ([ -f scripts/x ] && ...) may legitimately point at an optional file.
                guarded = f"-f {ref}" in line or f"-f ./{ref.lstrip('./')}" in line
                if not os.path.exists(path) and not guarded:
                    missing.append(ref)
        self.assertEqual([], sorted(set(missing)))

    def test_bundled_shell_scripts_are_executable_and_parse(self):
        for ref in self._referenced_scripts():
            path = os.path.join(REPO, ref.lstrip("./"))
            if not os.path.exists(path) or not path.endswith(".sh"):
                continue
            self.assertTrue(os.access(path, os.X_OK), f"{ref} is not executable")
            result = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_smbenum_never_waits_on_stdin_and_finishes_without_tools(self):
        script = os.path.join(REPO, "scripts", "smbenum.sh")
        with open(script, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("</dev/null", text)
        self.assertIn("timeout", text)
        for forbidden in ("hydra", "msfconsole", "ms08"):  # enumeration only; attacks are approval-gated actions
            self.assertNotIn(forbidden, text)
        bash = shutil.which("bash")
        # An empty PATH: every enumeration tool is "missing", so the wrapper must skip each step and still finish.
        result = subprocess.run(
            [bash, script, "192.0.2.1"], capture_output=True, text=True, timeout=120,
            env={"PATH": "/nonexistent", "SMBENUM_STEP_TIMEOUT": "5"},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("smbenum finished", result.stdout)
