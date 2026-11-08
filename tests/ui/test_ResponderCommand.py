import os
import shlex
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui.dialogs import ResponderWidget
from ui.view import View


class ResponderCommandJoinTest(unittest.TestCase):
    def test_executable_with_arguments_is_kept_verbatim(self):
        command = ResponderWidget._joinCommand("python3 /opt/Responder/Responder.py", ["-I", "eth0", "-w", "-F"])
        self.assertEqual(
            ["python3", "/opt/Responder/Responder.py", "-I", "eth0", "-w", "-F"],
            shlex.split(command),
        )

    def test_extra_arguments_with_spaces_stay_single_tokens(self):
        command = ResponderWidget._joinCommand("ntlmrelayx.py", ["-t", "smb://10.0.0.5", "-c", "whoami /all"])
        self.assertEqual(["ntlmrelayx.py", "-t", "smb://10.0.0.5", "-c", "whoami /all"], shlex.split(command))


class ToolExecutableExistsTest(unittest.TestCase):
    # callResponder checks the configured command before running it: only its first token is the program.
    def _check(self, command):
        return View._tool_executable_exists(SimpleNamespace(), command, "Responder")

    @patch("ui.view.shutil.which", return_value="/usr/bin/python3")
    def test_command_with_arguments_checks_only_the_program(self, which):
        self.assertTrue(self._check("python3 /opt/Responder/Responder.py"))
        which.assert_called_once_with("python3")

    @patch("ui.view.os.access", return_value=True)
    @patch("ui.view.os.path.isfile", return_value=True)
    def test_absolute_program_with_arguments_checks_only_the_program(self, isfile, _access):
        self.assertTrue(self._check("/usr/bin/python3 /opt/Responder/Responder.py -v"))
        isfile.assert_called_once_with("/usr/bin/python3")


if __name__ == "__main__":
    unittest.main()
