import os
import tempfile
import unittest
from unittest.mock import patch

from app.web.runtime_credential_capture import NTLMRELAYX_COMMANDS, RESPONDER_COMMANDS, resolve_capture_tool


class CredentialCaptureToolResolutionTest(unittest.TestCase):
    """The configured relay tool wins when it exists; otherwise whichever packaged variant is installed runs."""

    def test_configured_path_is_used_when_it_exists(self):
        with tempfile.NamedTemporaryFile() as tool:
            self.assertEqual(tool.name, resolve_capture_tool(tool.name, NTLMRELAYX_COMMANDS))

    def test_missing_configured_name_falls_back_to_the_installed_variant(self):
        with patch("app.web.runtime_credential_capture.shutil.which",
                   side_effect=lambda name: "/usr/bin/ntlmrelayx.py" if name == "ntlmrelayx.py" else None):
            self.assertEqual("ntlmrelayx.py", resolve_capture_tool("impacket-ntlmrelayx", NTLMRELAYX_COMMANDS))
            self.assertEqual("ntlmrelayx.py", resolve_capture_tool("", NTLMRELAYX_COMMANDS))

    def test_nothing_installed_keeps_the_configured_name_for_the_error(self):
        with patch("app.web.runtime_credential_capture.shutil.which", return_value=None):
            self.assertEqual("/opt/x/ntlmrelayx.py", resolve_capture_tool("/opt/x/ntlmrelayx.py", NTLMRELAYX_COMMANDS))
            self.assertEqual("responder", resolve_capture_tool("", RESPONDER_COMMANDS))


if __name__ == "__main__":
    unittest.main()
