import unittest


class FormatCommandQProcessTest(unittest.TestCase):
    def test_token_list_stays_direct_exec(self):
        from app.auxiliary import formatCommandQProcess

        program, args = formatCommandQProcess(["ls", "-la", "/tmp"])
        self.assertEqual("ls", program)
        self.assertEqual(["-la", "/tmp"], args)

    def test_plain_string_stays_direct_exec(self):
        from app.auxiliary import formatCommandQProcess

        program, args = formatCommandQProcess("ls -la /tmp")
        self.assertEqual("ls", program)
        self.assertEqual(["-la", "/tmp"], args)

    def test_missing_tool_degrades_to_shell_not_found(self):
        from app.auxiliary import formatCommandQProcess

        command = "legion-no-such-tool-xyz --log-brief=/tmp/out.txt example.com:80"
        program, args = formatCommandQProcess(command)
        self.assertEqual("/bin/sh", program)
        self.assertEqual(["-c", command], args)

        program, args = formatCommandQProcess(["legion-no-such-tool-xyz", "example.com"])
        self.assertEqual("/bin/sh", program)
        self.assertEqual(["-c", "legion-no-such-tool-xyz example.com"], args)

    def test_shell_pipeline_action_goes_through_sh(self):
        from app.auxiliary import formatCommandQProcess

        command = (
            "(command -v feroxbuster >/dev/null 2>&1 && "
            "feroxbuster -u https://example.com:8080 -k --silent -o out.txt) "
            "|| echo feroxbuster/gobuster not found"
        )
        program, args = formatCommandQProcess(command)
        self.assertEqual("/bin/sh", program)
        self.assertEqual(["-c", command], args)

    def test_redirect_and_var_expansion_go_through_sh(self):
        from app.auxiliary import formatCommandQProcess

        for command in (
            "whatweb http://example.com > out.txt",
            'gobuster dir -u http://example.com/ -w "${WL}"',
            "if command -v ffuf >/dev/null 2>&1; then ffuf -u http://example.com/FUZZ; fi",
        ):
            with self.subTest(command=command):
                program, args = formatCommandQProcess(command)
                self.assertEqual("/bin/sh", program)
                self.assertEqual(["-c", command], args)

    def test_myqprocess_child_stdin_is_not_an_open_pipe(self):
        # Tools that read targets from a piped stdin (katana) blocked
        # forever because Legion never writes to or closes the pipe.
        # A child reading stdin to EOF must finish immediately.
        import os
        import time
        from unittest.mock import Mock

        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication

        from app.auxiliary import MyQProcess

        app = QApplication.instance() or QApplication([])
        proc = MyQProcess(
            "cat", "cat", "127.0.0.1", "", "tcp", "cat", "now", "", Mock()
        )
        finished = []
        proc.finished.connect(lambda code, status: finished.append(code))
        proc.start("cat", [])
        deadline = time.time() + 10
        while not finished and time.time() < deadline:
            app.processEvents()
            time.sleep(0.05)
        self.assertEqual([0], finished, "child blocked reading stdin (open pipe)")

    def test_empty_command(self):
        from app.auxiliary import formatCommandQProcess

        self.assertEqual(("", []), formatCommandQProcess(""))
        self.assertEqual(("", []), formatCommandQProcess([]))
        self.assertEqual(("", []), formatCommandQProcess(None))


if __name__ == "__main__":
    unittest.main()
