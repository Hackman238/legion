import os
import stat
import tempfile
import unittest


class ToolingEnvTest(unittest.TestCase):
    def test_build_tool_execution_env_prepends_go_bin_directory(self):
        from app.tooling import build_tool_execution_env

        env = build_tool_execution_env({
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/local/bin:/usr/bin",
            "GOBIN": "",
            "GOPATH": "",
        })

        path_parts = env["PATH"].split(os.pathsep)
        self.assertEqual("/tmp/legion-home/go/bin", path_parts[0])
        self.assertIn("/usr/local/bin", path_parts)
        self.assertIn("/usr/bin", path_parts)

    def test_build_tool_execution_env_prefers_configured_gobin(self):
        from app.tooling import build_tool_execution_env

        env = build_tool_execution_env({
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/bin",
            "GOBIN": "/opt/projectdiscovery/bin",
            "GOPATH": "/workspace/go",
        })

        path_parts = env["PATH"].split(os.pathsep)
        self.assertEqual("/opt/projectdiscovery/bin", path_parts[0])
        self.assertIn("/workspace/go/bin", path_parts)
        self.assertIn("/tmp/legion-home/go/bin", path_parts)

    def test_audit_legion_tools_resolves_path_and_configured_tool(self):
        from app.tooling import audit_legion_tools

        class StubSettings:
            tools_path_nmap = "/tmp/does-not-exist"
            tools_path_hydra = ""
            tools_path_texteditor = ""
            tools_path_responder = ""
            tools_path_ntlmrelay = ""
            hostActions = []
            portActions = []
            portTerminalActions = []

        with tempfile.TemporaryDirectory() as tempdir:
            nmap_path = os.path.join(tempdir, "nmap")
            hydra_path = os.path.join(tempdir, "hydra")
            for path in (nmap_path, hydra_path):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("#!/bin/sh\nexit 0\n")
                os.chmod(path, stat.S_IRWXU)

            settings = StubSettings()
            settings.tools_path_nmap = nmap_path
            rows = audit_legion_tools(settings, base_env={
                "HOME": tempdir,
                "PATH": tempdir,
                "GOBIN": "",
                "GOPATH": "",
            })
            by_key = {row.key: row for row in rows}
            self.assertEqual("installed", by_key["nmap"].status)
            self.assertEqual(nmap_path, by_key["nmap"].resolved_path)
            self.assertEqual("installed", by_key["hydra"].status)
            self.assertEqual(hydra_path, by_key["hydra"].resolved_path)

    def test_audit_legion_tools_discovers_custom_command_v_tools(self):
        from app.tooling import audit_legion_tools

        class StubSettings:
            tools_path_nmap = ""
            tools_path_hydra = ""
            tools_path_texteditor = ""
            tools_path_responder = ""
            tools_path_ntlmrelay = ""
            hostActions = []
            portTerminalActions = []
            portActions = [
                ["Custom scan", "customscan", "(command -v customscan >/dev/null 2>&1 && customscan [IP]) || echo customscan not found", "http"]
            ]

        rows = audit_legion_tools(StubSettings(), base_env={
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/bin",
            "GOBIN": "",
            "GOPATH": "",
        })
        by_key = {row.key: row for row in rows}
        self.assertIn("customscan", by_key)
        self.assertEqual("custom", by_key["customscan"].category)
        self.assertEqual("missing", by_key["customscan"].status)


if __name__ == "__main__":
    unittest.main()
