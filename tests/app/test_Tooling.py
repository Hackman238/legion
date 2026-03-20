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

    def test_build_tool_install_plan_rewrites_kali_apt_commands(self):
        from app.tooling import ToolAuditEntry, build_tool_install_plan

        rows = [
            ToolAuditEntry(
                key="nmap",
                label="Nmap",
                category="core",
                purpose="scan",
                status="missing",
                resolved_path="",
                resolved_command="",
                configured_value="",
                kali_install="sudo apt install nmap",
                ubuntu_install="sudo apt install nmap",
                notes="",
                optional=False,
            ),
            ToolAuditEntry(
                key="httpx",
                label="httpx",
                category="planned",
                purpose="http probing",
                status="missing",
                resolved_path="",
                resolved_command="",
                configured_value="",
                kali_install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                ubuntu_install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                notes="",
                optional=True,
            ),
        ]

        plan = build_tool_install_plan(rows, platform="kali")
        self.assertEqual("kali", plan["platform"])
        self.assertEqual(2, plan["command_count"])
        commands = [item["command"] for item in plan["commands"]]
        self.assertIn("sudo -n apt-get install -y nmap", commands)
        self.assertIn("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", commands)
        self.assertIn("# Generated by Legion Tool Audit", plan["script"])

    def test_detect_supported_tool_install_platform_prefers_os_release(self):
        from app.tooling import detect_supported_tool_install_platform

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("ID=ubuntu\nID_LIKE=debian\n")
            path = handle.name
        try:
            detected = detect_supported_tool_install_platform(os_release_path=path, base_env={})
        finally:
            os.remove(path)
        self.assertEqual("ubuntu", detected)

    def test_build_tool_install_plan_bootstraps_go_when_missing(self):
        from app.tooling import ToolAuditEntry, build_tool_install_plan

        rows = [
            ToolAuditEntry(
                key="httpx",
                label="httpx",
                category="planned",
                purpose="http probing",
                status="missing",
                resolved_path="",
                resolved_command="",
                configured_value="",
                kali_install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                ubuntu_install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                notes="",
                optional=True,
            ),
        ]

        plan = build_tool_install_plan(rows, platform="kali", base_env={
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/local/sbin",
            "GOBIN": "",
            "GOPATH": "",
        })
        commands = [item["command"] for item in plan["commands"]]
        self.assertEqual("sudo -n apt-get install -y golang-go", commands[0])
        self.assertIn("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", commands[1])

    def test_execute_tool_install_plan_runs_commands(self):
        from app.tooling import execute_tool_install_plan

        plan = {
            "platform": "kali",
            "scope": "missing",
            "commands": [
                {"label": "Echo", "tool_key": "echo", "command": "printf 'legion-tool-test'"},
            ],
            "manual": [],
            "script": "#!/usr/bin/env bash\nprintf 'legion-tool-test'\n",
        }
        result = execute_tool_install_plan(plan, base_env={
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/bin:/bin",
            "GOBIN": "",
            "GOPATH": "",
        })
        self.assertEqual(1, result["command_count"])
        self.assertEqual(1, len(result["completed_commands"]))
        self.assertEqual(0, result["completed_commands"][0]["exit_code"])
        self.assertIn("legion-tool-test", result["completed_commands"][0]["stdout_tail"])


if __name__ == "__main__":
    unittest.main()
