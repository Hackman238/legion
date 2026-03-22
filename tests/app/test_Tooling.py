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
        self.assertIn("/tmp/legion-home/.local/bin", path_parts)
        self.assertIn("/tmp/legion-home/.cargo/bin", path_parts)

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

    def test_audit_legion_tools_discovers_direct_command_tools_without_command_v(self):
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
                ["Ping timestamp", "hping3-check", "hping3 -V -C 13 -c 1 [IP]", ""],
                ["SMTP enum", "smtp-enum", "smtp-user-enum -M VRFY -t [IP] -p [PORT]", "smtp"],
            ]

        rows = audit_legion_tools(StubSettings(), base_env={
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/bin",
            "GOBIN": "",
            "GOPATH": "",
        })
        by_key = {row.key: row for row in rows}
        self.assertIn("hping3", by_key)
        self.assertEqual("legacy", by_key["hping3"].category)
        self.assertEqual("missing", by_key["hping3"].status)
        self.assertIn("smtp-user-enum", by_key)
        self.assertIn("pipx install --force smtp-user-enum", by_key["smtp-user-enum"].ubuntu_install)

    def test_audit_legion_tools_detects_user_local_impacket_entry_points(self):
        from app.tooling import audit_legion_tools

        class StubSettings:
            tools_path_nmap = ""
            tools_path_hydra = ""
            tools_path_texteditor = ""
            tools_path_responder = ""
            tools_path_ntlmrelay = ""
            hostActions = []
            portTerminalActions = []
            portActions = []

        with tempfile.TemporaryDirectory() as tempdir:
            local_bin = os.path.join(tempdir, ".local", "bin")
            os.makedirs(local_bin, exist_ok=True)
            impacket_tool = os.path.join(local_bin, "impacket-samrdump")
            with open(impacket_tool, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(impacket_tool, stat.S_IRWXU)

            rows = audit_legion_tools(StubSettings(), base_env={
                "HOME": tempdir,
                "PATH": "/usr/bin",
                "GOBIN": "",
                "GOPATH": "",
                "CARGO_HOME": "",
                "PIPX_BIN_DIR": "",
            })
            by_key = {row.key: row for row in rows}
            self.assertEqual("installed", by_key["samrdump"].status)
            self.assertEqual(impacket_tool, by_key["samrdump"].resolved_path)
            self.assertIn("pipx install --force impacket", by_key["samrdump"].ubuntu_install)

    def test_audit_legion_tools_exposes_curated_ubuntu_hints_for_nonpackaged_tools(self):
        from app.tooling import audit_legion_tools

        class StubSettings:
            tools_path_nmap = ""
            tools_path_hydra = ""
            tools_path_texteditor = ""
            tools_path_responder = ""
            tools_path_ntlmrelay = ""
            hostActions = []
            portTerminalActions = []
            portActions = []

        rows = audit_legion_tools(StubSettings(), base_env={
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/bin",
            "GOBIN": "",
            "GOPATH": "",
        })
        by_key = {row.key: row for row in rows}
        self.assertEqual("cargo install feroxbuster", by_key["feroxbuster"].ubuntu_install)
        self.assertIn("github.com/cddmp/enum4linux-ng.git", by_key["enum4linux-ng"].ubuntu_install)
        self.assertIn("github.com/CiscoCXSecurity/enum4linux.git", by_key["enum4linux"].ubuntu_install)
        self.assertIn("pipx install --force", by_key["theHarvester"].ubuntu_install)
        self.assertIn("does not mix Kali repositories into Ubuntu", by_key["snmpcheck"].ubuntu_install)
        self.assertEqual("sudo apt install testssl.sh", by_key["testssl.sh"].ubuntu_install)
        self.assertIn("github.com/Pennyw0rth/NetExec.git", by_key["netexec"].ubuntu_install)
        self.assertEqual("python3 -m pipx install --force sslyze", by_key["sslyze"].ubuntu_install)
        self.assertEqual("python3 -m pipx install --force wafw00f", by_key["wafw00f"].ubuntu_install)

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

    def test_build_tool_install_plan_bootstraps_git_cargo_and_pipx_for_ubuntu(self):
        from app.tooling import ToolAuditEntry, build_tool_install_plan

        rows = [
            ToolAuditEntry(
                key="feroxbuster",
                label="Feroxbuster",
                category="web",
                purpose="content discovery",
                status="missing",
                resolved_path="",
                resolved_command="",
                configured_value="",
                kali_install="sudo apt install feroxbuster",
                ubuntu_install="cargo install feroxbuster",
                notes="",
                optional=True,
            ),
            ToolAuditEntry(
                key="theHarvester",
                label="theHarvester",
                category="passive",
                purpose="recon",
                status="missing",
                resolved_path="",
                resolved_command="",
                configured_value="",
                kali_install="sudo apt install theharvester",
                ubuntu_install='tmpdir="$(mktemp -d)" && git clone --depth 1 https://github.com/laramies/theHarvester.git "$tmpdir/theHarvester" && python3 -m pipx install --force "$tmpdir/theHarvester"',
                notes="",
                optional=True,
            ),
        ]

        plan = build_tool_install_plan(rows, platform="ubuntu", base_env={
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/local/sbin",
            "GOBIN": "",
            "GOPATH": "",
            "CARGO_HOME": "",
            "PIPX_BIN_DIR": "",
        })
        commands = [item["command"] for item in plan["commands"]]
        self.assertIn("sudo -n apt-get install -y git", commands)
        self.assertIn("sudo -n apt-get install -y cargo", commands)
        self.assertIn("sudo -n apt-get install -y pipx python3-venv", commands)
        self.assertIn("cargo install feroxbuster", commands)
        self.assertTrue(any("python3 -m pipx install --force" in item for item in commands))

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
