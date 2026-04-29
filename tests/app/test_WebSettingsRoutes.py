import unittest
from types import SimpleNamespace


class _SettingsRouteRuntime:
    def __init__(self):
        self.calls = []
        self.settings = SimpleNamespace(
            general_colorful_ascii_background=False,
            tools_path_nmap="",
            tools_path_hydra="",
            tools_path_texteditor="",
            tools_path_responder="",
            tools_path_ntlmrelay="",
            hostActions=[],
            portActions=[],
            portTerminalActions=[],
        )

    def get_snapshot(self):
        return {"scheduler": {"feature_flags": {"graph_workspace": True}}}

    def get_tool_audit(self):
        self.calls.append(("get_tool_audit",))
        return {
            "summary": {"installed": 1, "missing": 0},
            "tools": [{"label": "Nmap", "status": "installed"}],
            "supported_platforms": ["kali", "ubuntu"],
            "recommended_platform": "kali",
        }

    def get_tool_install_plan(self, platform="kali", scope="missing", tool_keys=None):
        self.calls.append(("get_tool_install_plan", str(platform), str(scope), list(tool_keys or [])))
        return {
            "platform": str(platform),
            "scope": str(scope),
            "commands": ["apt-get install nmap"],
            "script": "apt-get install nmap",
            "manual": [],
            "supported_platforms": ["kali", "ubuntu"],
        }

    def start_tool_install_job(self, platform="kali", scope="missing", tool_keys=None):
        self.calls.append(("start_tool_install_job", str(platform), str(scope), list(tool_keys or [])))
        return {
            "id": 91,
            "type": "tool-install",
            "status": "queued",
            "payload": {
                "platform": str(platform),
                "scope": str(scope),
                "tool_keys": list(tool_keys or []),
            },
        }


class WebSettingsRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = _SettingsRouteRuntime()
        self.client = create_app(self.runtime).test_client()

    def test_settings_routes_delegate_to_settings_service(self):
        display = self.client.get("/api/settings/display")
        self.assertEqual(200, display.status_code)
        self.assertFalse(display.json["colorful_ascii_background"])
        self.assertEqual("no-store, max-age=0, must-revalidate", display.headers.get("Cache-Control"))

        audit = self.client.get("/api/settings/tool-audit")
        self.assertEqual(200, audit.status_code)
        self.assertEqual("installed", audit.json["tools"][0]["status"])

        plan = self.client.get("/api/settings/tool-audit/install-plan?platform=ubuntu&scope=missing&tool_keys=nmap,nikto")
        self.assertEqual(200, plan.status_code)
        self.assertEqual("ubuntu", plan.json["platform"])

        install = self.client.post("/api/settings/tool-audit/install", json={
            "platform": "ubuntu",
            "scope": "missing",
            "tool_keys": ["nmap", "nikto"],
        })
        self.assertEqual(202, install.status_code)
        self.assertEqual("tool-install", install.json["job"]["type"])

        self.assertEqual(
            [
                ("get_tool_audit",),
                ("get_tool_install_plan", "ubuntu", "missing", ["nmap", "nikto"]),
                ("start_tool_install_job", "ubuntu", "missing", ["nmap", "nikto"]),
            ],
            [call for call in self.runtime.calls if call[0] != "get_snapshot"],
        )


if __name__ == "__main__":
    unittest.main()
