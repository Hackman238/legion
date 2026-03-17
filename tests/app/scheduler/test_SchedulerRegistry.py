import unittest
from types import SimpleNamespace


class SchedulerRegistryTest(unittest.TestCase):
    def test_registry_adapts_port_actions_and_scheduler_settings_into_action_specs(self):
        from app.scheduler.registry import ActionRegistry

        settings = SimpleNamespace(
            automatedAttacks=[
                ["screenshooter", "http,https", "tcp"],
                ["smb-enum-users.nse", "smb", "tcp"],
            ],
            portActions=[
                ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http,https"],
                ["SMB Enum Users", "smb-enum-users.nse", "nmap --script=smb-enum-users [IP] -p [PORT]", "smb"],
            ],
        )

        registry = ActionRegistry.from_settings(settings, dangerous_categories=["credential_bruteforce"])
        screenshooter = registry.get_by_tool_id("screenshooter")
        nuclei = registry.get_by_tool_id("nuclei-web")
        smb_enum = registry.get_by_tool_id("smb-enum-users.nse")

        self.assertIsNotNone(screenshooter)
        self.assertIsNotNone(nuclei)
        self.assertIsNotNone(smb_enum)

        self.assertTrue(screenshooter.supports_deterministic)
        self.assertTrue(screenshooter.supports_ai_selection)
        self.assertEqual("browser", screenshooter.runner_type)
        self.assertIn("screenshot", screenshooter.artifact_types)

        self.assertTrue(nuclei.supports_ai_selection)
        self.assertFalse(nuclei.supports_deterministic)
        self.assertIn("web", nuclei.methodology_tags)
        self.assertIn("external_surface", nuclei.pack_tags)

        self.assertTrue(smb_enum.supports_deterministic)
        self.assertTrue(smb_enum.supports_ai_selection)
        self.assertEqual(["tcp"], smb_enum.protocol_scope)


if __name__ == "__main__":
    unittest.main()
