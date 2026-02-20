import os
import tempfile
import unittest
from unittest.mock import patch


class SchedulerConfigManagerTest(unittest.TestCase):
    def test_default_config_path_uses_legion_home_override(self):
        from app.scheduler.config import get_default_scheduler_config_path

        with tempfile.TemporaryDirectory() as tmpdir:
            legion_home = os.path.join(tmpdir, "legion-dev-home")
            with patch.dict(os.environ, {"LEGION_HOME": legion_home}, clear=False):
                path = get_default_scheduler_config_path()

            self.assertEqual(os.path.join(legion_home, "scheduler-ai.json"), path)
            self.assertTrue(os.path.isdir(legion_home))

    def test_load_update_and_approve_family(self):
        from app.scheduler.config import SchedulerConfigManager

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "scheduler-ai.json")
            manager = SchedulerConfigManager(config_path=path)

            defaults = manager.load()
            self.assertEqual("deterministic", defaults["mode"])
            self.assertEqual("internal_asset_discovery", defaults["goal_profile"])
            self.assertEqual(1, int(defaults["max_concurrency"]))
            self.assertEqual(200, int(defaults["max_jobs"]))
            self.assertIn("ai_feedback", defaults)
            self.assertTrue(defaults["ai_feedback"]["enabled"])
            self.assertEqual(4, int(defaults["ai_feedback"]["max_actions_per_round"]))
            self.assertEqual("gpt-4.1-mini", defaults["providers"]["openai"]["model"])
            self.assertIn("project_report_delivery", defaults)
            self.assertEqual("POST", defaults["project_report_delivery"]["method"])
            self.assertEqual("json", defaults["project_report_delivery"]["format"])

            updated = manager.update_preferences({
                "mode": "ai",
                "goal_profile": "external_pentest",
                "provider": "openai",
                "providers": {
                    "openai": {
                        "enabled": True,
                        "model": "gpt-5-mini",
                        "api_key": "test-key",
                    }
                },
            })
            self.assertEqual("ai", updated["mode"])
            self.assertEqual("external_pentest", updated["goal_profile"])
            self.assertEqual("openai", updated["provider"])
            self.assertEqual(1, int(updated["max_concurrency"]))
            self.assertEqual("gpt-5-mini", updated["providers"]["openai"]["model"])
            self.assertEqual(4, int(updated["ai_feedback"]["max_rounds_per_target"]))

            normalized_openai_model = manager.update_preferences({
                "providers": {
                    "openai": {
                        "model": "",
                    }
                },
            })
            self.assertEqual("gpt-4.1-mini", normalized_openai_model["providers"]["openai"]["model"])

            updated_concurrency = manager.update_preferences({
                "max_concurrency": 99,
            })
            self.assertEqual(16, int(updated_concurrency["max_concurrency"]))

            updated_jobs = manager.update_preferences({
                "max_jobs": 99999,
            })
            self.assertEqual(2000, int(updated_jobs["max_jobs"]))

            updated_delivery = manager.update_preferences({
                "project_report_delivery": {
                    "provider_name": "siem-prod",
                    "endpoint": "https://example.local/report",
                    "method": "delete",
                    "format": "markdown",
                    "headers": {"Authorization": "Bearer token"},
                    "timeout_seconds": 999,
                    "mtls": {
                        "enabled": True,
                        "client_cert_path": "/tmp/client.crt",
                        "client_key_path": "/tmp/client.key",
                        "ca_cert_path": "/tmp/ca.crt",
                    },
                }
            })
            delivery = updated_delivery["project_report_delivery"]
            self.assertEqual("siem-prod", delivery["provider_name"])
            self.assertEqual("https://example.local/report", delivery["endpoint"])
            self.assertEqual("POST", delivery["method"])
            self.assertEqual("md", delivery["format"])
            self.assertEqual("Bearer token", delivery["headers"]["Authorization"])
            self.assertEqual(300, int(delivery["timeout_seconds"]))
            self.assertTrue(delivery["mtls"]["enabled"])

            normalized = manager.update_preferences({
                "ai_feedback": {
                    "enabled": True,
                    "max_rounds_per_target": 99,
                    "max_actions_per_round": 0,
                    "recent_output_chars": 10,
                }
            })
            self.assertEqual(12, int(normalized["ai_feedback"]["max_rounds_per_target"]))
            self.assertEqual(1, int(normalized["ai_feedback"]["max_actions_per_round"]))
            self.assertEqual(320, int(normalized["ai_feedback"]["recent_output_chars"]))

            self.assertFalse(manager.is_family_preapproved("abc123"))
            manager.approve_family("abc123", {"tool_id": "hydra", "label": "Hydra", "danger_categories": []})
            self.assertTrue(manager.is_family_preapproved("abc123"))


if __name__ == "__main__":
    unittest.main()
