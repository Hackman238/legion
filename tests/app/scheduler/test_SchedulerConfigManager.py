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
            self.assertEqual("internal_recon", defaults["engagement_policy"]["preset"])
            self.assertEqual(1, int(defaults["max_concurrency"]))
            self.assertEqual(200, int(defaults["max_jobs"]))
            self.assertIn("ai_feedback", defaults)
            self.assertTrue(defaults["ai_feedback"]["enabled"])
            self.assertEqual(5, int(defaults["ai_feedback"]["max_rounds_per_target"]))
            self.assertEqual(6, int(defaults["ai_feedback"]["max_actions_per_round"]))
            self.assertTrue(defaults["ai_feedback"]["reflection_enabled"])
            self.assertEqual(2, int(defaults["ai_feedback"]["stall_rounds_without_progress"]))
            self.assertEqual(2, int(defaults["ai_feedback"]["stall_repeat_selection_threshold"]))
            self.assertEqual(1, int(defaults["ai_feedback"]["max_reflections_per_target"]))
            self.assertEqual("gpt-4.1-mini", defaults["providers"]["openai"]["model"])
            self.assertFalse(defaults["providers"]["openai"]["structured_outputs"])
            self.assertIn("feature_flags", defaults)
            self.assertTrue(defaults["feature_flags"]["graph_workspace"])
            self.assertTrue(defaults["feature_flags"]["optional_runners"])
            self.assertTrue(defaults["feature_flags"]["scheduler_prompt_profiles"])
            self.assertFalse(defaults["feature_flags"]["scheduler_web_followup_sidecar"])
            self.assertIn("disabled_tool_ids", defaults)
            self.assertIn("http-drupal-modules.nse", defaults["disabled_tool_ids"])
            self.assertIn("http-vuln-zimbra-lfi.nse", defaults["disabled_tool_ids"])
            self.assertIn("http-drupal-modules.nse", manager.get_disabled_tool_ids())
            self.assertIn("tool_execution_profiles", defaults)
            self.assertTrue(defaults["tool_execution_profiles"]["nikto"]["quiet_long_running"])
            self.assertEqual(1800, int(defaults["tool_execution_profiles"]["nikto"]["activity_timeout_seconds"]))
            self.assertEqual(0, int(defaults["tool_execution_profiles"]["nikto"]["hard_timeout_seconds"]))
            self.assertIn("runners", defaults)
            self.assertFalse(defaults["runners"]["container"]["enabled"])
            self.assertTrue(defaults["runners"]["browser"]["enabled"])
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
                        "structured_outputs": True,
                    }
                },
            })
            self.assertEqual("ai", updated["mode"])
            self.assertEqual("external_pentest", updated["goal_profile"])
            self.assertEqual("external_pentest", updated["engagement_policy"]["preset"])
            self.assertEqual("openai", updated["provider"])
            self.assertEqual(1, int(updated["max_concurrency"]))
            self.assertEqual("gpt-5-mini", updated["providers"]["openai"]["model"])
            self.assertTrue(updated["providers"]["openai"]["structured_outputs"])
            self.assertEqual(5, int(updated["ai_feedback"]["max_rounds_per_target"]))

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
                    "reflection_enabled": False,
                    "stall_rounds_without_progress": 99,
                    "stall_repeat_selection_threshold": 0,
                    "max_reflections_per_target": 99,
                }
            })
            self.assertEqual(12, int(normalized["ai_feedback"]["max_rounds_per_target"]))
            self.assertEqual(1, int(normalized["ai_feedback"]["max_actions_per_round"]))
            self.assertEqual(320, int(normalized["ai_feedback"]["recent_output_chars"]))
            self.assertFalse(normalized["ai_feedback"]["reflection_enabled"])
            self.assertEqual(6, int(normalized["ai_feedback"]["stall_rounds_without_progress"]))
            self.assertEqual(1, int(normalized["ai_feedback"]["stall_repeat_selection_threshold"]))
            self.assertEqual(4, int(normalized["ai_feedback"]["max_reflections_per_target"]))

            updated_runners = manager.update_preferences({
                "runners": {
                    "container": {
                        "enabled": True,
                        "runtime": "podman",
                        "image": "kalilinux/kali-rolling",
                    },
                    "browser": {
                        "enabled": False,
                        "timeout": 9999,
                    },
                }
            })
            self.assertTrue(updated_runners["runners"]["container"]["enabled"])
            self.assertEqual("podman", updated_runners["runners"]["container"]["runtime"])
            self.assertEqual("kalilinux/kali-rolling", updated_runners["runners"]["container"]["image"])
            self.assertFalse(updated_runners["runners"]["browser"]["enabled"])
            self.assertEqual(900, int(updated_runners["runners"]["browser"]["timeout"]))

            updated_flags = manager.update_preferences({
                "feature_flags": {
                    "graph_workspace": False,
                    "optional_runners": False,
                    "scheduler_prompt_profiles": False,
                    "scheduler_web_followup_sidecar": True,
                }
            })
            self.assertFalse(updated_flags["feature_flags"]["graph_workspace"])
            self.assertFalse(updated_flags["feature_flags"]["optional_runners"])
            self.assertFalse(updated_flags["feature_flags"]["scheduler_prompt_profiles"])
            self.assertTrue(updated_flags["feature_flags"]["scheduler_web_followup_sidecar"])
            self.assertFalse(manager.is_feature_enabled("graph_workspace"))
            self.assertFalse(manager.is_feature_enabled("optional_runners"))
            self.assertFalse(manager.is_feature_enabled("scheduler_prompt_profiles"))
            self.assertTrue(manager.is_feature_enabled("scheduler_web_followup_sidecar"))

            updated_profiles = manager.update_preferences({
                "tool_execution_profiles": {
                    "nikto": {
                        "activity_timeout_seconds": 2400,
                    },
                    "feroxbuster": {
                        "quiet_long_running": True,
                        "activity_timeout_seconds": 900,
                        "hard_timeout_seconds": 7200,
                    },
                }
            })
            self.assertEqual(2400, int(updated_profiles["tool_execution_profiles"]["nikto"]["activity_timeout_seconds"]))
            self.assertTrue(updated_profiles["tool_execution_profiles"]["feroxbuster"]["quiet_long_running"])
            self.assertEqual(900, int(updated_profiles["tool_execution_profiles"]["feroxbuster"]["activity_timeout_seconds"]))
            self.assertEqual(7200, int(updated_profiles["tool_execution_profiles"]["feroxbuster"]["hard_timeout_seconds"]))

            updated_policy = manager.update_preferences({
                "engagement_policy": {
                    "preset": "internal_pentest",
                    "intent": "pentest",
                    "allow_exploitation": True,
                    "allow_lateral_movement": True,
                }
            })
            self.assertEqual("internal_pentest", updated_policy["engagement_policy"]["preset"])
            self.assertEqual("internal_asset_discovery", updated_policy["goal_profile"])
            self.assertTrue(updated_policy["engagement_policy"]["allow_exploitation"])

            self.assertFalse(manager.is_family_preapproved("abc123"))
            manager.approve_family("abc123", {"tool_id": "hydra", "label": "Hydra", "danger_categories": []})
            self.assertTrue(manager.is_family_preapproved("abc123"))
            self.assertEqual("allowed", manager.get_family_policy_state("abc123"))

            manager.require_family_approval("abc123", {"tool_id": "hydra", "label": "Hydra"}, reason="manual review")
            self.assertEqual("approval_required", manager.get_family_policy_state("abc123"))
            self.assertFalse(manager.is_family_preapproved("abc123"))

            manager.suppress_family("abc123", {"tool_id": "hydra", "label": "Hydra"}, reason="too noisy")
            self.assertEqual("suppressed", manager.get_family_policy_state("abc123"))

            manager.block_family("abc123", {"tool_id": "hydra", "label": "Hydra"}, reason="out of scope")
            self.assertEqual("blocked", manager.get_family_policy_state("abc123"))


if __name__ == "__main__":
    unittest.main()
