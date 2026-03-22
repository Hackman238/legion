import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class SchedulerPlannerTest(unittest.TestCase):
    def test_deterministic_mode_follows_scheduler_mapping(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.models import ActionSpec, PlanStep
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({"mode": "deterministic"})
            planner = SchedulerPlanner(manager)

            settings = SimpleNamespace(
                automatedAttacks=[["smb-enum-users.nse", "smb", "tcp"]],
                portActions=[["SMB Users", "smb-enum-users.nse", "nmap --script=smb-enum-users [IP] -p [PORT]", "smb"]],
            )

            actions = planner.plan_actions("smb", "tcp", settings)
            self.assertEqual(1, len(actions))
            self.assertIsInstance(actions[0], PlanStep)
            self.assertIsInstance(actions[0].action, ActionSpec)
            self.assertEqual("smb-enum-users.nse", actions[0].tool_id)
            self.assertFalse(actions[0].requires_approval)
            self.assertEqual("smb-enum-users.nse", actions[0].action.action_id)
            self.assertTrue(actions[0].action.supports_deterministic)

    def test_plan_actions_returns_shared_plan_step_shape_for_both_modes(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.models import PlanStep
        from app.scheduler.planner import SchedulerPlanner

        settings = SimpleNamespace(
            automatedAttacks=[["nuclei-web", "http", "tcp"]],
            portActions=[
                ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "scheduler-ai.json")
            manager = SchedulerConfigManager(config_path=path)
            planner = SchedulerPlanner(manager)

            manager.update_preferences({"mode": "deterministic", "goal_profile": "internal_asset_discovery"})
            det_actions = planner.plan_actions("http", "tcp", settings)

            manager.update_preferences({"mode": "ai", "goal_profile": "external_pentest", "provider": "none"})
            ai_actions = planner.plan_actions("http", "tcp", settings)

            self.assertTrue(det_actions)
            self.assertTrue(ai_actions)
            self.assertIsInstance(det_actions[0], PlanStep)
            self.assertIsInstance(ai_actions[0], PlanStep)
            self.assertEqual("nuclei-web", det_actions[0].action_id)
            self.assertEqual("nuclei-web", ai_actions[0].action_id)
            self.assertEqual("scheduler_deterministic", det_actions[0].origin_planner)
            self.assertEqual("scheduler_ai", ai_actions[0].origin_planner)

    def test_planner_uses_normalized_engagement_policy_preset_for_plan_steps(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        settings = SimpleNamespace(
            automatedAttacks=[["nuclei-web", "http", "tcp"]],
            portActions=[
                ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "deterministic",
                "engagement_policy": {
                    "preset": "external_recon",
                    "scope": "external",
                    "intent": "recon",
                    "noise_budget": "low",
                },
            })
            planner = SchedulerPlanner(manager)

            actions = planner.plan_actions("http", "tcp", settings)

            self.assertEqual(1, len(actions))
            self.assertEqual("external_recon", actions[0].engagement_preset)
            self.assertEqual("external_pentest", actions[0].goal_profile)

    def test_plan_actions_mode_override_does_not_mutate_saved_preferences(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        settings = SimpleNamespace(
            automatedAttacks=[["nuclei-web", "http", "tcp"]],
            portActions=[
                ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({"mode": "deterministic", "provider": "none"})
            planner = SchedulerPlanner(manager)

            actions = planner.plan_actions("http", "tcp", settings, mode_override="ai")

            self.assertEqual(1, len(actions))
            self.assertEqual("deterministic", manager.load()["mode"])
            self.assertIn(actions[0].origin_mode, {"ai", "deterministic"})

    @patch.object(__import__("app.scheduler.planner", fromlist=["SchedulerPlanner"]).SchedulerPlanner, "_plan_ai")
    def test_ai_empty_result_falls_back_to_deterministic_plan_step(self, mock_plan_ai):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.models import PlanStep
        from app.scheduler.planner import SchedulerPlanner

        mock_plan_ai.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({"mode": "ai"})
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[["smb-enum-users.nse", "smb", "tcp"]],
                portActions=[["SMB Users", "smb-enum-users.nse", "nmap --script=smb-enum-users [IP]", "smb"]],
            )

            actions = planner.plan_actions("smb", "tcp", settings)

            self.assertEqual(1, len(actions))
            self.assertIsInstance(actions[0], PlanStep)
            self.assertEqual("deterministic", actions[0].origin_mode)
            self.assertEqual("scheduler_deterministic", actions[0].origin_planner)

    def test_ai_mode_marks_dangerous_actions_for_approval(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "dangerous_categories": ["credential_bruteforce"],
                "engagement_policy": {
                    "preset": "internal_pentest",
                    "intent": "pentest",
                    "credential_attack_mode": "approval",
                    "lockout_risk_mode": "approval",
                },
            })
            planner = SchedulerPlanner(manager)

            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["SMB Users", "smb-enum-users.nse", "nmap --script=smb-enum-users [IP] -p [PORT]", "smb"],
                    ["SMB Hydra", "smb-default", "hydra -s [PORT] -u root -P pass.txt [IP] smb", "smb"],
                ],
            )

            actions = planner.plan_actions("smb", "tcp", settings)
            hydra = [item for item in actions if item.tool_id == "smb-default"][0]
            self.assertTrue(hydra.requires_approval)
            self.assertIn("credential_bruteforce", hydra.danger_categories)

            manager.approve_family(
                hydra.family_id,
                {"tool_id": hydra.tool_id, "label": hydra.label, "danger_categories": hydra.danger_categories}
            )
            actions_after_approval = planner.plan_actions("smb", "tcp", settings)
            hydra_after = [item for item in actions_after_approval if item.tool_id == "smb-default"][0]
            self.assertFalse(hydra_after.requires_approval)

    def test_internal_recon_blocks_credential_attack_actions(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "deterministic",
                "engagement_policy": {"preset": "internal_recon"},
            })
            planner = SchedulerPlanner(manager)

            settings = SimpleNamespace(
                automatedAttacks=[["smb-default", "smb", "tcp"]],
                portActions=[
                    ["SMB Default", "smb-default", "hydra -s [PORT] -u root -P pass.txt [IP] smb", "smb"],
                ],
            )

            actions = planner.plan_actions("smb", "tcp", settings)

            self.assertEqual(1, len(actions))
            self.assertTrue(actions[0].is_blocked)
            self.assertEqual("blocked", actions[0].policy_decision)
            self.assertIn("credential_bruteforce", actions[0].danger_categories)

    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_uses_provider_scores_when_available(self, mock_rank_actions):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        mock_rank_actions.return_value = [
            {"tool_id": "high-signal", "score": 99, "rationale": "Provider selected this as top signal."},
            {"tool_id": "lower-signal", "score": 40, "rationale": "Lower confidence."},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "openai",
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"}
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["Lower Signal", "lower-signal", "echo low [IP]", "smb"],
                    ["High Signal", "high-signal", "echo high [IP]", "smb"],
                ],
            )

            actions = planner.plan_actions("smb", "tcp", settings)
            self.assertEqual("high-signal", actions[0].tool_id)
            self.assertEqual(99, actions[0].score)
            self.assertIn("Provider selected", actions[0].rationale)
            _, kwargs = mock_rank_actions.call_args
            self.assertIn("context", kwargs)
            self.assertEqual({}, kwargs["context"])

    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_rationale_includes_provider_failure(self, mock_rank_actions):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner
        from app.scheduler.providers import ProviderError

        mock_rank_actions.side_effect = ProviderError("connection refused")

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "lm_studio",
                "providers": {
                    "lm_studio": {
                        "enabled": True,
                        "base_url": "http://127.0.0.1:1234/v1",
                        "model": "o3-7b",
                    }
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["SMB Enum", "smb-enum-users.nse", "nmap --script smb-enum-users [IP]", "smb"],
                ],
            )

            actions = planner.plan_actions("smb", "tcp", settings)
            self.assertEqual(1, len(actions))
            self.assertIn("Provider 'lm_studio' failed", actions[0].rationale)

    def test_ai_mode_prioritizes_nuclei_and_nmap_vuln_for_http(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "external_pentest",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["HTTP Headers", "http-headers.nse", "nmap -Pn -p [PORT] --script=http-headers [IP]", "http"],
                    ["WhatWeb", "whatweb-http", "whatweb http://[IP]:[PORT]", "http"],
                    ["Nikto", "nikto", "nikto -h [IP] -p [PORT]", "http"],
                    ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                    ["nmap-vuln.nse", "nmap-vuln.nse", "nmap -Pn -n -sV -p [PORT] --script=vuln [IP]", "http"],
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                ],
            )

            actions = planner.plan_actions("http", "tcp", settings)
            tool_ids = [item.tool_id for item in actions]
            self.assertIn("nmap-vuln.nse", tool_ids)
            self.assertIn("nuclei-web", tool_ids)

    def test_ai_mode_web_baseline_includes_nuclei_vuln_and_screenshooter_for_both_profiles(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        for goal_profile in ["internal_asset_discovery", "external_pentest"]:
            with tempfile.TemporaryDirectory() as tmpdir:
                manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
                manager.update_preferences({
                    "mode": "ai",
                    "goal_profile": goal_profile,
                    "provider": "none",
                })
                planner = SchedulerPlanner(manager)
                settings = SimpleNamespace(
                    automatedAttacks=[
                        ["screenshooter", "http,https,ssl,http-proxy,http-alt,https-alt", "tcp"],
                    ],
                    portActions=[
                        ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                        ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                        ["nmap-vuln.nse", "nmap-vuln.nse", "nmap -Pn -n -sV -p [PORT] --script=vuln [IP]", "http"],
                        ["WhatWeb", "whatweb-http", "whatweb http://[IP]:[PORT]", "http"],
                    ],
                )

                actions = planner.plan_actions("http", "tcp", settings)
                tool_ids = [item.tool_id for item in actions]
                self.assertIn("nuclei-web", tool_ids)
                self.assertIn("nmap-vuln.nse", tool_ids)
                self.assertIn("screenshooter", tool_ids)

    def test_ai_mode_filters_candidates_whose_binary_is_known_missing(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["WhatWeb", "whatweb-http", "whatweb http://[IP]:[PORT]", "http"],
                    ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {
                        "web_service": True,
                        "missing_tools": ["whatweb-http"],
                    },
                    "coverage": {
                        "missing": ["missing_whatweb"],
                    },
                },
            )

            tool_ids = [item.tool_id for item in actions]
            self.assertIn("banner", tool_ids)
            self.assertNotIn("whatweb-http", tool_ids)

    def test_deterministic_mode_filters_candidates_whose_binary_is_not_available_in_tool_audit(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[
                    ["whatweb-http", "http", "tcp"],
                    ["nikto", "http", "tcp"],
                    ["banner", "http", "tcp"],
                ],
                portActions=[
                    ["WhatWeb", "whatweb-http", "whatweb http://[IP]:[PORT]", "http"],
                    ["Nikto", "nikto", "nikto -h [IP] -p [PORT]", "http"],
                    ["Banner", "banner", "LEGION_BANNER_TARGET=[IP] python3 -m app.banner_probe", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "tool_audit": {
                        "available_tool_ids": [],
                        "unavailable_tool_ids": ["whatweb", "nikto"],
                    },
                },
            )

            tool_ids = [item.tool_id for item in actions]
            self.assertIn("banner", tool_ids)
            self.assertNotIn("whatweb-http", tool_ids)
            self.assertNotIn("nikto", tool_ids)

    def test_context_recent_failures_do_not_mark_tools_unavailable_without_explicit_missing_signals(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[
                    ["whatweb-http", "http", "tcp"],
                    ["banner", "http", "tcp"],
                ],
                portActions=[
                    ["WhatWeb", "whatweb-http", "whatweb http://[IP]:[PORT]", "http"],
                    ["Banner", "banner", "LEGION_BANNER_TARGET=[IP] python3 -m app.banner_probe", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "context_summary": {
                        "recent_failures": ["whatweb-http: command not found"],
                    },
                },
            )

            tool_ids = [item.tool_id for item in actions]
            self.assertIn("whatweb-http", tool_ids)
            self.assertIn("banner", tool_ids)

    def test_ai_mode_excludes_already_attempted_tools(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "external_pentest",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[
                    ["screenshooter", "http", "tcp"],
                ],
                portActions=[
                    ["Banner", "banner", "echo | nc -v [IP] [PORT]", "http"],
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                    ["nmap-vuln.nse", "nmap-vuln.nse", "nmap --script vuln [IP] -p [PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                excluded_tool_ids=["banner", "nuclei-web"],
                limit=6,
            )
            tool_ids = [item.tool_id for item in actions]
            self.assertNotIn("banner", tool_ids)
            self.assertNotIn("nuclei-web", tool_ids)
            self.assertIn("nmap-vuln.nse", tool_ids)

    def test_planner_excludes_blacklisted_tool_ids_from_config(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "none",
                "disabled_tool_ids": ["http-drupal-modules.nse", "http-vuln-zimbra-lfi.nse"],
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["Drupal Modules", "http-drupal-modules.nse", "nmap --script http-drupal-modules.nse [IP]", "http"],
                    ["Zimbra LFI", "http-vuln-zimbra-lfi.nse", "nmap --script http-vuln-zimbra-lfi.nse [IP]", "http"],
                    ["WhatWeb", "whatweb", "whatweb http://[IP]:[PORT]", "http"],
                ],
            )

            actions = planner.plan_actions("http", "tcp", settings, limit=6)
            tool_ids = {item.tool_id for item in actions}
            self.assertNotIn("http-drupal-modules.nse", tool_ids)
            self.assertNotIn("http-vuln-zimbra-lfi.nse", tool_ids)
            self.assertIn("whatweb", tool_ids)

    def test_ai_mode_excludes_already_attempted_family_and_command_signature(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "external_pentest",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                    ["WhatWeb", "whatweb", "whatweb http://[IP]:[PORT]", "http"],
                ],
            )
            signature = SchedulerPlanner._command_signature("tcp", "nuclei -u http://[IP]:[PORT] -silent")

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                excluded_family_ids=["nuclei-web"],
                excluded_command_signatures=[signature],
                limit=6,
            )
            tool_ids = [item.tool_id for item in actions]
            self.assertNotIn("nuclei-web", tool_ids)
            self.assertIn("whatweb", tool_ids)

    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_forwards_context_to_provider(self, mock_rank_actions):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        mock_rank_actions.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "openai",
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"}
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["SMB Enum", "smb-enum-users.nse", "nmap --script smb-enum-users [IP]", "smb"],
                ],
            )
            context = {
                "target": {"host_ip": "10.0.0.5", "service": "smb"},
                "signals": {"smb_signing_disabled": True},
            }
            planner.plan_actions("smb", "tcp", settings, context=context)
            _, kwargs = mock_rank_actions.call_args
            self.assertEqual(context, kwargs["context"])

    def test_ai_candidate_filter_prunes_specialized_web_tools_without_signals(self):
        from app.scheduler.planner import SchedulerPlanner

        candidates = [
            {"tool_id": "nuclei-web", "label": "Nuclei", "command_template": "nuclei -u [IP]", "service_scope": "http"},
            {"tool_id": "nmap-vuln.nse", "label": "nmap vuln", "command_template": "nmap --script vuln [IP]", "service_scope": "http"},
            {"tool_id": "wpscan", "label": "WPScan", "command_template": "wpscan --url [IP]", "service_scope": "http"},
            {"tool_id": "http-vmware-path-vuln.nse", "label": "vmware path", "command_template": "nmap --script http-vmware-path-vuln", "service_scope": "http"},
            {"tool_id": "http-iis-webdav-vuln.nse", "label": "iis webdav", "command_template": "nmap --script http-iis-webdav-vuln", "service_scope": "http"},
            {"tool_id": "http-huawei-hg5xx-vuln.nse", "label": "huawei", "command_template": "nmap --script http-huawei-hg5xx-vuln", "service_scope": "http"},
        ]
        context = {
            "signals": {
                "web_service": True,
                "wordpress_detected": False,
                "vmware_detected": False,
                "iis_detected": False,
                "webdav_detected": False,
                "huawei_detected": False,
            }
        }

        filtered = SchedulerPlanner._filter_candidates_with_context(candidates, context)
        filtered_ids = {item["tool_id"] for item in filtered}
        self.assertIn("nuclei-web", filtered_ids)
        self.assertIn("nmap-vuln.nse", filtered_ids)
        self.assertNotIn("wpscan", filtered_ids)
        self.assertNotIn("http-vmware-path-vuln.nse", filtered_ids)
        self.assertNotIn("http-iis-webdav-vuln.nse", filtered_ids)
        self.assertNotIn("http-huawei-hg5xx-vuln.nse", filtered_ids)

    def test_ai_candidate_filter_keeps_specialized_tool_when_signal_present(self):
        from app.scheduler.planner import SchedulerPlanner

        candidates = [
            {"tool_id": "http-vmware-path-vuln.nse", "label": "vmware path", "command_template": "nmap --script http-vmware-path-vuln", "service_scope": "http"},
        ]
        filtered = SchedulerPlanner._filter_candidates_with_context(
            candidates,
            {"signals": {"vmware_detected": True}},
        )
        self.assertEqual(1, len(filtered))
        self.assertEqual("http-vmware-path-vuln.nse", filtered[0]["tool_id"])

    def test_ai_candidate_filter_generalized_vendor_token_block_and_allow(self):
        from app.scheduler.planner import SchedulerPlanner

        candidates = [
            {
                "tool_id": "http-acme-panel-vuln.nse",
                "label": "acme panel",
                "command_template": "nmap --script http-acme-panel-vuln [IP]",
                "service_scope": "http",
            },
            {
                "tool_id": "web-content-discovery",
                "label": "gobuster",
                "command_template": "gobuster dir -u http://[IP] -w /usr/share/wordlists/dirb/common.txt",
                "service_scope": "http",
            },
        ]

        no_match_context = {
            "target": {
                "service": "http",
                "service_product": "nginx",
                "service_extrainfo": "UniFi OS",
                "host_open_services": ["http", "https"],
            },
            "signals": {"web_service": True, "ubiquiti_detected": True},
        }
        filtered = SchedulerPlanner._filter_candidates_with_context(candidates, no_match_context)
        filtered_ids = {item["tool_id"] for item in filtered}
        self.assertNotIn("http-acme-panel-vuln.nse", filtered_ids)
        self.assertIn("web-content-discovery", filtered_ids)

        matched_context = {
            "target": {
                "service": "http",
                "service_product": "Acme Appliance",
                "service_extrainfo": "acme admin panel",
                "host_open_services": ["http"],
            },
            "signals": {"web_service": True},
        }
        filtered_match = SchedulerPlanner._filter_candidates_with_context(candidates, matched_context)
        filtered_match_ids = {item["tool_id"] for item in filtered_match}
        self.assertIn("http-acme-panel-vuln.nse", filtered_match_ids)
        self.assertIn("web-content-discovery", filtered_match_ids)

    def test_ai_mode_coverage_gap_prioritizes_missing_baseline_tools(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[["screenshooter", "http", "tcp"]],
                portActions=[
                    ["Banner", "banner", "echo | nc -v [IP] [PORT]", "http"],
                    ["nmap-vuln.nse", "nmap-vuln.nse", "nmap --script vuln [IP] -p [PORT]", "http"],
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                    ["whatweb", "whatweb", "whatweb [IP]:[PORT]", "http"],
                    ["nikto", "nikto", "nikto -h [IP] -p [PORT]", "http"],
                    ["web-content-discovery", "web-content-discovery", "gobuster dir -u http://[IP]:[PORT]", "http"],
                ],
            )

            context = {
                "signals": {"web_service": True},
                "coverage": {
                    "analysis_mode": "standard",
                    "stage": "baseline",
                    "missing": ["missing_screenshot", "missing_nmap_vuln", "missing_nuclei_auto"],
                    "recommended_tool_ids": ["screenshooter", "nmap-vuln.nse", "nuclei-web"],
                },
            }
            actions = planner.plan_actions("http", "tcp", settings, context=context, limit=4)
            tool_ids = [item.tool_id for item in actions]
            self.assertIn("screenshooter", tool_ids)
            self.assertIn("nmap-vuln.nse", tool_ids)
            self.assertIn("nuclei-web", tool_ids)

    def test_ai_mode_coverage_gap_prioritizes_cpe_cve_enrichment(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-cpe.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["Banner", "banner", "echo | nc -v [IP] [PORT]", "https"],
                    ["nmap-vuln.nse", "nmap-vuln.nse", "nmap --script vuln [IP] -p [PORT]", "https"],
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u https://[IP]:[PORT] -silent", "https"],
                ],
            )

            context = {
                "signals": {"web_service": True},
                "coverage": {
                    "analysis_mode": "standard",
                    "stage": "baseline",
                    "missing": ["missing_cpe_cve_enrichment"],
                    "recommended_tool_ids": ["nmap-vuln.nse", "nuclei-web"],
                },
            }
            actions = planner.plan_actions("https", "tcp", settings, context=context, limit=2)
            tool_ids = [item.tool_id for item in actions]
            self.assertIn("nmap-vuln.nse", tool_ids)
            self.assertIn("nuclei-web", tool_ids)

    def test_ai_mode_dig_deeper_promotes_targeted_nuclei_and_generic_http_follow_up(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-dig-deeper.json"))
            manager.update_preferences({
                "mode": "ai",
                "engagement_policy": {"preset": "external_pentest"},
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[["screenshooter", "http", "tcp"]],
                portActions=[
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                    ["nmap-vuln.nse", "nmap-vuln.nse", "nmap --script vuln [IP] -p [PORT]", "http"],
                    ["Run nuclei CVE follow-up", "nuclei-cves", "nuclei -tags cve -u http://[IP]:[PORT] -silent", "http"],
                    ["Run nuclei exposure follow-up", "nuclei-exposures", "nuclei -tags exposure,panel -u http://[IP]:[PORT] -silent", "http"],
                    ["WhatWeb", "whatweb", "whatweb http://[IP]:[PORT]", "http"],
                    ["Nikto", "nikto", "nikto -h [IP] -p [PORT]", "http"],
                    ["Web Discovery", "web-content-discovery", "gobuster dir -u http://[IP]:[PORT]", "http"],
                    ["HTTP Headers", "curl-headers", "curl -I http://[IP]:[PORT] > [OUTPUT].txt", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True, "vuln_hits": 2},
                    "host_cves": [{"cve": "CVE-2025-1111"}],
                    "coverage": {
                        "analysis_mode": "dig_deeper",
                        "missing": ["missing_followup_after_vuln", "missing_cpe_cve_enrichment"],
                    },
                },
            )

            tool_ids = {item.tool_id for item in actions}
            self.assertIn("nmap-vuln.nse", tool_ids)
            self.assertIn("nuclei-web", tool_ids)
            self.assertIn("nuclei-cves", tool_ids)
            self.assertIn("nuclei-exposures", tool_ids)
            self.assertIn("nikto", tool_ids)
            self.assertTrue({"whatweb", "web-content-discovery", "curl-headers"} & tool_ids)

    def test_ai_mode_dig_deeper_promotes_dirsearch_and_ffuf_for_missing_web_content_gap(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-dir-content.json"))
            manager.update_preferences({
                "mode": "ai",
                "engagement_policy": {"preset": "external_pentest"},
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[["screenshooter", "http", "tcp"]],
                portActions=[
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u [WEB_URL] -silent", "http"],
                    ["WhatWeb", "whatweb", "whatweb [WEB_URL]", "http"],
                    ["Run dirsearch", "dirsearch", "dirsearch -u [WEB_URL]/ --format=json --output=[OUTPUT].json", "http"],
                    ["Run ffuf", "ffuf", "ffuf -u [WEB_URL]/FUZZ -w /usr/share/wordlists/dirb/common.txt -s -of json -o [OUTPUT].json", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True, "vuln_hits": 1},
                    "coverage": {
                        "analysis_mode": "dig_deeper",
                        "missing": ["missing_web_content_discovery", "missing_followup_after_vuln"],
                    },
                },
            )

            tool_ids = {item.tool_id for item in actions}
            self.assertTrue({"dirsearch", "ffuf"} & tool_ids)

    def test_ai_mode_internal_safe_enum_gap_prioritizes_enum4linux_smbmap_or_rpcclient(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-internal-gap.json"))
            manager.update_preferences({
                "mode": "ai",
                "engagement_policy": {"preset": "internal_recon"},
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[
                    ["enum4linux-ng", "smb", "tcp"],
                    ["smbmap", "smb", "tcp"],
                    ["rpcclient-enum", "smb", "tcp"],
                ],
                portActions=[
                    ["Run enum4linux-ng", "enum4linux-ng", "enum4linux-ng -A -oJ [OUTPUT] [IP]", "smb"],
                    ["Run smbmap", "smbmap", "smbmap -H [IP] -P [PORT] -q --no-write-check | tee [OUTPUT].txt", "smb"],
                    ["Run rpcclient enum", "rpcclient-enum", "rpcclient [IP] -p [PORT] -U '%' -c 'srvinfo;enumdomusers' > [OUTPUT].txt", "smb"],
                    ["Banner", "banner", "echo | nc -v [IP] [PORT]", "smb"],
                ],
            )

            actions = planner.plan_actions(
                "smb",
                "tcp",
                settings,
                context={
                    "signals": {"smb_signing_disabled": True},
                    "coverage": {
                        "analysis_mode": "standard",
                        "missing": ["missing_internal_safe_enum"],
                    },
                },
                limit=3,
            )

            tool_ids = {item.tool_id for item in actions}
            self.assertTrue({"enum4linux-ng", "smbmap", "rpcclient-enum"} & tool_ids)

    def test_deterministic_mode_uses_strategy_packs_to_close_explicit_gap_when_context_exists(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-det-gap.json"))
            manager.update_preferences({
                "mode": "deterministic",
                "engagement_policy": {"preset": "external_pentest"},
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[
                    ["nikto", "http", "tcp"],
                    ["whatweb", "http", "tcp"],
                ],
                portActions=[
                    ["Nikto", "nikto", "nikto -h [IP] -p [PORT]", "http"],
                    ["WhatWeb", "whatweb", "whatweb http://[IP]:[PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True, "tls_detected": False},
                    "coverage": {"missing": ["missing_whatweb"]},
                },
            )

            self.assertEqual("whatweb", actions[0].tool_id)
            self.assertIn("web_app_api", actions[0].pack_ids)
            self.assertEqual("missing_whatweb", actions[0].coverage_gap)
            self.assertIn("web_app_api", actions[0].rationale)

    def test_ai_mode_wordpress_signal_prefers_wordpress_follow_up_and_carries_pack_metadata(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-wordpress.json"))
            manager.update_preferences({
                "mode": "ai",
                "engagement_policy": {"preset": "external_pentest"},
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["WhatWeb", "whatweb", "whatweb http://[IP]:[PORT]", "http"],
                    ["WPScan", "wpscan", "wpscan --url http://[IP]:[PORT] --no-update", "http"],
                    ["Banner", "banner", "echo | nc -v [IP] [PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {
                        "web_service": True,
                        "wordpress_detected": True,
                        "observed_technologies": ["wordpress"],
                    },
                },
                limit=3,
            )

            self.assertEqual("wpscan", actions[0].tool_id)
            self.assertIn("web_app_api", actions[0].pack_ids)
            self.assertIn("strategy packs web_app_api", actions[0].rationale)

    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_appends_strategy_pack_and_gap_context_to_provider_rationale(self, mock_rank_actions):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        mock_rank_actions.return_value = [
            {"tool_id": "sslscan", "score": 91, "rationale": "Provider selected TLS posture validation."},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-tls-pack.json"))
            manager.update_preferences({
                "mode": "ai",
                "engagement_policy": {"preset": "external_pentest"},
                "provider": "openai",
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"}
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["SSLScan", "sslscan", "sslscan [IP]:[PORT]", "https"],
                ],
            )

            actions = planner.plan_actions(
                "https",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True, "tls_detected": True},
                    "coverage": {"missing": ["missing_deep_tls_waf_checks"]},
                },
            )

            self.assertEqual("sslscan", actions[0].tool_id)
            self.assertIn("Provider selected TLS posture validation.", actions[0].rationale)
            self.assertIn("tls_and_exposure", actions[0].rationale)
            self.assertEqual("missing_deep_tls_waf_checks", actions[0].coverage_gap)

    @patch("app.scheduler.planner.select_web_followup_with_provider")
    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_web_followup_sidecar_boosts_selected_candidate_and_persists_payload(
            self,
            mock_rank_actions,
            mock_sidecar,
    ):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        mock_rank_actions.return_value = [
            {"tool_id": "banner", "score": 78, "rationale": "Provider prefers a simple banner check."},
            {"tool_id": "curl-headers", "score": 62, "rationale": "Lower initial confidence."},
        ]
        mock_sidecar.return_value = {
            "focus": "tech_validation",
            "selected_tool_ids": ["curl-headers"],
            "reason": "Reflection posture favors bounded HTTP follow-up over another generic check.",
            "manual_tests": [{"why": "Verify headers manually", "command": "curl -k -I https://10.0.0.5", "scope_note": "safe read-only"}],
            "prompt_version": "scheduler-web-followup-v1",
            "prompt_type": "web_followup",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-web-sidecar.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "openai",
                "feature_flags": {
                    "scheduler_web_followup_sidecar": True,
                },
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"}
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                    ["HTTP Headers", "curl-headers", "curl -k -I https://[IP]:[PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True},
                    "coverage": {"missing": []},
                    "context_summary": {
                        "reflection_posture": {
                            "state": "stalled",
                            "priority_shift": "targeted_followup",
                            "reason": "Repeated generic picks are no longer moving coverage.",
                        }
                    },
                },
                limit=2,
            )

            self.assertEqual("curl-headers", actions[0].tool_id)
            self.assertGreater(actions[0].score, 78)
            self.assertIn("Web follow-up specialist favored curl-headers", actions[0].rationale)
            _, kwargs = mock_sidecar.call_args
            self.assertEqual(["curl-headers"], [item["tool_id"] for item in kwargs["candidates"]])
            payload = planner.get_last_provider_payload(clear=True)
            self.assertEqual("curl-headers", payload["specialist_sidecars"][0]["selected_tool_ids"][0])
            self.assertIn("curl -k -I", payload["manual_tests"][0]["command"])

    @patch("app.scheduler.planner.select_web_followup_with_provider")
    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_skips_web_followup_sidecar_for_already_covered_broad_web_tools(
            self,
            mock_rank_actions,
            mock_sidecar,
    ):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        mock_rank_actions.return_value = [
            {"tool_id": "banner", "score": 78, "rationale": "Provider prefers a simple banner check."},
            {"tool_id": "whatweb", "score": 76, "rationale": "Re-run technology fingerprinting."},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-web-covered.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "openai",
                "feature_flags": {
                    "scheduler_web_followup_sidecar": True,
                },
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"}
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                    ["WhatWeb", "whatweb", "whatweb http://[IP]:[PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True},
                    "coverage": {
                        "missing": [],
                        "has": {
                            "whatweb": True,
                            "nikto": True,
                            "web_content_discovery": True,
                        },
                    },
                    "context_summary": {
                        "reflection_posture": {
                            "state": "continue",
                            "priority_shift": "targeted_followup",
                            "reason": "Prefer bounded follow-up only if a concrete gap remains.",
                        }
                    },
                },
                limit=2,
            )

            self.assertEqual("banner", actions[0].tool_id)
            mock_sidecar.assert_not_called()

    def test_ai_mode_abstains_when_only_remaining_strict_gap_has_no_matching_candidates(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-abstain-gap.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "openai",
                "engagement_policy": {"preset": "external_pentest"},
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"},
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["HTTP Headers", "curl-headers", "curl -I http://[IP]:[PORT]", "http"],
                    ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True},
                    "coverage": {"missing": ["missing_nikto"]},
                },
                limit=3,
            )

            self.assertEqual([], actions)

    @patch("app.scheduler.planner.rank_actions_with_provider")
    def test_ai_mode_discards_provider_rankings_that_skip_visible_gap_closer(self, mock_rank_actions):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        mock_rank_actions.return_value = [
            {"tool_id": "banner", "score": 99, "rationale": "Provider drifted toward a generic refresh."},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-gap-fallback.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "openai",
                "engagement_policy": {"preset": "external_pentest"},
                "providers": {
                    "openai": {"enabled": True, "model": "gpt-5-mini", "api_key": "x"},
                },
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[["screenshooter", "http", "tcp"]],
                portActions=[
                    ["Capture screenshot", "screenshooter", "screenshooter [WEB_URL]", "http"],
                    ["Banner", "banner", "echo | nc -v -n [IP] [PORT]", "http"],
                ],
            )

            actions = planner.plan_actions(
                "http",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True},
                    "coverage": {"missing": ["missing_screenshot"]},
                },
                limit=2,
            )

            self.assertTrue(actions)
            self.assertEqual("screenshooter", actions[0].tool_id)

    def test_ai_mode_reflection_suppression_filters_web_candidates(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai-reflection-suppress.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "none",
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[],
                portActions=[
                    ["HTTP Vulns", "nmap-vuln.nse", "nmap --script vuln [IP] -p [PORT]", "https-alt"],
                    ["WAFW00F", "wafw00f", "wafw00f https://[IP]:[PORT]", "https-alt"],
                    ["HTTP Headers", "curl-headers", "curl -k -I https://[IP]:[PORT]", "https-alt"],
                ],
            )

            actions = planner.plan_actions(
                "https-alt",
                "tcp",
                settings,
                context={
                    "signals": {"web_service": True, "waf_detected": True},
                    "coverage": {"missing": ["missing_nikto"]},
                    "context_summary": {
                        "reflection_posture": {
                            "state": "continue",
                            "priority_shift": "coverage_first",
                            "reason": "Broad vuln coverage already ran; avoid repeating it.",
                            "suppress_tool_ids": ["nmap-vuln.nse"],
                        }
                    },
                },
                limit=3,
            )

            tool_ids = [item.tool_id for item in actions]
            self.assertNotIn("nmap-vuln.nse", tool_ids)
            self.assertIn("curl-headers", tool_ids)


if __name__ == "__main__":
    unittest.main()
