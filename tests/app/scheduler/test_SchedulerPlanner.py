import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class SchedulerPlannerTest(unittest.TestCase):
    def test_deterministic_mode_follows_scheduler_mapping(self):
        from app.scheduler.config import SchedulerConfigManager
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
            self.assertEqual("smb-enum-users.nse", actions[0].tool_id)
            self.assertFalse(actions[0].requires_approval)

    def test_ai_mode_marks_dangerous_actions_for_approval(self):
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "dangerous_categories": ["credential_bruteforce"],
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


if __name__ == "__main__":
    unittest.main()
