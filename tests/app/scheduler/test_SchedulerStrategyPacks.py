import unittest


class SchedulerStrategyPacksTest(unittest.TestCase):
    def test_select_strategy_packs_activates_web_tls_and_validation_flows(self):
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.strategy_packs import select_strategy_packs

        policy = normalize_engagement_policy({"preset": "external_pentest"})
        selected = select_strategy_packs(
            "https",
            "tcp",
            policy,
            context={
                "signals": {
                    "web_service": True,
                    "tls_detected": True,
                    "vuln_hits": 2,
                    "observed_technologies": ["wordpress", "nginx"],
                },
                "coverage": {
                    "missing": [
                        "missing_nuclei_auto",
                        "missing_whatweb",
                        "missing_deep_tls_waf_checks",
                    ],
                },
                "host_cves": [{"name": "CVE-2025-0001"}],
                "host_ai_state": {
                    "findings": [{"title": "Login panel exposed"}],
                },
            },
        )

        pack_ids = [item.pack.pack_id for item in selected]
        self.assertIn("external_surface", pack_ids)
        self.assertIn("web_app_api", pack_ids)
        self.assertIn("vuln_validation", pack_ids)
        self.assertIn("tls_and_exposure", pack_ids)

    def test_evaluate_action_strategy_marks_gap_closure_and_expected_evidence(self):
        from app.scheduler.models import ActionSpec
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.strategy_packs import evaluate_action_strategy, select_strategy_packs

        policy = normalize_engagement_policy({"preset": "external_pentest"})
        action = ActionSpec(
            action_id="sslscan",
            tool_id="sslscan",
            label="SSLScan",
            description="SSLScan",
            command_template="sslscan [IP]:[PORT]",
            service_scope=["https"],
            protocol_scope=["tcp"],
            methodology_tags=["web", "validation"],
            pack_tags=["tls_and_exposure"],
        )

        context = {
            "signals": {"web_service": True, "tls_detected": True},
            "coverage": {"missing": ["missing_deep_tls_waf_checks"]},
        }
        selections = select_strategy_packs("https", "tcp", policy, context=context)
        guidance = evaluate_action_strategy(action, selections, policy, context=context)

        self.assertIn("tls_and_exposure", guidance.pack_ids)
        self.assertEqual("missing_deep_tls_waf_checks", guidance.coverage_gap)
        self.assertTrue(guidance.coverage_notes.startswith("Closes"))
        self.assertIn("TLS posture", guidance.evidence_expectations)


if __name__ == "__main__":
    unittest.main()
