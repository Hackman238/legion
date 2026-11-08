import unittest


class SchedulerPolicyEngineTest(unittest.TestCase):
    def test_classify_risk_tags_detects_bruteforce_and_lockout_risk(self):
        from app.scheduler.risk import classify_risk_tags

        tags = classify_risk_tags(
            "hydra -L users.txt -P pass.txt 10.0.0.5 smb",
            tool_id="smb-default",
            label="SMB Default",
            service_scope=["smb"],
        )

        self.assertIn("credential_bruteforce", tags)
        self.assertIn("account_lockout_risk", tags)

    def test_internal_recon_blocks_credential_attack(self):
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.policy_engine import evaluate_policy_for_risk_tags

        policy = normalize_engagement_policy({"preset": "internal_recon"})
        decision = evaluate_policy_for_risk_tags(
            ["credential_bruteforce", "account_lockout_risk"],
            policy,
        )

        self.assertEqual("blocked", decision.state)
        self.assertIn("credential_bruteforce", decision.legacy_danger_categories)

    def test_internal_pentest_requires_approval_for_exploit_execution(self):
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.policy_engine import evaluate_policy_for_risk_tags

        policy = normalize_engagement_policy({"preset": "internal_pentest"})
        decision = evaluate_policy_for_risk_tags(["exploit_execution"], policy)

        self.assertEqual("approval_required", decision.state)
        self.assertTrue(decision.requires_approval)

    def test_detection_risk_mode_gates_high_detection_tools(self):
        # detection_risk_mode is the engagement's tolerance for noisy tools: only "high" lets
        # high-detection tools run without approval. approval_mode="always" still gates them.
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.policy_engine import evaluate_policy_for_risk_tags

        expected = {"low": "approval_required", "medium": "approval_required", "high": "allowed"}
        for mode, state in expected.items():
            policy = normalize_engagement_policy({"preset": "internal_pentest", "detection_risk_mode": mode})
            decision = evaluate_policy_for_risk_tags(["high_detection_likelihood"], policy)
            self.assertEqual(state, decision.state, mode)

        strict = normalize_engagement_policy({
            "preset": "internal_pentest", "detection_risk_mode": "high", "approval_mode": "always",
        })
        self.assertEqual(
            "approval_required",
            evaluate_policy_for_risk_tags(["high_detection_likelihood"], strict).state,
        )

    def test_family_allow_only_bypasses_approval_required_not_blocked(self):
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.policy_engine import evaluate_policy_for_risk_tags

        recon_policy = normalize_engagement_policy({"preset": "internal_recon"})
        blocked = evaluate_policy_for_risk_tags(
            ["credential_bruteforce", "account_lockout_risk"],
            recon_policy,
            family_policy_state="allowed",
        )
        self.assertEqual("blocked", blocked.state)

        pentest_policy = normalize_engagement_policy({"preset": "internal_pentest"})
        allowed = evaluate_policy_for_risk_tags(
            ["credential_bruteforce", "account_lockout_risk"],
            pentest_policy,
            family_policy_state="allowed",
        )
        self.assertEqual("allowed", allowed.state)


if __name__ == "__main__":
    unittest.main()
