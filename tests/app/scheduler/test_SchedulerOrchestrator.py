import unittest
from types import SimpleNamespace


class _ConfigStub:
    def __init__(self):
        self.state = {
            "mode": "deterministic",
            "max_concurrency": 2,
            "ai_feedback": {
                "enabled": True,
                "max_rounds_per_target": 4,
                "max_actions_per_round": 2,
                "recent_output_chars": 900,
            },
            "engagement_policy": {"preset": "internal_recon"},
            "goal_profile": "internal_asset_discovery",
        }

    def load(self):
        return dict(self.state)


class _PlannerStub:
    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.calls = []

    def plan_actions(self, service, protocol, settings, **kwargs):
        self.calls.append({
            "service": service,
            "protocol": protocol,
            "settings": settings,
            **kwargs,
        })
        return list(self.decisions)

    def get_last_provider_payload(self, clear=False):
        _ = clear
        return {"provider": "stub"}


class SchedulerOrchestratorTest(unittest.TestCase):
    def test_build_run_options_clamps_feedback_and_dig_deeper(self):
        from app.scheduler.orchestrator import SchedulerOrchestrator

        orchestrator = SchedulerOrchestrator(_ConfigStub(), planner=_PlannerStub([]))
        options = orchestrator.build_run_options(
            {
                "mode": "ai",
                "max_concurrency": 20,
                "ai_feedback": {
                    "enabled": True,
                    "max_rounds_per_target": 99,
                    "max_actions_per_round": 1,
                    "recent_output_chars": 100,
                },
            },
            dig_deeper=True,
        )

        self.assertEqual("ai", options.scheduler_mode)
        self.assertEqual(16, options.scheduler_concurrency)
        self.assertTrue(options.ai_feedback_enabled)
        self.assertGreaterEqual(options.max_rounds, 4)
        self.assertGreaterEqual(options.max_actions_per_round, 3)
        self.assertEqual(1600, options.recent_output_chars)
        self.assertTrue(options.dig_deeper)

    def test_run_targets_routes_blocked_approval_and_execution_through_callbacks(self):
        from app.scheduler.models import PlanStep
        from app.scheduler.orchestrator import (
            SchedulerDecisionDisposition,
            SchedulerExecutionTask,
            SchedulerOrchestrator,
            SchedulerRunOptions,
            SchedulerTarget,
        )

        blocked = PlanStep.from_legacy_fields(
            tool_id="hydra",
            label="Hydra",
            command_template="hydra [IP]",
            protocol="tcp",
            score=1,
            rationale="blocked test",
            mode="deterministic",
            goal_profile="internal_asset_discovery",
            family_id="fam-blocked",
            danger_categories=["credential_bruteforce"],
            approval_state="blocked",
            policy_reason="blocked by policy",
        )
        approval = PlanStep.from_legacy_fields(
            tool_id="nuclei-web",
            label="Nuclei",
            command_template="nuclei -u http://[IP]:[PORT]",
            protocol="tcp",
            score=2,
            rationale="approval test",
            mode="deterministic",
            goal_profile="external_pentest",
            family_id="fam-approval",
            danger_categories=["exploit_execution"],
            approval_state="approval_required",
            policy_reason="approval required",
        )
        allowed = PlanStep.from_legacy_fields(
            tool_id="whatweb",
            label="WhatWeb",
            command_template="whatweb http://[IP]:[PORT]",
            protocol="tcp",
            score=3,
            rationale="allowed test",
            mode="deterministic",
            goal_profile="external_recon",
            family_id="fam-allowed",
            danger_categories=[],
            approval_state="not_required",
        )

        planner = _PlannerStub([blocked, approval, allowed])
        orchestrator = SchedulerOrchestrator(_ConfigStub(), planner=planner)
        target = SchedulerTarget(host_id=11, host_ip="10.0.0.5", hostname="demo", port="80", protocol="tcp", service_name="http")

        blocked_events = []
        approval_events = []
        executed_events = []

        def handle_blocked(**kwargs):
            blocked_events.append(kwargs["decision"].tool_id)
            return SchedulerDecisionDisposition(action="skipped", reason="blocked")

        def handle_approval(**kwargs):
            approval_events.append(kwargs["decision"].tool_id)
            return SchedulerDecisionDisposition(action="execute", approval_id=77, reason="approved inline")

        def execute_batch(tasks, max_concurrency):
            self.assertEqual(2, max_concurrency)
            self.assertEqual(2, len(tasks))
            for item in tasks:
                self.assertIsInstance(item, SchedulerExecutionTask)
            return [
                {
                    "decision": task.decision,
                    "tool_id": task.tool_id,
                    "executed": True,
                    "reason": "queued",
                    "process_id": 0,
                    "execution_record": None,
                    "approval_id": int(task.approval_id or 0),
                }
                for task in tasks
            ]

        def on_execution_result(**kwargs):
            executed_events.append((kwargs["decision"].tool_id, kwargs["result"].get("approval_id", 0)))

        summary = orchestrator.run_targets(
            settings=SimpleNamespace(portActions=[]),
            targets=[target],
            engagement_policy={"preset": "external_pentest"},
            options=SchedulerRunOptions(
                scheduler_mode="deterministic",
                scheduler_concurrency=2,
                ai_feedback_enabled=False,
                max_rounds=1,
                max_actions_per_round=0,
            ),
            handle_blocked=handle_blocked,
            handle_approval=handle_approval,
            execute_batch=execute_batch,
            on_execution_result=on_execution_result,
        )

        self.assertEqual(["hydra"], blocked_events)
        self.assertEqual(["nuclei-web"], approval_events)
        self.assertEqual([("nuclei-web", 77), ("whatweb", 0)], executed_events)
        self.assertEqual(3, summary["considered"])
        self.assertEqual(0, summary["approval_queued"])
        self.assertEqual(2, summary["executed"])
        self.assertEqual(1, summary["skipped"])


if __name__ == "__main__":
    unittest.main()
