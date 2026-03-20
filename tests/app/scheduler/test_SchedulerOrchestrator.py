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
    def __init__(self, decisions, provider_payloads=None):
        self.decisions = list(decisions)
        self.provider_payloads = list(provider_payloads or [])
        self.calls = []
        self.plan_calls = 0

    def plan_actions(self, service, protocol, settings, **kwargs):
        self.calls.append({
            "service": service,
            "protocol": protocol,
            "settings": settings,
            **kwargs,
        })
        if self.decisions and isinstance(self.decisions[0], list):
            index = min(self.plan_calls, len(self.decisions) - 1)
            selected = self.decisions[index]
        else:
            selected = self.decisions
        self.plan_calls += 1
        return list(selected)

    def get_last_provider_payload(self, clear=False):
        _ = clear
        if self.provider_payloads:
            index = max(0, min(self.plan_calls - 1, len(self.provider_payloads) - 1))
            return dict(self.provider_payloads[index])
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
        self.assertTrue(options.reflection_enabled)
        self.assertEqual(2, options.stall_rounds_without_progress)
        self.assertEqual(2, options.stall_repeat_selection_threshold)
        self.assertGreaterEqual(options.max_reflections_per_target, 1)
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

    def test_run_targets_uses_reflection_to_suppress_and_promote_tools_after_stall(self):
        from app.scheduler.models import PlanStep
        from app.scheduler.orchestrator import SchedulerExecutionTask, SchedulerOrchestrator, SchedulerRunOptions, SchedulerTarget

        tool_a = PlanStep.from_legacy_fields(
            tool_id="tool-a",
            label="Tool A",
            command_template="tool-a [IP]",
            protocol="tcp",
            score=1,
            rationale="round one",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-a",
        )
        tool_b = PlanStep.from_legacy_fields(
            tool_id="tool-b",
            label="Tool B",
            command_template="tool-b [IP]",
            protocol="tcp",
            score=1,
            rationale="round two",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-b",
        )
        tool_c = PlanStep.from_legacy_fields(
            tool_id="tool-c",
            label="Tool C",
            command_template="tool-c [IP]",
            protocol="tcp",
            score=1,
            rationale="round three suppressed",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-c",
        )
        tool_d = PlanStep.from_legacy_fields(
            tool_id="tool-d",
            label="Tool D",
            command_template="tool-d [IP]",
            protocol="tcp",
            score=1,
            rationale="round three promoted",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-d",
        )

        planner = _PlannerStub(
            [[tool_a], [tool_b], [tool_c, tool_d]],
            provider_payloads=[
                {"provider": "openai", "findings": [], "manual_tests": [], "technologies": [], "next_phase": ""},
                {"provider": "openai", "findings": [], "manual_tests": [], "technologies": [], "next_phase": ""},
                {"provider": "openai", "findings": [], "manual_tests": [], "technologies": [], "next_phase": ""},
            ],
        )
        orchestrator = SchedulerOrchestrator(_ConfigStub(), planner=planner)
        target = SchedulerTarget(host_id=41, host_ip="10.0.0.8", hostname="edge", port="443", protocol="tcp", service_name="https")

        executed_batches = []
        reflections = []
        persisted_reflections = []

        def build_context(**kwargs):
            _ = kwargs
            return {
                "coverage": {
                    "stage": "baseline",
                    "missing": ["missing_nmap_vuln"],
                },
                "signals": {
                    "web_service": True,
                    "tls_detected": True,
                },
            }

        def reflect_progress(**kwargs):
            reflections.append(kwargs)
            return {
                "provider": "openai",
                "state": "stalled",
                "reason": "Coverage has not changed across recent rounds.",
                "priority_shift": "coverage_first",
                "promote_tool_ids": ["tool-d"],
                "suppress_tool_ids": ["tool-c"],
                "manual_tests": [{"why": "verify auth manually", "command": "curl -k https://10.0.0.8/admin", "scope_note": "safe"}],
                "prompt_version": "scheduler-reflection-v1",
                "prompt_type": "reflection",
            }

        def on_reflection_analysis(**kwargs):
            persisted_reflections.append(kwargs["reflection_payload"])

        def execute_batch(tasks, max_concurrency):
            self.assertEqual(2, max_concurrency)
            executed_batches.append([task.tool_id for task in tasks])
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

        summary = orchestrator.run_targets(
            settings=SimpleNamespace(portActions=[]),
            targets=[target],
            engagement_policy={"preset": "external_pentest"},
            options=SchedulerRunOptions(
                scheduler_mode="ai",
                scheduler_concurrency=2,
                ai_feedback_enabled=True,
                max_rounds=3,
                max_actions_per_round=2,
                recent_output_chars=900,
                reflection_enabled=True,
                stall_rounds_without_progress=2,
                stall_repeat_selection_threshold=2,
                max_reflections_per_target=1,
            ),
            build_context=build_context,
            reflect_progress=reflect_progress,
            on_reflection_analysis=on_reflection_analysis,
            execute_batch=execute_batch,
        )

        self.assertEqual([["tool-a"], ["tool-b"], ["tool-d"]], executed_batches)
        self.assertEqual(1, len(reflections))
        self.assertEqual(2, len(reflections[0]["recent_rounds"]))
        self.assertEqual(["tool-a"], reflections[0]["recent_rounds"][0]["decision_tool_ids"])
        self.assertEqual(["tool-b"], reflections[0]["recent_rounds"][1]["decision_tool_ids"])
        self.assertEqual(1, len(persisted_reflections))
        self.assertEqual(["tool-c"], persisted_reflections[0]["suppress_tool_ids"])
        self.assertEqual(["tool-d"], persisted_reflections[0]["promote_tool_ids"])
        self.assertEqual(3, summary["executed"])
        self.assertEqual(1, summary["reflections"])
        self.assertEqual(0, summary["reflection_stops"])

    def test_run_targets_expands_whatweb_reflection_suppression_only_after_real_attempt(self):
        from app.scheduler.models import PlanStep
        from app.scheduler.orchestrator import SchedulerExecutionTask, SchedulerOrchestrator, SchedulerRunOptions, SchedulerTarget

        whatweb_http = PlanStep.from_legacy_fields(
            tool_id="whatweb-http",
            label="WhatWeb HTTP",
            command_template="whatweb http://[IP]:[PORT]",
            protocol="tcp",
            score=1,
            rationale="round one",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-whatweb",
        )
        tool_b = PlanStep.from_legacy_fields(
            tool_id="tool-b",
            label="Tool B",
            command_template="tool-b [IP]",
            protocol="tcp",
            score=1,
            rationale="round two",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-b",
        )
        whatweb = PlanStep.from_legacy_fields(
            tool_id="whatweb",
            label="WhatWeb",
            command_template="whatweb [IP]:[PORT]",
            protocol="tcp",
            score=1,
            rationale="round three should be suppressed by alias",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-whatweb",
        )
        tool_d = PlanStep.from_legacy_fields(
            tool_id="tool-d",
            label="Tool D",
            command_template="tool-d [IP]",
            protocol="tcp",
            score=1,
            rationale="round three promoted",
            mode="ai",
            goal_profile="external_pentest",
            family_id="fam-d",
        )

        planner = _PlannerStub(
            [[whatweb_http], [tool_b], [whatweb, tool_d]],
            provider_payloads=[
                {"provider": "openai", "findings": [], "manual_tests": [], "technologies": [], "next_phase": ""},
                {"provider": "openai", "findings": [], "manual_tests": [], "technologies": [], "next_phase": ""},
                {"provider": "openai", "findings": [], "manual_tests": [], "technologies": [], "next_phase": ""},
            ],
        )
        orchestrator = SchedulerOrchestrator(_ConfigStub(), planner=planner)
        target = SchedulerTarget(host_id=42, host_ip="10.0.0.9", hostname="edge", port="80", protocol="tcp", service_name="http")

        executed_batches = []

        def build_context(**kwargs):
            attempted_tool_ids = kwargs.get("attempted_tool_ids", set())
            return {
                "coverage": {
                    "stage": "post_baseline",
                    "missing": [],
                },
                "signals": {
                    "web_service": True,
                },
                "attempted_tool_ids": sorted(attempted_tool_ids),
            }

        def reflect_progress(**kwargs):
            _ = kwargs
            return {
                "provider": "openai",
                "state": "continue",
                "reason": "WhatWeb already ran on this service family.",
                "priority_shift": "targeted_followup",
                "promote_tool_ids": ["tool-d"],
                "suppress_tool_ids": ["whatweb-http"],
                "manual_tests": [],
                "prompt_version": "scheduler-reflection-v1",
                "prompt_type": "reflection",
            }

        def execute_batch(tasks, max_concurrency):
            self.assertEqual(2, max_concurrency)
            executed_batches.append([task.tool_id for task in tasks])
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

        summary = orchestrator.run_targets(
            settings=SimpleNamespace(portActions=[]),
            targets=[target],
            engagement_policy={"preset": "external_pentest"},
            options=SchedulerRunOptions(
                scheduler_mode="ai",
                scheduler_concurrency=2,
                ai_feedback_enabled=True,
                max_rounds=3,
                max_actions_per_round=2,
                recent_output_chars=900,
                reflection_enabled=True,
                stall_rounds_without_progress=2,
                stall_repeat_selection_threshold=2,
                max_reflections_per_target=1,
            ),
            build_context=build_context,
            reflect_progress=reflect_progress,
            execute_batch=execute_batch,
        )

        self.assertEqual([["whatweb-http"], ["tool-b"], ["tool-d"]], executed_batches)
        self.assertEqual(3, summary["executed"])


if __name__ == "__main__":
    unittest.main()
