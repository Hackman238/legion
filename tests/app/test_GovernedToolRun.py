import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))


def _rpc(request_id, name, arguments=None):
    return json.dumps({
        "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })


def _run_server(requests, home, cwd=REPO, operator_mode=False):
    env = {key: value for key, value in os.environ.items() if key != "LEGION_MCP_OPERATOR_MODE"}
    env.update(LEGION_HOME=home, LEGION_TMPDIR=os.path.join(home, "tmp"))
    if operator_mode:
        env["LEGION_MCP_OPERATOR_MODE"] = "1"
    completed = subprocess.run(
        [sys.executable, os.path.join(REPO, "legion.py"), "--mcp-server"],
        input=("\n".join(requests) + "\n").encode(), capture_output=True, timeout=180, cwd=cwd, env=env,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    responses = {}
    for line in completed.stdout.decode().splitlines():
        if line.strip():
            item = json.loads(line)
            result = item["result"]
            if result.get("isError"):
                responses[item["id"]] = {"error": result["content"][0]["text"]}
            else:
                responses[item["id"]] = result.get("structuredContent", result)
    return responses


class GovernedToolRunTest(unittest.TestCase):
    """An agent's run_tool goes through the engagement policy before anything executes."""

    def test_mcp_run_tool_blocks_or_queues_approval_instead_of_running_risky_tools(self):
        with tempfile.TemporaryDirectory() as home:
            responses = _run_server([
                _rpc(1, "get_engagement_policy"),
                # default internal_recon: credential attacks blocked, detection-heavy tools need approval
                _rpc(2, "run_tool", {"host_ip": "192.0.2.10", "port": "22", "tool_id": "ssh-default"}),
                _rpc(3, "run_tool", {"host_ip": "192.0.2.10", "port": "80", "tool_id": "nikto"}),
                _rpc(4, "list_approvals", {"status": "pending"}),
                _rpc(5, "list_processes"),
            ], home, cwd=home)  # started from another directory, as an MCP client would

        self.assertEqual("blocked", responses[1].get("credential_attack_mode"))
        blocked = responses[2]
        self.assertEqual("blocked", blocked["status"])
        self.assertIsNone(blocked["job"])
        self.assertIn("credential_bruteforce", blocked["policy"]["risk_tags"])
        queued = responses[3]
        self.assertEqual("approval_required", queued["status"])
        self.assertIsNone(queued["job"])
        self.assertEqual(1, len(queued["approval_ids"]))
        approvals = responses[4]["approvals"]
        self.assertEqual([("nikto", "pending")], [(item["tool_id"], item["status"]) for item in approvals])
        self.assertEqual(queued["approval_ids"][0], approvals[0]["id"])
        self.assertEqual([], responses[5].get("processes", []))  # nothing ran

    def test_the_agent_cannot_approve_its_own_request_loosen_the_policy_or_use_nmap_args_to_get_around_it(self):
        with tempfile.TemporaryDirectory() as home:
            responses = _run_server([
                _rpc(1, "run_tool", {"host_ip": "192.0.2.10", "port": "80", "tool_id": "nikto"}),
                _rpc(2, "run_tool", {"host_ip": "192.0.2.10", "port": "80", "tool_id": "nikto"}),  # asked again
                _rpc(3, "execute_approved_plan_step", {"approval_id": 1}),
                _rpc(4, "approve_approval", {"approval_id": 1, "run_now": True}),
                _rpc(5, "set_engagement_policy", {
                    "credential_attack_mode": "allowed", "lockout_risk_mode": "allowed", "approval_mode": "never"}),
                _rpc(6, "run_tool", {"host_ip": "192.0.2.10", "port": "22", "tool_id": "ssh-default"}),
                _rpc(7, "start_nmap_scan", {
                    "targets": ["192.0.2.10"], "nmap_path": "/bin/echo",
                    "nmap_args": "--script ssh-brute --script-args unsafe=1"}),
                _rpc(8, "list_approvals", {"status": "pending"}),
                _rpc(9, "list_processes"),
                _rpc(10, "list_jobs"),
                _rpc(11, "get_engagement_policy"),
            ], home)

        self.assertEqual("approval_required", responses[1]["status"])
        self.assertEqual(responses[1]["approval_ids"], responses[2]["approval_ids"])  # no duplicate request
        for refused in (responses[3], responses[4], responses[5]):
            self.assertIn("LEGION_MCP_OPERATOR_MODE", refused.get("error", ""), refused)
        self.assertIn("credential_bruteforce: blocked -> allowed", responses[5]["error"])
        self.assertEqual("blocked", responses[6]["status"])  # the policy was not changed
        self.assertEqual("blocked", responses[7]["status"])
        self.assertIsNone(responses[7]["job"])
        self.assertIn("credential_bruteforce", responses[7]["policy"]["risk_tags"])
        self.assertEqual(1, len(responses[8]["approvals"]))
        self.assertEqual("pending", responses[8]["approvals"][0]["status"])
        self.assertEqual([], responses[9].get("processes", []))
        self.assertEqual([], responses[10].get("jobs", []))  # nothing was queued, not even the scan
        self.assertEqual("blocked", responses[11]["credential_attack_mode"])
        self.assertEqual("risky", responses[11]["approval_mode"])

    def test_operator_mode_delegates_approvals_and_policy_changes(self):
        with tempfile.TemporaryDirectory() as home:
            responses = _run_server([
                _rpc(1, "run_tool", {"host_ip": "192.0.2.10", "port": "80", "tool_id": "nikto"}),
                _rpc(2, "approve_approval", {"approval_id": 1, "run_now": False}),
                _rpc(3, "set_engagement_policy", {"credential_attack_mode": "approval"}),
                _rpc(4, "set_engagement_policy", {"preset": "internal_recon"}),
            ], home, operator_mode=True)
        self.assertEqual("approval_required", responses[1]["status"])  # still asked for; the agent may now answer
        self.assertEqual("approved", responses[2]["approval"]["status"])
        self.assertEqual("approval", responses[3]["credential_attack_mode"])
        # naming a preset means that preset: the earlier override does not survive under its name
        self.assertEqual("blocked", responses[4]["credential_attack_mode"])

    def test_plain_scans_and_policy_tightening_still_work_without_operator_mode(self):
        from app.web.services.scan_service import ScanService

        runtime = mock.MagicMock()
        runtime.start_nmap_scan_job.return_value = {"id": 5, "status": "queued"}
        allowed = {"state": "allowed", "risk_tags": [], "reason": "ok", "risk_summary": "", "safer_alternative": ""}
        with mock.patch("app.web.runtime_tools.evaluate_command_policy", return_value=allowed) as evaluate:
            result = ScanService(runtime).start_governed_nmap_scan(
                {"targets": ["10.0.0.0/24"], "scan_mode": "easy", "nmap_path": "/bin/echo", "nmap_args": "-T3"})
        self.assertEqual("accepted", result["status"])
        self.assertEqual("nmap -T3", evaluate.call_args.args[1])
        self.assertEqual("nmap", runtime.start_nmap_scan_job.call_args.kwargs["nmap_path"])  # never the caller's
        held = dict(allowed, state="approval_required", risk_tags=["high_detection_likelihood"])
        with mock.patch("app.web.runtime_tools.evaluate_command_policy", return_value=held):
            refused = ScanService(runtime).start_governed_nmap_scan({"targets": ["10.0.0.1"], "nmap_args": "-T5"})
            delegated = ScanService(runtime).start_governed_nmap_scan(
                {"targets": ["10.0.0.1"], "nmap_args": "-T5"}, approvals_delegated=True)
        self.assertEqual(("approval_required", None), (refused["status"], refused["job"]))
        self.assertEqual("accepted", delegated["status"])

    def test_policy_loosenings_and_preset_reset(self):
        from app.scheduler.policy import normalize_engagement_policy
        from app.scheduler.policy_engine import policy_loosenings
        from app.web.runtime_scheduler_policy_config import merge_engagement_policy_payload

        recon = normalize_engagement_policy({"preset": "internal_recon"})
        self.assertEqual([], policy_loosenings(recon, recon))
        self.assertEqual([], policy_loosenings(recon, normalize_engagement_policy(
            {"preset": "internal_recon", "approval_mode": "always", "stability_risk_mode": "blocked"})))
        looser = normalize_engagement_policy({"preset": "internal_recon", "approval_mode": "never"})
        self.assertTrue(policy_loosenings(recon, looser))
        self.assertTrue(policy_loosenings(recon, normalize_engagement_policy({"preset": "internal_pentest"})))

        loosened = looser.to_dict()
        loosened["credential_attack_mode"] = "allowed"
        reset = normalize_engagement_policy(merge_engagement_policy_payload(loosened, {"preset": "internal_recon"}))
        self.assertEqual(("blocked", "risky"), (reset.credential_attack_mode, reset.approval_mode))
        kept = normalize_engagement_policy(merge_engagement_policy_payload(loosened, {"noise_budget": "medium"}))
        self.assertEqual("allowed", kept.credential_attack_mode)  # an update without a preset still merges
        custom = normalize_engagement_policy(merge_engagement_policy_payload(loosened, {"preset": "custom"}))
        self.assertEqual("allowed", custom.credential_attack_mode)  # custom keeps the operator's own fields

    def test_unused_temporary_project_is_removed_when_the_session_ends_and_a_used_one_is_kept(self):
        with tempfile.TemporaryDirectory() as home:
            _run_server([_rpc(1, "list_projects")], home)
            tmp = os.path.join(home, "tmp")
            self.assertEqual([], [name for name in os.listdir(tmp)] if os.path.isdir(tmp) else [])
            # a session that queued an approval leaves its project for the operator to come back to
            _run_server([_rpc(1, "run_tool", {"host_ip": "192.0.2.10", "port": "80", "tool_id": "nikto"})], home)
            self.assertTrue(any(name.endswith(".legion") for name in os.listdir(tmp)))

    def test_allowed_tools_are_queued_as_before_and_batches_are_deduplicated(self):
        from app.web import runtime_tools
        from app.web.services.tool_service import ToolService

        runtime = mock.MagicMock()
        runtime.start_tool_run_job.side_effect = lambda **kwargs: {"id": len(runtime.start_tool_run_job.mock_calls)}
        allowed = {"state": "allowed", "tool_id": "banner", "label": "Banner", "command_template": "nc [IP] [PORT]",
                   "family_id": "f", "risk_tags": [], "reason": "ok", "risk_summary": "", "safer_alternative": "",
                   "family_policy_state": ""}
        with mock.patch.object(runtime_tools, "evaluate_tool_run_policy", return_value=allowed):
            result = ToolService(runtime).start_governed_tool_run(
                {"host_ip": "10.0.0.5", "port": "22", "tool_id": "banner"})
        self.assertEqual("accepted", result["status"])
        self.assertEqual("allowed", result["policy"]["state"])
        runtime.start_tool_run_job.assert_called_once()

        needs_approval = dict(allowed, state="approval_required", risk_tags=["high_detection_likelihood"])
        runtime.start_tool_run_job.reset_mock()
        with mock.patch.object(runtime_tools, "evaluate_tool_run_policy", return_value=needs_approval), \
                mock.patch.object(runtime_tools, "queue_tool_run_approval", side_effect=[11, 12]) as queue:
            result = ToolService(runtime).start_governed_tool_run({"tool_id": "nikto", "targets": [
                {"host_ip": "10.0.0.5", "port": "80"}, {"host_ip": "10.0.0.5", "port": "80"},
                {"host_ip": "10.0.0.6", "port": "443"},
            ]})
        self.assertEqual("approval_required", result["status"])
        self.assertEqual([11, 12], result["approval_ids"])  # one approval per distinct target
        self.assertEqual(2, queue.call_count)
        runtime.start_tool_run_job.assert_not_called()

    def test_web_ui_manual_runs_are_not_gated(self):
        # A person clicking Run is their own approval; only agent-requested runs ask the policy.
        from app.web import runtime_tools
        from app.web.services.tool_service import ToolService

        runtime = mock.MagicMock()
        runtime.start_tool_run_job.return_value = {"id": 1}
        with mock.patch.object(runtime_tools, "evaluate_tool_run_policy") as evaluate:
            result = ToolService(runtime).start_tool_run(
                {"host_ip": "10.0.0.5", "port": "22", "tool_id": "ssh-default"})
        self.assertEqual("accepted", result["status"])
        evaluate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
