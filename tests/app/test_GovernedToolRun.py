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


def _run_server(requests, home, cwd=REPO):
    env = dict(os.environ, LEGION_HOME=home, LEGION_TMPDIR=os.path.join(home, "tmp"))
    completed = subprocess.run(
        [sys.executable, os.path.join(REPO, "legion.py"), "--mcp-server"],
        input=("\n".join(requests) + "\n").encode(), capture_output=True, timeout=180, cwd=cwd, env=env,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    responses = {}
    for line in completed.stdout.decode().splitlines():
        if line.strip():
            item = json.loads(line)
            responses[item["id"]] = item["result"].get("structuredContent", item["result"])
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
