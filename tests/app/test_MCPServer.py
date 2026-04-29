import unittest
from unittest import mock


def _drain_coroutine(coro):
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    raise RuntimeError("Coroutine yielded unexpectedly; this test helper only supports synchronous coroutines.")


class DummyMCPRuntime:
    def __init__(self):
        self.project = {"name": "demo.legion"}
        self.last_calls = []
        self.policy = {"preset": "internal_recon", "approval_mode": "risky"}

    def list_projects(self, limit=500):
        self.last_calls.append(("list_projects", limit))
        return [{"name": "demo.legion", "path": "/tmp/demo.legion"}][:limit]

    def get_project_details(self):
        return dict(self.project)

    def open_project(self, path):
        self.last_calls.append(("open_project", path))
        self.project["name"] = path
        return dict(self.project)

    def save_project_as(self, path, replace=True):
        self.last_calls.append(("save_project_as", path, bool(replace)))
        self.project["name"] = path
        return dict(self.project)

    def get_engagement_policy(self):
        self.last_calls.append(("get_engagement_policy",))
        return dict(self.policy)

    def set_engagement_policy(self, updates):
        self.last_calls.append(("set_engagement_policy", dict(updates or {})))
        self.policy.update(dict(updates or {}))
        return dict(self.policy)

    def get_scheduler_plan_preview(self, **kwargs):
        self.last_calls.append(("get_scheduler_plan_preview", dict(kwargs)))
        return {"requested_mode": kwargs.get("mode", "compare"), "target_count": 1, "targets": []}

    def get_scheduler_approvals(self, limit=200, status=None):
        self.last_calls.append(("get_scheduler_approvals", limit, status))
        return [{"id": 77, "status": status or "pending"}][:limit]

    def approve_scheduler_approval(self, approval_id, approve_family=False, run_now=True, family_action=""):
        self.last_calls.append(
            ("approve_scheduler_approval", int(approval_id), bool(approve_family), bool(run_now), str(family_action))
        )
        return {"approval": {"id": int(approval_id), "status": "approved"}, "job": {"id": 9} if run_now else None}

    def reject_scheduler_approval(self, approval_id, reason="", family_action=""):
        self.last_calls.append(("reject_scheduler_approval", int(approval_id), str(reason), str(family_action)))
        return {"id": int(approval_id), "status": "rejected"}

    def get_evidence_graph(self, filters=None):
        self.last_calls.append(("get_evidence_graph", dict(filters or {})))
        return {"nodes": [], "edges": [], "meta": {"filters": dict(filters or {})}}

    def get_findings(self, host_id=0, limit_findings=1000):
        self.last_calls.append(("get_findings", int(host_id), int(limit_findings)))
        return {"count": 1, "findings": [{"title": "demo"}]}

    def get_target_state_view(self, host_id=0, limit=500):
        self.last_calls.append(("get_target_state_view", int(host_id), int(limit)))
        return {"host": {"id": int(host_id)}, "target_state": {"engagement_preset": "internal_recon"}}

    def get_project_ai_report(self):
        self.last_calls.append(("get_project_ai_report",))
        return {"project": {"name": "demo.legion"}}

    def get_project_report(self):
        self.last_calls.append(("get_project_report",))
        return {"project": {"name": "demo.legion"}, "summary_of_discovered_assets": {"host_count": 1}}

    def render_project_ai_report_markdown(self, report):
        self.last_calls.append(("render_project_ai_report_markdown", dict(report or {})))
        return "# project report"

    def render_project_report_markdown(self, report):
        self.last_calls.append(("render_project_report_markdown", dict(report or {})))
        return "# project report"

    def get_host_ai_report(self, host_id):
        self.last_calls.append(("get_host_ai_report", int(host_id)))
        return {"host": {"id": int(host_id)}}

    def get_host_report(self, host_id):
        self.last_calls.append(("get_host_report", int(host_id)))
        return {"host": {"id": int(host_id)}, "validated_findings": {"count": 1}}

    def render_host_ai_report_markdown(self, report):
        self.last_calls.append(("render_host_ai_report_markdown", dict(report or {})))
        return "# host report"

    def render_host_report_markdown(self, report):
        self.last_calls.append(("render_host_report_markdown", dict(report or {})))
        return "# host report"

    def get_scheduler_execution_traces(self, *, limit=200, host_id=0, host_ip="", tool_id="", include_output=False):
        self.last_calls.append(
            ("get_scheduler_execution_traces", int(limit), int(host_id), str(host_ip), str(tool_id), bool(include_output))
        )
        return [{"execution_id": "exec-1"}]

    def get_scheduler_execution_trace(self, execution_id, output_max_chars=4000):
        self.last_calls.append(("get_scheduler_execution_trace", str(execution_id), int(output_max_chars)))
        return {"execution_id": str(execution_id), "stdout_excerpt": "sample"}

    def save_evidence_graph_annotation(
            self,
            *,
            target_kind,
            target_ref,
            body,
            created_by="operator",
            source_ref="",
            annotation_id="",
    ):
        self.last_calls.append(
            (
                "save_evidence_graph_annotation",
                str(target_kind),
                str(target_ref),
                str(body),
                str(created_by),
                str(source_ref),
                str(annotation_id),
            )
        )
        return {"annotation_id": annotation_id or "annotation-1", "target_ref": target_ref, "body": body}

    def run_governed_discovery(self, target, *, run_actions=False):
        self.last_calls.append(("run_governed_discovery", str(target), bool(run_actions)))
        return {
            "target": str(target),
            "run_actions": bool(run_actions),
            "project": dict(self.project),
            "results": [{"id": 1, "ip": str(target)}],
            "services": [],
            "scan": {"targets": [str(target)], "run_actions": bool(run_actions)},
        }


class MCPServerTest(unittest.TestCase):
    def setUp(self):
        from app.mcpServer import MCPServer

        self.runtime = DummyMCPRuntime()
        self.server = MCPServer(runtime=self.runtime)

    def _call_tool(self, name, arguments=None):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call_tool",
            "params": {
                "name": name,
                "arguments": dict(arguments or {}),
            },
        }
        response = _drain_coroutine(self.server.handle_request(request))
        self.assertNotIn("error", response)
        return response["result"]

    def test_list_tools_exposes_phase10_tools(self):
        response = _drain_coroutine(self.server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "list_tools",
        }))
        names = {item["name"] for item in response["result"]}
        self.assertIn("open_project", names)
        self.assertIn("get_plan_preview", names)
        self.assertIn("execute_approved_plan_step", names)
        self.assertIn("query_graph", names)
        self.assertIn("query_state", names)
        self.assertIn("export_report", names)
        self.assertIn("get_execution_trace", names)
        self.assertIn("create_annotation", names)
        self.assertNotIn("execute_plan_step", names)

    def test_project_tools_delegate_to_runtime(self):
        listing = self._call_tool("list_projects", {"limit": 10})
        self.assertEqual("demo.legion", listing["projects"][0]["name"])

        opened = self._call_tool("open_project", {"path": "/tmp/engagement.legion"})
        self.assertEqual("/tmp/engagement.legion", opened["project"]["name"])

        saved = self._call_tool("save_project", {"path": "/tmp/saved.legion", "replace": False})
        self.assertEqual("/tmp/saved.legion", saved["project"]["name"])

    def test_plan_preview_and_approval_tools_delegate_to_runtime(self):
        preview = self._call_tool("get_plan_preview", {"host_id": 11, "mode": "compare", "limit_actions": 4})
        self.assertEqual("compare", preview["requested_mode"])

        approvals = self._call_tool("list_approvals", {"status": "pending", "limit": 5})
        self.assertEqual(77, approvals["approvals"][0]["id"])

        approved = self._call_tool("approve_approval", {"approval_id": 77, "run_now": False})
        self.assertEqual("approved", approved["approval"]["status"])
        self.assertIsNone(approved["job"])

        executed = self._call_tool("execute_approved_plan_step", {"approval_id": 77})
        self.assertEqual(9, executed["job"]["id"])

        rejected = self._call_tool("reject_approval", {"approval_id": 77, "reason": "too risky"})
        self.assertEqual("rejected", rejected["approval"]["status"])

    def test_query_report_trace_and_annotation_tools_delegate_to_runtime(self):
        graph = self._call_tool("query_graph", {"node_types": ["host"], "host_id": 11})
        self.assertEqual(["host"], graph["meta"]["filters"]["node_types"])

        findings = self._call_tool("query_findings", {"host_id": 11, "limit": 10})
        self.assertEqual("demo", findings["findings"][0]["title"])

        state = self._call_tool("query_state", {"host_id": 11, "limit": 7})
        self.assertEqual("internal_recon", state["target_state"]["engagement_preset"])
        self.assertIn(("get_target_state_view", 11, 7), self.runtime.last_calls)

        project_report = self._call_tool("export_report", {"scope": "project", "format": "md"})
        self.assertEqual("md", project_report["format"])
        self.assertIn("# project report", project_report["body"])
        self.assertIn(("get_project_report",), self.runtime.last_calls)

        host_report = self._call_tool("export_report", {"scope": "host", "host_id": 11, "format": "json"})
        self.assertEqual(11, host_report["report"]["host"]["id"])
        self.assertIn(("get_host_report", 11), self.runtime.last_calls)

        traces = self._call_tool("list_execution_traces", {"host_id": 11, "include_output": True})
        self.assertEqual("exec-1", traces["executions"][0]["execution_id"])

        trace = self._call_tool("get_execution_trace", {"execution_id": "exec-1", "max_chars": 512})
        self.assertEqual("sample", trace["stdout_excerpt"])

        annotation = self._call_tool(
            "create_annotation",
            {"target_kind": "node", "target_ref": "graph-node-host", "body": "focus this node"},
        )
        self.assertEqual("focus this node", annotation["annotation"]["body"])

    def test_run_discovery_delegates_to_governed_runtime_path(self):
        payload = self._call_tool("run_discovery", {"target": "10.0.0.5", "run_actions": True})
        self.assertEqual("10.0.0.5", payload["target"])
        self.assertTrue(payload["run_actions"])
        self.assertIn(("run_governed_discovery", "10.0.0.5", True), self.runtime.last_calls)

    def test_run_discovery_uses_scan_service_boundary(self):
        from app.web.services.scan_service import ScanService

        with mock.patch.object(
                ScanService,
                "run_discovery",
                autospec=True,
                return_value={"target": "10.0.0.5", "run_actions": True},
        ) as mocked:
            payload = self._call_tool("run_discovery", {"target": "10.0.0.5", "run_actions": True})

        self.assertEqual("10.0.0.5", payload["target"])
        service, request_payload = mocked.call_args.args
        self.assertIs(service.runtime, self.runtime)
        self.assertEqual({"target": "10.0.0.5", "run_actions": True}, request_payload)

    def test_approval_tools_use_scheduler_service_boundary(self):
        from app.web.services.scheduler_service import SchedulerService

        with mock.patch.object(
                SchedulerService,
                "list_approvals",
                autospec=True,
                return_value={"approvals": [{"id": 77, "status": "pending"}]},
        ) as mocked_list:
            listed = self._call_tool("list_approvals", {"status": "pending", "limit": 5})

        self.assertEqual(77, listed["approvals"][0]["id"])
        self.assertIs(mocked_list.call_args.args[0].runtime, self.runtime)

        with mock.patch.object(
                SchedulerService,
                "approve_approval",
                autospec=True,
                return_value=({"status": "ok", "approval": {"id": 77, "status": "approved"}, "job": None}, 200),
        ) as mocked_approve:
            approved = self._call_tool("approve_approval", {"approval_id": 77, "run_now": False})

        self.assertEqual("approved", approved["approval"]["status"])
        service, approval_id, request_payload = mocked_approve.call_args.args
        self.assertIs(service.runtime, self.runtime)
        self.assertEqual(77, approval_id)
        self.assertFalse(request_payload["run_now"])

        with mock.patch.object(
                SchedulerService,
                "approve_approval",
                autospec=True,
                return_value=({"status": "ok", "approval": {"id": 77, "status": "approved"}, "job": {"id": 9}}, 202),
        ) as mocked_execute:
            executed = self._call_tool("execute_approved_plan_step", {"approval_id": 77})

        self.assertEqual(9, executed["job"]["id"])
        self.assertTrue(mocked_execute.call_args.args[2]["run_now"])

        with mock.patch.object(
                SchedulerService,
                "reject_approval",
                autospec=True,
                return_value={"status": "ok", "approval": {"id": 77, "status": "rejected"}},
        ) as mocked_reject:
            rejected = self._call_tool("reject_approval", {"approval_id": 77, "reason": "too risky"})

        self.assertEqual("rejected", rejected["approval"]["status"])
        self.assertIs(mocked_reject.call_args.args[0].runtime, self.runtime)

    def test_graph_report_and_trace_tools_use_service_boundaries(self):
        from app.web.services.graph_service import GraphService
        from app.web.services.report_service import ReportService
        from app.web.services.scheduler_service import SchedulerService
        from app.web.services.workspace_service import WorkspaceService

        with mock.patch.object(
                GraphService,
                "get_graph",
                autospec=True,
                return_value={"nodes": [], "edges": [], "meta": {"filters": {"host_id": 11}}},
        ) as mocked_graph:
            graph = self._call_tool("query_graph", {"host_id": 11})

        self.assertEqual(11, graph["meta"]["filters"]["host_id"])
        self.assertIs(mocked_graph.call_args.args[0].runtime, self.runtime)

        with mock.patch.object(
                ReportService,
                "export_report",
                autospec=True,
                return_value={"scope": "project", "format": "md", "body": "# report"},
        ) as mocked_report:
            report = self._call_tool("export_report", {"scope": "project", "format": "md"})

        self.assertEqual("md", report["format"])
        self.assertIs(mocked_report.call_args.args[0].runtime, self.runtime)

        with mock.patch.object(
                SchedulerService,
                "list_executions",
                autospec=True,
                return_value={"executions": [{"execution_id": "exec-1"}]},
        ) as mocked_list:
            traces = self._call_tool("list_execution_traces", {"host_id": 11, "include_output": True})

        self.assertEqual("exec-1", traces["executions"][0]["execution_id"])
        self.assertIs(mocked_list.call_args.args[0].runtime, self.runtime)

        with mock.patch.object(
                SchedulerService,
                "get_execution_trace",
                autospec=True,
                return_value={"execution_id": "exec-1", "stdout_excerpt": "sample"},
        ) as mocked_trace:
            trace = self._call_tool("get_execution_trace", {"execution_id": "exec-1", "max_chars": 512})

        self.assertEqual("sample", trace["stdout_excerpt"])
        self.assertIs(mocked_trace.call_args.args[0].runtime, self.runtime)

        with mock.patch.object(
                WorkspaceService,
                "list_findings",
                autospec=True,
                return_value={"count": 1, "findings": [{"title": "demo"}]},
        ) as mocked_findings:
            findings = self._call_tool("query_findings", {"host_id": 11, "limit": 10})

        self.assertEqual("demo", findings["findings"][0]["title"])
        service, request_payload = mocked_findings.call_args.args
        self.assertIs(service.runtime, self.runtime)
        self.assertEqual({"host_id": 11, "limit": 10}, request_payload)

        with mock.patch.object(
                WorkspaceService,
                "get_host_target_state",
                autospec=True,
                return_value={"host": {"id": 11}, "target_state": {"engagement_preset": "internal_recon"}},
        ) as mocked_state:
            state = self._call_tool("query_state", {"host_id": 11, "limit": 42})

        self.assertEqual("internal_recon", state["target_state"]["engagement_preset"])
        self.assertIs(mocked_state.call_args.args[0].runtime, self.runtime)
        self.assertEqual(11, mocked_state.call_args.args[1])
        self.assertEqual(42, mocked_state.call_args.kwargs["limit"])


if __name__ == "__main__":
    unittest.main()
