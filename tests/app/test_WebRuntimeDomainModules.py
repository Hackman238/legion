import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock


class _GraphRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self._project = SimpleNamespace(
            database=object(),
            properties=SimpleNamespace(outputFolder="/tmp/out", runningFolder="/tmp/run"),
        )

    def _require_active_project(self):
        return self._project

    def _is_project_artifact_path(self, project, path):
        return False

    def get_process_output(self, process_id, offset=0, max_chars=12000):
        return {"output": f"process output {process_id}"}

    def get_screenshot_file(self, filename):
        return f"/tmp/{filename}"


class _ConfigStore:
    def __init__(self, payload):
        self.payload = payload

    def load(self):
        return dict(self.payload)


class _ReportRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self.scheduler_config = _ConfigStore({
            "project_report_delivery": {
                "provider_name": "siem",
                "endpoint": "",
                "method": "POST",
                "format": "json",
                "headers": {},
                "timeout_seconds": 30,
                "mtls": {
                    "enabled": False,
                    "client_cert_path": "",
                    "client_key_path": "",
                    "ca_cert_path": "",
                },
            }
        })
        self.request_call = None

    def _project_report_delivery_config(self, preferences=None):
        source = preferences if isinstance(preferences, dict) else {}
        delivery = source.get("project_report_delivery", {})
        defaults = {
            "provider_name": "",
            "endpoint": "",
            "method": "POST",
            "format": "json",
            "headers": {},
            "timeout_seconds": 30,
            "mtls": {
                "enabled": False,
                "client_cert_path": "",
                "client_key_path": "",
                "ca_cert_path": "",
            },
        }
        if isinstance(delivery, dict):
            defaults.update(delivery)
        defaults["headers"] = self._normalize_project_report_headers(defaults.get("headers", {}))
        return defaults

    @staticmethod
    def _normalize_project_report_headers(headers):
        source = headers if isinstance(headers, dict) else {}
        return {
            str(name or "").strip(): str(value or "")
            for name, value in source.items()
            if str(name or "").strip()
        }


class _ToolQueryResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return list(self._rows)


class _ToolSession:
    def __init__(self, database):
        self._database = database

    def execute(self, _query, params=None):
        self._database.last_params = dict(params or {})
        return _ToolQueryResult(self._database.rows)

    def close(self):
        return None


class _ToolDatabase:
    def __init__(self, rows):
        self.rows = list(rows)
        self.last_params = {}

    def session(self):
        return _ToolSession(self)


class _ToolRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self.scheduler_config = SimpleNamespace(
            get_dangerous_categories=lambda: ["credential_access"]
        )
        self.settings = SimpleNamespace(
            portActions=[
                ("Run SMBMap", "smbmap", "smbmap -H [TARGET_HOST] -P [PORT]", "smb"),
                ("Run WhatWeb", "whatweb-http", "whatweb [WEB_URL]", "http"),
                ("Skip Custom", "custom-tool", "custom [TARGET_HOST]", "http"),
            ],
            automatedAttacks=[
                ("screenshooter", "http"),
                ("custom-tool", "http"),
            ],
        )
        self.logic = SimpleNamespace(
            activeProject=SimpleNamespace(
                database=_ToolDatabase([
                    {
                        "host_id": 11,
                        "host_ip": "10.0.0.5",
                        "hostname": "dc01.local",
                        "port": "445",
                        "protocol": "tcp",
                        "service": "smb",
                        "service_product": "samba",
                        "service_version": "4.x",
                    },
                    {
                        "host_id": 11,
                        "host_ip": "10.0.0.5",
                        "hostname": "dc01.local",
                        "port": "80",
                        "protocol": "tcp",
                        "service": "http",
                        "service_product": "nginx",
                        "service_version": "1.24",
                    },
                ])
            )
        )
        self.started_job = None
        self.command_call = None
        self.run_call = None

    def _get_settings(self):
        return self.settings

    def _tool_run_stats(self, _project):
        return {
            "smbmap": {
                "run_count": 2,
                "last_status": "completed",
                "last_start": "2026-04-17T10:15:00Z",
            }
        }

    @staticmethod
    def _split_csv(raw):
        return [item.strip() for item in str(raw or "").split(",") if item.strip()]

    @staticmethod
    def _port_sort_key(port_value):
        try:
            return 0, f"{int(str(port_value or '').strip()):08d}"
        except (TypeError, ValueError):
            return 1, str(port_value or "")

    def _require_active_project(self):
        return self.logic.activeProject

    @staticmethod
    def _find_port_action(settings, tool_id):
        for action in settings.portActions:
            if str(action[1]) == str(tool_id):
                return action
        return None

    def _build_command(self, template, host_ip, port, protocol, tool_id):
        self.command_call = {
            "template": template,
            "host_ip": host_ip,
            "port": port,
            "protocol": protocol,
            "tool_id": tool_id,
        }
        return (f"rendered {tool_id} {host_ip}:{port}/{protocol}", "/tmp/tool-output")

    def _run_command_with_tracking(self, **kwargs):
        self.run_call = dict(kwargs)
        return True, "completed", 42

    def _start_job(self, job_type, callback, payload):
        self.started_job = {
            "job_type": job_type,
            "payload": dict(payload or {}),
        }
        result = callback(9)
        return {
            "id": 9,
            "type": job_type,
            "payload": dict(payload or {}),
            "result": result,
        }


class _ArtifactRuntime:
    def __init__(self, output_dir):
        self._lock = threading.RLock()
        self._project = SimpleNamespace(
            database=object(),
            properties=SimpleNamespace(
                outputFolder=output_dir,
                runningFolder=os.path.join(output_dir, "running"),
            ),
        )
        self._host = SimpleNamespace(id=11, ip="10.0.0.5", hostname="dc01.local")

    def _require_active_project(self):
        return self._project

    def _resolve_host(self, host_id):
        return self._host if int(host_id or 0) == 11 else None


class _WorkspaceMutationRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self._project = SimpleNamespace(database=object())
        self._host = SimpleNamespace(
            id=11,
            ip="10.0.0.5",
            hostname="dc01.local",
            osMatch="Linux 6.x",
        )

    def _require_active_project(self):
        return self._project

    def _resolve_host(self, host_id):
        return self._host if int(host_id or 0) == 11 else None


class _WorkspaceReadRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self._project = SimpleNamespace(database=object())
        self._host = SimpleNamespace(
            id=11,
            ip="10.0.0.5",
            hostname="dc01.local",
            status="up",
            osMatch="Linux 6.x",
        )

    def _project_metadata(self):
        return {"name": "demo"}

    def _summary(self):
        return {"hosts": 2, "services": 3}

    def _scheduler_preferences(self):
        return {"mode": "ai"}

    def _scheduler_rationale_feed_locked(self, limit=12):
        return [{"host_ip": "10.0.0.5", "headline": "smbmap"}][: int(limit or 12)]

    def _require_active_project(self):
        return self._project

    def _resolve_host(self, host_id):
        return self._host if int(host_id or 0) == 11 else None

    def _hosts(self, limit=None):
        rows = [
            {"id": 11, "ip": "10.0.0.5", "hostname": "dc01.local", "status": "up", "os": "Linux 6.x"},
            {"id": 12, "ip": "10.0.0.7", "hostname": "web01.local", "status": "up", "os": "Linux"},
        ]
        if limit is None:
            return rows
        return rows[: int(limit)]


class _StatusDomainRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self.jobs = SimpleNamespace(list_jobs=lambda limit=20: [{"id": 9, "type": "scan", "status": "queued"}][:limit])
        self.autosave_checks = 0

    def _maybe_schedule_autosave_locked(self):
        self.autosave_checks += 1

    def _project_metadata(self):
        return {"name": "demo"}

    def _summary(self):
        return {"hosts": 2, "services": 3}

    def _hosts(self, include_down=False):
        rows = [
            {"id": 11, "ip": "10.0.0.5", "hostname": "dc01.local", "status": "up", "os": "Linux 6.x"},
        ]
        if include_down:
            rows.append({"id": 12, "ip": "10.0.0.7", "hostname": "web01.local", "status": "down", "os": "Linux"})
        return rows

    def _processes(self, limit=75):
        return [{"id": 91, "name": "nmap", "status": "running"}][: int(limit or 75)]

    def get_workspace_services(self, limit=40):
        return [{"service": "http", "host_count": 1}][: int(limit or 40)]

    def get_workspace_tools_page(self, limit=300, offset=0):
        return {
            "tools": [{"tool_id": "nmap", "label": "Nmap"}][: int(limit or 300)],
            "offset": int(offset),
            "limit": int(limit),
            "total": 1,
            "has_more": False,
            "next_offset": None,
        }

    def _credential_capture_state_locked(self, include_captures=False):
        return {"enabled": True, "captures": [] if include_captures else None}

    def _scheduler_preferences(self):
        return {"mode": "ai"}

    def get_scheduler_decisions(self, limit=80):
        return [{"id": 1, "tool_id": "smbmap"}][: int(limit or 80)]

    def _scheduler_rationale_feed_locked(self, limit=12):
        return [{"headline": "smbmap"}][: int(limit or 12)]

    def get_scheduler_approvals(self, limit=40, status="pending"):
        return [{"id": 2, "status": status}][: int(limit or 40)]

    def get_scheduler_execution_records(self, limit=40):
        return [{"id": "exec-1"}][: int(limit or 40)]

    def get_scan_history(self, limit=40):
        return [{"id": 3, "status": "completed"}][: int(limit or 40)]


class _JobManager:
    def __init__(self):
        self.jobs = {
            5: {
                "id": 5,
                "type": "tool-run",
                "status": "running",
                "payload": {"host_id": 11},
            }
        }
        self.cancelled = []

    def get_job(self, job_id):
        return self.jobs.get(int(job_id))

    def cancel_job(self, job_id, reason=""):
        self.cancelled.append((int(job_id), str(reason)))
        job = self.jobs.get(int(job_id))
        if job is None:
            return None
        job["status"] = "cancelled"
        return dict(job)


class _ProcessDomainRuntime:
    def __init__(self):
        self.jobs = _JobManager()
        self.killed = []
        self._process_runtime_lock = threading.Lock()
        self._job_process_ids = {5: {91, 92}}
        self._process_job_id = {91: 5, 92: 5}

    def kill_process(self, process_id):
        self.killed.append(int(process_id))
        return {"killed": True, "process_id": int(process_id)}


class _SchedulerDomainRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self._host = SimpleNamespace(id=11, ip="10.0.0.5")
        self.scheduler_config = SimpleNamespace(
            load=lambda: {
                "mode": "ai",
                "provider": "openai",
                "providers": {"openai": {"enabled": True, "api_key": "secret-provider-key"}},
                "integrations": {
                    "shodan": {"api_key": "shodan secret"},
                    "grayhatwarfare": {"api_key": "grayhat secret"},
                },
                "device_categories": ["server"],
                "dangerous_categories": ["credential_access"],
                "cloud_notice": "custom cloud notice",
            },
            get_feature_flags=lambda: {"credential_capture_panel": True},
            secret_storage_status=lambda: {"backend": "memory", "available": True},
        )
        self.jobs = SimpleNamespace(worker_count=3, max_jobs=80)
        self.started_job = None
        self.run_call = None
        self.execute_call = None

    def _resolve_host(self, host_id):
        return self._host if int(host_id or 0) == 11 else None

    def _find_active_job(self, *, job_type: str, host_id=None):
        return None

    def _load_engagement_policy_locked(self, *, persist_if_missing=True):
        return {
            "legacy_goal_profile": "internal_asset_discovery",
            "preset": "internal_recon",
        }

    @staticmethod
    def _project_report_delivery_config(preferences=None):
        return {"method": "POST", "format": "json"}

    @staticmethod
    def _built_in_device_category_options():
        return [{"id": "server", "name": "Server", "built_in": True}]

    def _run_scheduler_actions_web(self, *, host_ids=None, dig_deeper=False, job_id=0):
        self.run_call = {
            "host_ids": set(host_ids or set()),
            "dig_deeper": bool(dig_deeper),
            "job_id": int(job_id or 0),
        }
        return {"job_id": int(job_id or 0)}

    def _start_job(self, job_type, callback, payload):
        self.started_job = {
            "job_type": str(job_type or ""),
            "payload": dict(payload or {}),
        }
        result = callback(17)
        return {
            "id": 17,
            "type": str(job_type or ""),
            "payload": dict(payload or {}),
            "result": result,
        }

    def _execute_scheduler_decision(
            self,
            decision,
            *,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            command_template: str,
            timeout: int,
            job_id: int = 0,
            capture_metadata: bool = False,
            approval_id: int = 0,
            runner_preference: str = "",
            runner_settings=None,
    ):
        self.execute_call = {
            "decision": decision,
            "host_ip": host_ip,
            "port": port,
            "protocol": protocol,
            "service_name": service_name,
            "command_template": command_template,
            "timeout": int(timeout),
            "job_id": int(job_id or 0),
            "capture_metadata": bool(capture_metadata),
            "approval_id": int(approval_id or 0),
            "runner_preference": str(runner_preference or ""),
            "runner_settings": dict(runner_settings or {}),
        }
        return {
            "executed": True,
            "reason": "completed",
            "process_id": 41,
            "execution_record": SimpleNamespace(id="exec-1"),
        }


class WebRuntimeDomainModulesTest(unittest.TestCase):
    def test_runtime_graph_module_resolves_inline_evidence(self):
        from app.web import runtime_graph

        runtime = _GraphRuntime()
        snapshot = {
            "nodes": [
                {
                    "node_id": "finding-1",
                    "type": "finding",
                    "label": "SMB shares enumerated (2)",
                    "properties": {},
                    "evidence_refs": [],
                },
                {
                    "node_id": "evidence-1",
                    "type": "evidence_record",
                    "label": "smbmap output",
                    "properties": {
                        "evidence": "smbmap: ADMIN$, C$",
                        "evidence_items": ["ADMIN$", "C$"],
                    },
                    "evidence_refs": ["ADMIN$", "C$"],
                },
            ],
            "edges": [
                {"from_node_id": "finding-1", "to_node_id": "evidence-1"},
            ],
        }

        with mock.patch("app.web.runtime_graph.ensure_scheduler_graph_tables"), mock.patch(
            "app.web.runtime_graph.query_evidence_graph",
            return_value=snapshot,
        ):
            related = runtime_graph.get_graph_related_content(runtime, "finding-1")
            self.assertEqual(1, related["entry_count"])
            self.assertIn("smbmap: ADMIN$, C$", related["entries"][0]["preview_text"])

            content = runtime_graph.get_graph_content(runtime, "evidence-1", download=True)
            self.assertEqual("text", content["kind"])
            self.assertTrue(content["download"])
            self.assertIn("ADMIN$", content["text"])

    def test_runtime_reports_module_pushes_markdown_with_delivery_overrides(self):
        from app.web import runtime_reports

        runtime = _ReportRuntime()

        class _RequestsModule:
            def request(self, **kwargs):
                runtime.request_call = dict(kwargs)
                return SimpleNamespace(status_code=202, text="queued")

        with mock.patch("app.web.runtime._get_requests_module", return_value=_RequestsModule()):
            result = runtime_reports.push_project_report_common(
                runtime,
                report={"project": {"name": "demo"}},
                markdown_renderer=lambda report: "# demo report\n",
                overrides={
                    "endpoint": "https://example.local/report",
                    "method": "PUT",
                    "format": "md",
                    "headers": {"X-Test": "1"},
                },
                report_label="project report",
            )

        self.assertTrue(result["ok"])
        self.assertEqual("PUT", result["method"])
        self.assertEqual("md", result["format"])
        self.assertEqual("https://example.local/report", result["endpoint"])
        self.assertIsNotNone(runtime.request_call)
        self.assertEqual("PUT", runtime.request_call["method"])
        self.assertEqual(b"# demo report\n", runtime.request_call["data"])
        self.assertEqual("1", runtime.request_call["headers"]["X-Test"])
        self.assertEqual("text/markdown; charset=utf-8", runtime.request_call["headers"]["Content-Type"])

    def test_runtime_tools_module_pages_supported_tools_and_scheduler_only_entries(self):
        from app.web import runtime_tools

        runtime = _ToolRuntime()

        page = runtime_tools.get_workspace_tools_page(runtime, service="http", limit=10, offset=0)

        self.assertEqual(2, page["total"])
        self.assertEqual(["screenshooter", "whatweb-http"], [item["tool_id"] for item in page["tools"]])
        self.assertFalse(page["tools"][0]["runnable"])
        self.assertTrue(page["tools"][1]["runnable"])
        self.assertIsNone(page["next_offset"])

    def test_runtime_tools_module_sorts_tool_targets_and_normalizes_query_params(self):
        from app.web import runtime_tools

        runtime = _ToolRuntime()

        targets = runtime_tools.get_workspace_tool_targets(runtime, host_id="11", service="http", limit=77)

        self.assertEqual({"host_id": 11, "service": "http", "limit": 77}, runtime.logic.activeProject.database.last_params)
        self.assertEqual(["80", "445"], [item["port"] for item in targets])
        self.assertEqual("10.0.0.5 | dc01.local | http | 80/tcp", targets[0]["label"])

    def test_runtime_tools_module_starts_manual_tool_job_through_shared_tracking(self):
        from app.web import runtime_tools

        runtime = _ToolRuntime()

        job = runtime_tools.start_tool_run_job(
            runtime,
            host_ip="10.0.0.5",
            port="445",
            protocol="tcp",
            tool_id="smbmap",
            command_override="override smbmap",
            timeout=120,
        )

        self.assertEqual("tool-run", runtime.started_job["job_type"])
        self.assertEqual("override smbmap", runtime.started_job["payload"]["command_override"])
        self.assertEqual("override smbmap", runtime.command_call["template"])
        self.assertEqual("smbmap", runtime.run_call["tool_name"])
        self.assertEqual(120, runtime.run_call["timeout"])
        self.assertEqual(9, runtime.run_call["job_id"])
        self.assertTrue(job["result"]["executed"])
        self.assertEqual(42, job["result"]["process_id"])

    def test_runtime_artifacts_module_deletes_screenshot_and_prunes_state(self):
        from app.web import runtime_artifacts

        with tempfile.TemporaryDirectory() as tmpdir:
            screenshot_dir = os.path.join(tmpdir, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            screenshot_name = "10.0.0.5-445-screenshot.png"
            screenshot_path = os.path.join(screenshot_dir, screenshot_name)
            metadata_path = f"{screenshot_path}.json"
            with open(screenshot_path, "wb") as handle:
                handle.write(b"png")
            with open(metadata_path, "w", encoding="utf-8") as handle:
                handle.write("{}")

            runtime = _ArtifactRuntime(tmpdir)
            target_state = {
                "screenshots": [
                    {
                        "artifact_ref": f"/api/screenshots/{screenshot_name}",
                        "filename": screenshot_name,
                        "port": "445",
                        "protocol": "tcp",
                    }
                ],
                "artifacts": [
                    {
                        "kind": "screenshot",
                        "ref": f"/api/screenshots/{screenshot_name}",
                        "port": "445",
                        "protocol": "tcp",
                    },
                    {
                        "kind": "artifact",
                        "ref": "/tmp/scan.txt",
                        "port": "445",
                        "protocol": "tcp",
                    },
                ],
            }

            with mock.patch("app.web.runtime_artifacts.get_target_state", return_value=target_state), mock.patch(
                "app.web.runtime_artifacts.upsert_target_state"
            ) as mocked_upsert, mock.patch("app.web.runtime_artifacts.rebuild_evidence_graph") as mocked_rebuild:
                result = runtime_artifacts.delete_graph_screenshot(
                    runtime,
                    host_id=11,
                    filename=screenshot_name,
                    port="445",
                    protocol="tcp",
                )

            self.assertTrue(result["deleted"])
            self.assertEqual(2, result["deleted_files"])
            self.assertFalse(os.path.exists(screenshot_path))
            self.assertFalse(os.path.exists(metadata_path))
            updated_state = mocked_upsert.call_args.args[2]
            self.assertEqual([], updated_state["screenshots"])
            self.assertEqual(1, len(updated_state["artifacts"]))
            self.assertEqual("artifact", updated_state["artifacts"][0]["kind"])
            mocked_rebuild.assert_called_once()

    def test_runtime_workspace_module_updates_host_categories(self):
        from app.web import runtime_workspace

        runtime = _WorkspaceMutationRuntime()

        with mock.patch("app.web.runtime_workspace.upsert_target_state", return_value={
            "device_categories": ["server"],
            "manual_device_categories": ["server"],
            "device_category_override": True,
        }) as mocked_upsert:
            result = runtime_workspace.update_host_categories(
                runtime,
                11,
                manual_categories=["server"],
                override_auto=True,
            )

        self.assertEqual(11, result["host_id"])
        self.assertEqual(["server"], result["device_categories"])
        self.assertEqual(["server"], result["manual_device_categories"])
        self.assertTrue(result["device_category_override"])
        self.assertTrue(mocked_upsert.called)

    def test_runtime_workspace_module_reads_overview_target_state_and_findings(self):
        from app.web import runtime_workspace

        runtime = _WorkspaceReadRuntime()
        state_rows = {
            11: {
                "engagement_preset": "internal_recon",
                "findings": [
                    {
                        "title": "SMB signing not required",
                        "severity": "high",
                        "confidence": 0.9,
                        "source_kind": "observed",
                    }
                ],
            },
            12: {
                "engagement_preset": "internal_recon",
                "findings": [],
            },
        }

        with mock.patch(
            "app.web.runtime_workspace.get_target_state",
            side_effect=lambda _db, host_id: dict(state_rows.get(int(host_id), {})),
        ):
            overview = runtime_workspace.get_workspace_overview(runtime)
            single_state = runtime_workspace.get_target_state_view(runtime, host_id=11)
            state_listing = runtime_workspace.get_target_state_view(runtime, limit=5)
            findings = runtime_workspace.get_findings(runtime, host_id=11, limit_findings=10)

        self.assertEqual("demo", overview["project"]["name"])
        self.assertEqual("10.0.0.5", overview["scheduler_rationale_feed"][0]["host_ip"])
        self.assertEqual("internal_recon", single_state["target_state"]["engagement_preset"])
        self.assertEqual(2, state_listing["count"])
        self.assertEqual(1, findings["count"])
        self.assertEqual("SMB signing not required", findings["findings"][0]["title"])

    def test_runtime_status_module_builds_snapshot_payload(self):
        from app.web import runtime_status

        runtime = _StatusDomainRuntime()

        snapshot = runtime_status.get_snapshot(runtime)
        processes = runtime_status.get_workspace_processes(runtime, limit=5)

        self.assertEqual(1, runtime.autosave_checks)
        self.assertEqual("demo", snapshot["project"]["name"])
        self.assertEqual(2, snapshot["summary"]["hosts"])
        self.assertEqual("hide_down", snapshot["host_filter"])
        self.assertEqual("nmap", snapshot["processes"][0]["name"])
        self.assertEqual("http", snapshot["services"][0]["service"])
        self.assertEqual("ai", snapshot["scheduler"]["mode"])
        self.assertEqual("queued", snapshot["jobs"][0]["status"])
        self.assertEqual("nmap", processes[0]["name"])

    def test_runtime_processes_module_stops_job_and_kills_registered_processes(self):
        from app.web import runtime_processes

        runtime = _ProcessDomainRuntime()

        result = runtime_processes.stop_job(runtime, 5)

        self.assertTrue(result["stopped"])
        self.assertEqual([91, 92], sorted(result["killed_process_ids"]))
        self.assertEqual([91, 92], sorted(runtime.killed))
        self.assertEqual([(5, "stopped by user")], runtime.jobs.cancelled)

    def test_runtime_scheduler_module_starts_scheduler_run_and_dig_deeper_jobs(self):
        from app.web import runtime_scheduler

        runtime = _SchedulerDomainRuntime()

        scheduler_run = runtime_scheduler.start_scheduler_run_job(runtime)
        self.assertEqual("scheduler-run", scheduler_run["type"])
        self.assertEqual({}, scheduler_run["payload"])
        self.assertEqual(set(), runtime.run_call["host_ids"])
        self.assertFalse(runtime.run_call["dig_deeper"])
        self.assertEqual(17, runtime.run_call["job_id"])

        dig_deeper = runtime_scheduler.start_host_dig_deeper_job(runtime, 11)
        self.assertEqual("scheduler-dig-deeper", dig_deeper["type"])
        self.assertEqual(11, dig_deeper["payload"]["host_id"])
        self.assertEqual("10.0.0.5", dig_deeper["payload"]["host_ip"])
        self.assertTrue(dig_deeper["payload"]["dig_deeper"])
        self.assertEqual({11}, runtime.run_call["host_ids"])
        self.assertTrue(runtime.run_call["dig_deeper"])
        self.assertEqual(17, runtime.run_call["job_id"])

    def test_runtime_scheduler_module_executes_scheduler_task_payload(self):
        from app.web import runtime_scheduler

        runtime = _SchedulerDomainRuntime()
        task = {
            "decision": SimpleNamespace(tool_id="whatweb-http"),
            "tool_id": "whatweb-http",
            "host_ip": "10.0.0.5",
            "port": "80",
            "protocol": "tcp",
            "service_name": "http",
            "command_template": "whatweb http://10.0.0.5",
            "timeout": 120,
            "job_id": 8,
            "approval_id": 77,
            "runner_preference": "subprocess",
            "runner_settings": {"default": "subprocess"},
        }

        result = runtime_scheduler.execute_scheduler_task(runtime, task)

        self.assertTrue(result["executed"])
        self.assertEqual(41, result["process_id"])
        self.assertEqual(77, result["approval_id"])
        self.assertEqual("whatweb-http", result["tool_id"])
        self.assertIsNotNone(runtime.execute_call)
        self.assertEqual("10.0.0.5", runtime.execute_call["host_ip"])
        self.assertEqual("80", runtime.execute_call["port"])
        self.assertTrue(runtime.execute_call["capture_metadata"])
        self.assertEqual(77, runtime.execute_call["approval_id"])
        self.assertEqual("subprocess", runtime.execute_call["runner_preference"])

    def test_runtime_scheduler_module_builds_sanitized_preferences_and_placeholders(self):
        from app.web import runtime_scheduler

        runtime = _SchedulerDomainRuntime()

        prefs = runtime_scheduler.scheduler_preferences(runtime)
        placeholders = runtime_scheduler.scheduler_command_placeholders(
            runtime,
            host_ip="203.0.113.10",
            hostname="api.example.com",
        )

        self.assertEqual("ai", prefs["mode"])
        self.assertEqual("internal_asset_discovery", prefs["goal_profile"])
        self.assertTrue(prefs["providers"]["openai"]["api_key_configured"])
        self.assertEqual("", prefs["providers"]["openai"]["api_key"])
        self.assertTrue(prefs["integrations"]["shodan"]["api_key_configured"])
        self.assertIsInstance(prefs["device_categories"], list)
        self.assertEqual("server", prefs["built_in_device_categories"][0]["id"])
        self.assertEqual(3, prefs["job_workers"])
        self.assertEqual(80, prefs["job_max"])
        self.assertEqual("custom cloud notice", prefs["cloud_notice"])
        self.assertEqual("example.com", placeholders["ROOT_DOMAIN"])
        self.assertEqual("'grayhat secret'", placeholders["GRAYHAT_API_KEY"])
        self.assertEqual("'shodan secret'", placeholders["SHODAN_API_KEY"])


if __name__ == "__main__":
    unittest.main()
