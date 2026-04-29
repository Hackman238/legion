import os
import tempfile
import threading
import unittest
import zipfile
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
        from app.pipettes import find_pipette
        pipette = find_pipette(str(tool_id))
        if pipette is not None:
            return pipette.as_port_action()
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


class _WorkspaceLookupResult:
    def __init__(self, rows, keys=None):
        self._rows = list(rows)
        self._keys = list(keys or [])

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def keys(self):
        return list(self._keys)


class _WorkspaceLookupSession:
    def execute(self, query, params=None):
        sql = str(query)
        payload = dict(params or {})
        if "SELECT id FROM hostObj" in sql:
            if int(payload.get("id", 0) or 0) == 11:
                return _WorkspaceLookupResult([(11,)])
            return _WorkspaceLookupResult([])
        if "FROM cve WHERE hostId" in sql:
            return _WorkspaceLookupResult(
                [
                    (
                        7,
                        "CVE-2024-1111",
                        "high",
                        "nginx",
                        "1.24.0",
                        "https://example.local/cve",
                        "nuclei",
                        0,
                        "",
                        "",
                    )
                ],
                keys=["id", "name", "severity", "product", "version", "url", "source", "exploitId", "exploit", "exploitUrl"],
            )
        if "FROM portObj AS p" in sql:
            if int(payload.get("host_id", 0) or 0) == 11 and str(payload.get("port", "")) == "80":
                return _WorkspaceLookupResult([("http",)])
            return _WorkspaceLookupResult([])
        raise AssertionError(f"Unexpected query: {sql}")

    def close(self):
        return None


class _WorkspaceLookupDatabase:
    def session(self):
        return _WorkspaceLookupSession()


class _WorkspaceLookupHostRepo:
    def __init__(self):
        self.host = SimpleNamespace(id=11, ip="10.0.0.5", hostname="dc01.local")

    def getAllHostObjs(self):
        return [self.host]

    def getHostByIP(self, ip):
        if str(ip or "") == "10.0.0.5":
            return self.host
        return None


class _WorkspaceLookupRuntime:
    def __init__(self):
        host_repo = _WorkspaceLookupHostRepo()
        self._project = SimpleNamespace(
            database=_WorkspaceLookupDatabase(),
            repositoryContainer=SimpleNamespace(hostRepository=host_repo),
        )

    def _require_active_project(self):
        return self._project


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


class _SchedulerStateQueryResult:
    def __init__(self, rows):
        self._rows = list(rows)

    def fetchall(self):
        return list(self._rows)


class _SchedulerStateSession:
    def execute(self, query, params=None):
        sql = str(query)
        payload = dict(params or {})
        if "FROM l1ScriptObj AS s" in sql:
            return _SchedulerStateQueryResult([("nuclei-web",)])
        if "FROM process AS p" in sql and "COALESCE(p.port, '') = :port" in sql:
            return _SchedulerStateQueryResult([("whatweb-http", "whatweb http://10.0.0.5 > /tmp/run-a")])
        if "FROM process AS p" in sql:
            return _SchedulerStateQueryResult([("subfinder", "subfinder -d example.com -o /tmp/host-run")])
        if "FROM scheduler_pending_approval" in sql and "COALESCE(port, '') = :port" in sql:
            return _SchedulerStateQueryResult([("nmap-vuln.nse", "nmap -oA /tmp/scan-a 10.0.0.5", "family-port")])
        if "FROM scheduler_pending_approval" in sql:
            return _SchedulerStateQueryResult([("shodan-enrichment", "", "family-host")])
        raise AssertionError(f"Unexpected query: {sql} with {payload}")

    def close(self):
        return None


class _SchedulerStateDatabase:
    def session(self):
        return _SchedulerStateSession()


class _SchedulerStateRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self.logic = SimpleNamespace(activeProject=SimpleNamespace(database=_SchedulerStateDatabase()))

    def _ensure_scheduler_approval_store(self):
        return None

    def _ensure_scheduler_table(self):
        return None

    @staticmethod
    def _is_host_scoped_scheduler_tool(tool_id):
        return str(tool_id or "").strip().lower() in {"subfinder", "shodan-enrichment"}


class _RuntimeJobsManager:
    def __init__(self):
        self.jobs = [
            {"id": 7, "type": "scheduler-dig-deeper", "status": "running", "payload": {"host_id": 11}},
            {"id": 8, "type": "scheduler-dig-deeper", "status": "completed", "payload": {"host_id": 12}},
        ]
        self.started = None

    def start(self, job_type, runner, payload=None, queue_front=False, exclusive=False):
        job = {
            "id": 19,
            "type": str(job_type),
            "status": "queued",
            "payload": dict(payload or {}),
            "queue_front": bool(queue_front),
            "exclusive": bool(exclusive),
            "result": runner(),
        }
        self.started = dict(job)
        return job

    def list_jobs(self, limit=200):
        return list(self.jobs)[: int(limit or 200)]


class _RuntimeJobsRuntime:
    def __init__(self):
        self._ui_event_condition = threading.Condition()
        self._ui_event_seq = 0
        self._ui_events = []
        self._ui_last_emit_monotonic = {}
        self.jobs = _RuntimeJobsManager()


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

    def test_runtime_tools_module_passes_validated_pipette_parameters(self):
        from app.web import runtime_tools

        runtime = _ToolRuntime()

        job = runtime_tools.start_tool_run_job(
            runtime,
            host_ip="10.0.0.7",
            port="25",
            protocol="tcp",
            tool_id="pipette-smtp-internal-discovery",
            parameters={"spf_domain": "example.org", "ignored": "value"},
            timeout=120,
        )

        self.assertEqual({"spf_domain": "example.org"}, runtime.started_job["payload"]["parameters"])
        self.assertIn("--domain example.org", runtime.command_call["template"])
        self.assertEqual("pipette-smtp-internal-discovery", runtime.run_call["tool_name"])
        self.assertTrue(job["result"]["executed"])

    def test_runtime_tools_module_rejects_invalid_pipette_parameters_before_queueing(self):
        from app.web import runtime_tools

        runtime = _ToolRuntime()

        with self.assertRaises(ValueError):
            runtime_tools.start_tool_run_job(
                runtime,
                host_ip="10.0.0.7",
                port="25",
                protocol="tcp",
                tool_id="pipette-smtp-internal-discovery",
                parameters={"spf_domain": "example.org;id"},
                timeout=120,
            )
        self.assertIsNone(runtime.started_job)

    def test_runtime_tools_module_classifies_runner_types(self):
        from app.web import runtime_tools

        runtime = SimpleNamespace(
            _get_settings=lambda: SimpleNamespace(portActions=[], automatedAttacks=[]),
        )

        self.assertEqual("browser", runtime_tools.runner_type_for_tool(runtime, "screenshooter"))
        self.assertEqual("manual", runtime_tools.runner_type_for_tool(runtime, "responder"))
        self.assertEqual("manual", runtime_tools.runner_type_for_tool(runtime, "custom-tool", "operator clipboard"))
        self.assertEqual("manual", runtime_tools.runner_type_for_approval_item(runtime, {"tool_id": "ntlmrelayx"}))
        self.assertEqual("local", runtime_tools.runner_type_for_tool(runtime, "whatweb-http", "whatweb [WEB_URL]"))

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

    def test_runtime_workspace_mutation_module_updates_host_categories_with_injected_upsert(self):
        from app.web import runtime_workspace_mutation

        runtime = _WorkspaceMutationRuntime()

        result = runtime_workspace_mutation.update_host_categories(
            runtime,
            11,
            manual_categories=["server"],
            override_auto=True,
            upsert_target_state_func=lambda *_args, **_kwargs: {
                "device_categories": ["server"],
                "manual_device_categories": ["server"],
                "device_category_override": True,
            },
        )

        self.assertEqual(11, result["host_id"])
        self.assertEqual(["server"], result["device_categories"])
        self.assertEqual(["server"], result["manual_device_categories"])
        self.assertTrue(result["device_category_override"])

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

    def test_runtime_workspace_read_module_reads_state_with_injected_getter(self):
        from app.web import runtime_workspace_read

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

        state_listing = runtime_workspace_read.get_target_state_view(
            runtime,
            limit=5,
            get_target_state_func=lambda _db, host_id: dict(state_rows.get(int(host_id), {})),
        )
        findings = runtime_workspace_read.get_findings(
            runtime,
            host_id=11,
            limit_findings=10,
            get_target_state_func=lambda _db, host_id: dict(state_rows.get(int(host_id), {})),
        )

        self.assertEqual(2, state_listing["count"])
        self.assertEqual("internal_recon", state_listing["states"][0]["target_state"]["engagement_preset"])
        self.assertEqual(1, findings["count"])
        self.assertEqual("SMB signing not required", findings["findings"][0]["title"])

    def test_runtime_workspace_module_resolves_host_and_related_lookup_data(self):
        from app.web import runtime_workspace

        runtime = _WorkspaceLookupRuntime()

        host = runtime_workspace.resolve_host(runtime, 11)
        cves = runtime_workspace.load_cves_for_host(runtime._project, 11)
        hostname = runtime_workspace.hostname_for_ip(runtime, "10.0.0.5")
        service_name = runtime_workspace.service_name_for_target(runtime, "10.0.0.5", "80", "tcp")

        self.assertEqual(11, host.id)
        self.assertEqual("dc01.local", hostname)
        self.assertEqual("http", service_name)
        self.assertEqual("CVE-2024-1111", cves[0]["name"])
        self.assertEqual("nginx", cves[0]["product"])

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

    def test_runtime_jobs_module_starts_finds_and_emits_job_events(self):
        from app.web import runtime_jobs

        runtime = _RuntimeJobsRuntime()

        started = runtime_jobs.start_job(
            runtime,
            "tool-run",
            lambda job_id: {"job_id": int(job_id), "ok": True},
            payload={"host_id": 11},
            queue_front=True,
            exclusive=True,
        )
        selected = runtime_jobs.find_active_job(runtime, job_type="scheduler-dig-deeper", host_id=11)

        self.assertEqual(19, started["id"])
        self.assertTrue(started["result"]["ok"])
        self.assertTrue(runtime.jobs.started["queue_front"])
        self.assertTrue(runtime.jobs.started["exclusive"])
        self.assertEqual(7, selected["id"])

        runtime_jobs.emit_ui_invalidation(runtime, "jobs", "overview", throttle_seconds=0.0)
        payload = runtime_jobs.wait_for_ui_event(runtime, after_seq=0, timeout_seconds=0.01)
        self.assertEqual("invalidate", payload["type"])
        self.assertEqual(["jobs", "overview"], payload["channels"])

        runtime_jobs.handle_job_change(runtime, {"type": "nmap-scan"}, "updated")
        payload = runtime_jobs.wait_for_ui_event(runtime, after_seq=payload["seq"], timeout_seconds=0.01)
        self.assertEqual("invalidate", payload["type"])
        self.assertIn("scan_history", payload["channels"])
        self.assertIn("processes", payload["channels"])

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

    def test_runtime_scheduler_config_module_normalizes_worker_and_report_delivery_settings(self):
        from app.web import runtime_scheduler_config

        delivery = runtime_scheduler_config.project_report_delivery_config({
            "project_report_delivery": {
                "method": "get",
                "format": "markdown",
                "headers": "{\"X-Test\": 1, \"\": \"skip\"}",
                "timeout_seconds": "999",
                "mtls": {"enabled": True, "client_cert_path": "/tmp/cert.pem"},
            }
        })

        self.assertEqual(8, runtime_scheduler_config.job_worker_count({"max_concurrency": "99"}))
        self.assertEqual("POST", delivery["method"])
        self.assertEqual("md", delivery["format"])
        self.assertEqual({"X-Test": "1"}, delivery["headers"])
        self.assertEqual(300, delivery["timeout_seconds"])
        self.assertTrue(delivery["mtls"]["enabled"])
        self.assertEqual("/tmp/cert.pem", delivery["mtls"]["client_cert_path"])

    def test_runtime_scheduler_state_module_normalizes_command_signatures(self):
        from app.web import runtime_scheduler_state

        signature_a = runtime_scheduler_state.command_signature_for_target(
            "nmap -Pn -oA /tmp/scan-a 10.0.0.5",
            "tcp",
        )
        signature_b = runtime_scheduler_state.command_signature_for_target(
            "nmap -Pn -oA /tmp/scan-b 10.0.0.5",
            "tcp",
        )

        self.assertTrue(signature_a)
        self.assertEqual(signature_a, signature_b)

    def test_runtime_scheduler_target_state_module_normalizes_targets_and_gaps(self):
        from app.web import runtime_scheduler_target_state

        signature = runtime_scheduler_target_state.command_signature_for_target(
            "whatweb http://10.0.0.5 > /tmp/run-a",
            "tcp",
        )
        targets = runtime_scheduler_target_state.scan_history_targets({
            "targets_json": "[\"10.0.0.5\", \"svc.example.com\"]",
        })
        gaps = runtime_scheduler_target_state.coverage_gaps_from_summary({
            "missing": ["http_metadata", "tls_inventory"],
            "recommended_tool_ids": ["httpx", "sslscan"],
            "analysis_mode": "ai",
            "stage": "enumeration",
            "host_cve_count": 2,
        })

        self.assertTrue(signature)
        self.assertEqual(["10.0.0.5", "svc.example.com"], targets)
        self.assertEqual("http_metadata", gaps[0]["gap_id"])
        self.assertEqual(["httpx", "sslscan"], gaps[0]["recommended_tool_ids"])
        self.assertEqual("ai", gaps[0]["analysis_mode"])

    def test_runtime_scheduler_inference_module_normalizes_technology_helpers(self):
        from app.web import runtime_scheduler_inference

        apache_version = runtime_scheduler_inference.sanitize_technology_version_for_tech(
            name="Apache HTTP Server",
            version="8.12",
            cpe="cpe:/a:apache:http_server:8.12",
            evidence="service fingerprint from nmap",
        )
        hints = runtime_scheduler_inference.guess_technology_hints(
            "nginx reverse proxy and php-fpm",
            version_hint="nginx 1.24 php 8.2",
        )
        evidence_rows = runtime_scheduler_inference.cve_evidence_lines(
            "nmap-vuln",
            "Starting Nmap\nCVE-2024-1111 remote issue\nNmap done:",
            strip_nmap_preamble_fn=lambda value: value.replace("Starting Nmap", "").replace("Nmap done:", ""),
        )

        self.assertEqual("", apache_version)
        self.assertIn(("nginx", "cpe:/a:nginx:nginx:1.24"), hints)
        self.assertIn(("PHP", "cpe:/a:php:php:8.2"), hints)
        self.assertEqual(
            "cpe:/a:apache:http_server",
            runtime_scheduler_inference.cpe_base("cpe:/a:apache:http_server:2.4.58"),
        )
        self.assertEqual([("CVE-2024-1111", "CVE-2024-1111 remote issue")], evidence_rows)
        self.assertTrue(runtime_scheduler_inference.is_placeholder_scheduler_text("...[truncated]"))

    def test_runtime_scheduler_capture_module_extracts_and_shapes_credentials(self):
        from app.web import runtime_scheduler_capture

        class _CaptureHelper:
            @staticmethod
            def _split_credential_principal(value):
                return ("CORP", "alice") if str(value or "").strip() else ("", "")

            @staticmethod
            def _extract_cleartext_password(details):
                return "P@ssw0rd!" if "clear text password" in str(details or "").lower() else ""

            @staticmethod
            def _normalize_credential_capture_source(source):
                return str(source or "").strip()

            @staticmethod
            def _extract_credential_data(line):
                return ("CORP\\alice", "11223344556677889900aabbccddeeff")

        row = runtime_scheduler_capture.build_scheduler_credential_row(
            _CaptureHelper,
            "responder",
            {"username": "CORP\\alice", "details": "clear text password: P@ssw0rd!", "hash_value": ""},
        )
        context = {}
        first = runtime_scheduler_capture.extract_credential_capture_entries(
            _CaptureHelper,
            "responder",
            "username: CORP\\alice",
            context=context,
        )
        second = runtime_scheduler_capture.extract_credential_capture_entries(
            _CaptureHelper,
            "responder",
            "hash: CORP::alice:1122",
            default_source="10.0.0.5",
            context=context,
        )

        self.assertEqual("alice", row["username"])
        self.assertEqual("cleartext_password", row["type"])
        self.assertEqual([], first)
        self.assertEqual("10.0.0.5", second[0]["source"])
        self.assertEqual("CORP\\alice", second[0]["username"])

    def test_runtime_scheduler_state_module_summarizes_existing_attempts(self):
        from app.web import runtime_scheduler_state

        runtime = _SchedulerStateRuntime()
        attempted_actions = {
            "attempted_actions": [
                {
                    "tool_id": "httpx",
                    "family_id": "family-state",
                    "command_signature": "state-signature",
                    "port": "80",
                    "protocol": "tcp",
                },
                {
                    "tool_id": "subfinder",
                    "family_id": "family-host-state",
                    "command_signature": "host-state-signature",
                    "port": "",
                    "protocol": "tcp",
                },
            ]
        }

        with mock.patch("app.web.runtime_scheduler_state.get_target_state", return_value=attempted_actions):
            summary = runtime_scheduler_state.existing_attempt_summary_for_target(
                runtime,
                11,
                "10.0.0.5",
                "80",
                "tcp",
            )

        self.assertEqual(
            {"httpx", "nuclei-web", "nmap-vuln.nse", "shodan-enrichment", "subfinder", "whatweb-http"},
            summary["tool_ids"],
        )
        self.assertEqual(
            {"family-host", "family-host-state", "family-port", "family-state"},
            summary["family_ids"],
        )
        self.assertIn("state-signature", summary["command_signatures"])
        self.assertIn("host-state-signature", summary["command_signatures"])
        self.assertIn(
            runtime_scheduler_state.command_signature_for_target(
                "whatweb http://10.0.0.5 > /tmp/run-a",
                "tcp",
            ).lower(),
            summary["command_signatures"],
        )

    def test_runtime_scheduler_state_module_normalizes_technology_helpers(self):
        from app.web import runtime_scheduler_state

        apache_version = runtime_scheduler_state.sanitize_technology_version_for_tech(
            name="Apache HTTP Server",
            version="8.12",
            cpe="cpe:/a:apache:http_server:8.12",
            evidence="service fingerprint from nmap",
        )
        hints = runtime_scheduler_state.guess_technology_hints(
            "nginx reverse proxy and php-fpm",
            version_hint="nginx 1.24 php 8.2",
        )

        self.assertEqual("", apache_version)
        self.assertIn(("nginx", "cpe:/a:nginx:nginx:1.24"), hints)
        self.assertIn(("PHP", "cpe:/a:php:php:8.2"), hints)
        self.assertEqual(
            "cpe:/a:apache:http_server",
            runtime_scheduler_state.cpe_base("cpe:/a:apache:http_server:2.4.58"),
        )

    def test_runtime_scheduler_state_module_extracts_cve_evidence_and_sorts_findings(self):
        from app.web import runtime_scheduler_state

        evidence_rows = runtime_scheduler_state.cve_evidence_lines(
            "nmap-vuln",
            "Starting Nmap\nCVE-2024-1111 remote issue\nNmap done:",
            strip_nmap_preamble_fn=lambda value: value.replace("Starting Nmap", "").replace("Nmap done:", ""),
        )
        ordered = sorted(
            [
                {"severity": "medium", "cvss": 5.4},
                {"severity": "critical", "cvss": 9.8},
                {"severity": "high", "cvss": 8.1},
            ],
            key=runtime_scheduler_state.finding_sort_key,
            reverse=True,
        )

        self.assertEqual([("CVE-2024-1111", "CVE-2024-1111 remote issue")], evidence_rows)
        self.assertEqual("critical", ordered[0]["severity"])
        self.assertEqual("high", runtime_scheduler_state.severity_from_text("High risk finding"))

    def test_runtime_processes_module_redacts_command_secrets(self):
        from app.web import runtime_processes

        redacted = runtime_processes.redact_command_secrets(
            "SHODAN_API_KEY=supersecret nuclei --api-key abc123 --token bearer123 Authorization=rawtoken"
        )

        self.assertNotIn("supersecret", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("bearer123", redacted)
        self.assertIn("***redacted***", redacted)

    def test_runtime_process_progress_module_builds_summary_payload(self):
        from app.web import runtime_process_progress

        payload = runtime_process_progress.build_process_progress_payload(
            status="Running",
            percent="42.5",
            estimated_remaining=125,
            elapsed=75,
            progress_message="Requests 85/200",
            progress_source="nuclei",
            progress_updated_at="2026-04-21T10:00:00+00:00",
        )

        self.assertTrue(payload["active"])
        self.assertEqual("42.5%", payload["percent_display"])
        self.assertEqual("Nuclei", payload["source"])
        self.assertIn("ETA", payload["summary"])
        self.assertIn("Requests 85/200", payload["summary"])

    def test_runtime_process_history_module_normalizes_iso_timestamp(self):
        from app.web import runtime_process_history

        normalized = runtime_process_history.normalize_process_timestamp_to_utc(
            "2026-04-21T10:00:00Z"
        )

        self.assertEqual("2026-04-21T10:00:00+00:00", normalized)

    def test_runtime_process_control_module_splits_retry_targets(self):
        from app.web import runtime_process_control

        targets = runtime_process_control.split_process_retry_targets("10.0.0.5, 10.0.0.6 10.0.0.5")

        self.assertEqual(["10.0.0.5", "10.0.0.6"], targets)

    def test_runtime_scheduler_excerpt_module_extracts_missing_nse_scripts(self):
        from app.web import runtime_scheduler_excerpt

        tokens = runtime_scheduler_excerpt.extract_missing_nse_script_tokens(
            "NSE: 'http-vuln-cve2021-41773.nse' did not match a category, filename, or directory"
        )

        self.assertEqual({"http-vuln-cve2021-41773.nse"}, tokens)

    def test_runtime_scheduler_summary_module_flags_missing_web_baseline(self):
        from app.web import runtime_scheduler_summary

        coverage = runtime_scheduler_summary.build_scheduler_coverage_summary(
            service_name="http",
            signals={"web_service": True, "vuln_hits": 0},
            observed_tool_ids={"nmap"},
            host_cves=[],
            inferred_technologies=[],
            analysis_mode="standard",
        )

        self.assertIn("missing_screenshot", coverage["missing"])
        self.assertIn("missing_nuclei_auto", coverage["missing"])

    def test_runtime_scheduler_observation_inference_module_extracts_urls(self):
        from app.web import runtime_scheduler_observation_inference

        runtime = SimpleNamespace()
        urls = runtime_scheduler_observation_inference.infer_urls_from_observations(
            runtime,
            script_records=[{
                "script_id": "curl-headers",
                "analysis_excerpt": "GET /admin HTTP/1.1\nLocation: https://example.test/admin",
                "port": "443",
                "protocol": "tcp",
                "service": "https",
                "host_ip": "10.0.0.5",
                "hostname": "example.test",
            }],
            process_records=[],
            limit=20,
        )

        self.assertTrue(urls)
        self.assertEqual("https://example.test/admin", urls[0]["url"])

    def test_runtime_scans_module_normalizes_targets_and_quick_recon_profile(self):
        from app.web import runtime_scans
        from app.web.runtime import WebRuntime

        targets = runtime_scans.normalize_targets(["10.0.0.5,10.0.0.6", "10.0.0.5 10.0.0.7"])
        options = runtime_scans.apply_engagement_scan_profile(
            WebRuntime,
            {"top_ports": 1000, "explicit_ports": ""},
            engagement_policy={"preset": "internal_quick_recon"},
        )

        self.assertEqual(["10.0.0.5", "10.0.0.6", "10.0.0.7"], targets)
        self.assertEqual(0, options["top_ports"])
        self.assertEqual(WebRuntime.INTERNAL_QUICK_RECON_TCP_PORTS, options["explicit_ports"])

    def test_runtime_scan_discovery_module_builds_httpx_bootstrap_command(self):
        from app.web import runtime_scan_discovery

        command = runtime_scan_discovery.httpx_bootstrap_command("/tmp/targets.txt", "/tmp/httpx-out")

        self.assertIn("httpx -silent -json", command)
        self.assertIn("/tmp/targets.txt", command)
        self.assertIn("/tmp/httpx-out.jsonl", command)

    def test_runtime_scan_capture_module_classifies_mdns_and_prioritizes_interfaces(self):
        from app.web import runtime_scan_capture

        labels = runtime_scan_capture.classify_passive_protocols(
            "eth:ethertype:ip:udp:mdns",
            ["5353"],
            "printer.local",
        )
        eth_key = runtime_scan_capture.preferred_capture_interface_sort_key({"name": "eth0"})
        docker_key = runtime_scan_capture.preferred_capture_interface_sort_key({"name": "docker0"})

        self.assertIn("mdns", labels)
        self.assertIn("bonjour", labels)
        self.assertLess(eth_key, docker_key)

    def test_runtime_scan_planning_module_builds_easy_scan_plan(self):
        from app.web import runtime_scan_planning

        plan = runtime_scan_planning.build_nmap_scan_plan(
            None,
            targets=["10.0.0.5"],
            discovery=True,
            staged=False,
            nmap_path="nmap",
            nmap_args="--defeat-rst-ratelimit",
            output_prefix="/tmp/scan-easy",
            scan_mode="easy",
            scan_options={},
        )

        self.assertEqual("/tmp/scan-easy.xml", plan["xml_path"])
        self.assertEqual(1, len(plan["stages"]))
        self.assertIn("-sV", plan["stages"][0]["command"])
        self.assertIn("-sC", plan["stages"][0]["command"])
        self.assertIn("--top-ports 1000", plan["stages"][0]["command"])

    def test_runtime_scan_nmap_module_starts_scan_job_and_records_submission(self):
        from app.web import runtime_scan_nmap

        recorded = {}

        runtime = SimpleNamespace(
            _normalize_targets=lambda targets: [str(item) for item in list(targets or [])],
            _start_job=lambda kind, _runner, payload=None: {"id": 41, "type": kind, "payload": dict(payload or {})},
            _record_scan_submission=lambda **kwargs: recorded.update(kwargs) or {"id": 7},
            _compact_targets=lambda targets: ",".join(str(item) for item in list(targets or [])),
        )

        job = runtime_scan_nmap.start_nmap_scan_job(
            runtime,
            ["10.0.0.5"],
            discovery=False,
            staged=True,
            run_actions=True,
            nmap_path="nmap-custom",
            nmap_args="-Pn",
            scan_mode="hard",
            scan_options={"full_ports": True},
        )

        self.assertEqual("nmap-scan", job["type"])
        self.assertEqual(["10.0.0.5"], job["payload"]["targets"])
        self.assertEqual("hard", job["payload"]["scan_mode"])
        self.assertEqual("nmap_scan", recorded["submission_kind"])
        self.assertEqual("queued nmap for 10.0.0.5", recorded["result_summary"])
        self.assertTrue(recorded["scan_options"]["full_ports"])

    def test_runtime_project_autosave_module_resolves_temp_and_persistent_paths(self):
        from app.web import runtime_project_autosave
        from app.paths import get_legion_autosave_dir

        temp_project = SimpleNamespace(
            properties=SimpleNamespace(
                projectName="/tmp/legion-temp.legion",
                isTemporary=True,
            )
        )
        non_temp_project = SimpleNamespace(
            properties=SimpleNamespace(
                projectName="/opt/projects/client-a.legion",
                isTemporary=False,
            )
        )

        temp_path = runtime_project_autosave.resolve_autosave_target_path(temp_project)
        non_temp_path = runtime_project_autosave.resolve_autosave_target_path(non_temp_project)

        self.assertTrue(temp_path.endswith(".autosave.legion"))
        self.assertIn(get_legion_autosave_dir(), temp_path)
        self.assertEqual("/opt/projects/client-a.autosave.legion", non_temp_path)

    def test_runtime_project_bundle_module_rejects_unsafe_relative_paths(self):
        from app.web import runtime_project_bundle

        self.assertEqual("", runtime_project_bundle.safe_bundle_relative_path("../../etc/passwd"))
        self.assertEqual("dir/file.txt", runtime_project_bundle.safe_bundle_relative_path("./dir/file.txt"))

    def test_runtime_project_bundle_archive_module_rejects_unsafe_relative_paths(self):
        from app.web import runtime_project_bundle_archive

        self.assertEqual("", runtime_project_bundle_archive.safe_bundle_relative_path("/tmp/../secret.txt"))
        self.assertEqual("tmp/report.txt", runtime_project_bundle_archive.safe_bundle_relative_path("/tmp/report.txt"))

    def test_runtime_project_bundle_archive_module_fails_on_extraction_errors(self):
        from app.web import runtime_project_bundle_archive

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_path = os.path.join(tmpdir, "bundle.zip")
            destination = os.path.join(tmpdir, "restore")
            with zipfile.ZipFile(bundle_path, "w") as archive:
                archive.writestr("bundle/tool-output/report.txt", "report")

            with zipfile.ZipFile(bundle_path, "r") as archive:
                original_open = archive.open

                def failing_open(name, *args, **kwargs):
                    if str(name or "") == "bundle/tool-output/report.txt":
                        raise OSError("simulated extraction failure")
                    return original_open(name, *args, **kwargs)

                archive.open = failing_open
                with self.assertRaisesRegex(ValueError, "Failed to extract bundled artifacts"):
                    runtime_project_bundle_archive.extract_zip_prefix_to_dir(
                        archive,
                        "bundle/tool-output",
                        destination,
                    )

    def test_runtime_project_bundle_export_module_adds_existing_file(self):
        from app.web import runtime_project_bundle_export

        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = os.path.join(tmpdir, "report.txt")
            bundle_path = os.path.join(tmpdir, "bundle.zip")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("report")
            with zipfile.ZipFile(bundle_path, "w") as archive:
                runtime_project_bundle_export.zip_add_file_if_exists(
                    archive,
                    source_path,
                    "bundle/report.txt",
                )
            with zipfile.ZipFile(bundle_path, "r") as archive:
                self.assertEqual(["bundle/report.txt"], archive.namelist())

    def test_runtime_project_bundle_export_module_fails_on_artifact_errors(self):
        from app.web import runtime_project_bundle_export

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "artifacts")
            os.makedirs(source_dir)
            source_path = os.path.join(source_dir, "report.txt")
            bundle_path = os.path.join(tmpdir, "bundle.zip")
            with open(source_path, "w", encoding="utf-8") as handle:
                handle.write("report")

            with zipfile.ZipFile(bundle_path, "w") as archive:
                original_write = archive.write

                def failing_write(path, *args, **kwargs):
                    if os.path.basename(str(path or "")) == "report.txt":
                        raise OSError("simulated archive failure")
                    return original_write(path, *args, **kwargs)

                archive.write = failing_write
                with self.assertRaisesRegex(ValueError, "Failed to add bundled artifacts"):
                    runtime_project_bundle_export.zip_add_dir_if_exists(
                        archive,
                        source_dir,
                        "bundle/tool-output",
                    )

    def test_runtime_project_bundle_restore_preserves_active_project_when_staged_init_fails(self):
        from app.web import runtime_project_bundle_restore

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_path = os.path.join(tmpdir, "bundle.zip")
            restored_project_path = os.path.join(tmpdir, "restored.legion")
            restored_running_folder = os.path.join(tmpdir, "restored-running")
            with open(bundle_path, "wb") as handle:
                handle.write(b"placeholder")
            with open(restored_project_path, "wb") as handle:
                handle.write(b"placeholder")
            os.makedirs(restored_running_folder)

            previous_db = SimpleNamespace(dispose=mock.MagicMock())
            restored_db = SimpleNamespace(dispose=mock.MagicMock())
            previous_project = SimpleNamespace(
                database=previous_db,
                properties=SimpleNamespace(runningFolder=os.path.join(tmpdir, "previous-running")),
            )
            restored_project = SimpleNamespace(
                database=restored_db,
                properties=SimpleNamespace(runningFolder=os.path.join(tmpdir, "new-running")),
            )
            project_manager = SimpleNamespace(
                openExistingProject=mock.MagicMock(return_value=restored_project),
                closeProject=mock.MagicMock(),
            )
            runtime = SimpleNamespace(
                _lock=threading.RLock(),
                _save_in_progress=False,
                logic=SimpleNamespace(activeProject=previous_project, projectManager=project_manager),
                _ensure_scheduler_table=mock.MagicMock(side_effect=RuntimeError("schema init failed")),
                _ensure_scheduler_approval_store=mock.MagicMock(),
                _ensure_process_tables=mock.MagicMock(),
                get_project_details=mock.MagicMock(return_value={}),
            )

            with mock.patch.object(
                    runtime_project_bundle_restore.web_runtime_project_bundle_archive,
                    "extract_project_bundle_zip",
                    return_value={
                        "manifest": {},
                        "restore_root": tmpdir,
                        "project_path": restored_project_path,
                        "output_folder": os.path.join(tmpdir, "output"),
                        "running_folder": restored_running_folder,
                    },
            ), mock.patch.object(
                    runtime_project_bundle_restore.web_runtime_project_bundle_rebase,
                    "rebase_restored_project_paths",
                    return_value=None,
            ):
                with self.assertRaisesRegex(RuntimeError, "schema init failed"):
                    runtime_project_bundle_restore.restore_project_bundle_zip_impl(runtime, bundle_path)

            self.assertIs(runtime.logic.activeProject, previous_project)
            restored_db.dispose.assert_called_once()
            previous_db.dispose.assert_not_called()
            project_manager.closeProject.assert_called_once_with(restored_project)

    def test_runtime_scan_nmap_uses_unique_output_prefix_per_job(self):
        from app.web import runtime_scan_nmap

        with tempfile.TemporaryDirectory() as tmpdir:
            prefixes = []
            host_repo = SimpleNamespace(getAllHostObjs=lambda: [])
            project = SimpleNamespace(
                properties=SimpleNamespace(runningFolder=tmpdir),
                repositoryContainer=SimpleNamespace(hostRepository=host_repo),
            )

            def build_plan(**kwargs):
                prefixes.append(kwargs["output_prefix"])
                raise RuntimeError("stop after prefix")

            runtime = SimpleNamespace(
                _lock=threading.RLock(),
                _require_active_project=lambda: project,
                _update_scan_submission_status=mock.MagicMock(),
                _compact_targets=lambda targets: ",".join(targets),
                _build_nmap_scan_plan=build_plan,
                _emit_ui_invalidation=mock.MagicMock(),
                jobs=SimpleNamespace(is_cancel_requested=lambda _job_id: False),
            )

            for job_id in (1, 2):
                with self.assertRaisesRegex(RuntimeError, "stop after prefix"):
                    runtime_scan_nmap.run_nmap_scan_and_import(
                        runtime,
                        targets=["10.0.0.5"],
                        discovery=True,
                        staged=False,
                        run_actions=False,
                        nmap_path="nmap",
                        nmap_args="",
                        job_id=job_id,
                    )

            self.assertEqual(2, len(prefixes))
            self.assertNotEqual(prefixes[0], prefixes[1])
            self.assertTrue(prefixes[0].endswith("-job-1"))
            self.assertTrue(prefixes[1].endswith("-job-2"))

    def test_runtime_project_bundle_rebase_module_rewrites_file_reference(self):
        from app.web import runtime_project_bundle_rebase

        result = runtime_project_bundle_rebase.rebase_restored_file_reference(
            "/old/output/report.txt",
            root_mappings=[("/old/output", "/new/output")],
            text_replacements=[("/old/output", "/new/output")],
            basename_index={},
        )

        self.assertEqual("/new/output/report.txt", result)

    def test_runtime_scheduler_trace_module_reads_tail_excerpt(self):
        from app.web import runtime_scheduler_trace

        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as handle:
            handle.write("alpha\nbeta\ngamma")
            path = handle.name
        try:
            excerpt = runtime_scheduler_trace.read_text_excerpt(path, max_chars=5)
        finally:
            os.remove(path)

        self.assertEqual("gamma", excerpt)

    def test_runtime_scheduler_config_module_reports_enabled_integrations(self):
        from app.web import runtime_scheduler_config

        runtime = SimpleNamespace(
            scheduler_config=SimpleNamespace(load=lambda: {
                "integrations": {
                    "shodan": {"api_key": "shodan-secret"},
                    "grayhatwarfare": {"api_key": "grayhat-secret"},
                }
            })
        )

        self.assertTrue(runtime_scheduler_config.shodan_integration_enabled(runtime))
        self.assertTrue(runtime_scheduler_config.grayhatwarfare_integration_enabled(runtime))
        self.assertTrue(runtime_scheduler_config.built_in_device_category_options())

    def test_runtime_scheduler_signals_module_detects_web_markers(self):
        from app.web import runtime_scheduler_signals

        runtime = SimpleNamespace(
            _observation_text_for_analysis=lambda _tool_id, text: str(text or ""),
        )

        signals = runtime_scheduler_signals.extract_scheduler_signals(
            runtime,
            service_name="http",
            scripts=[{
                "script_id": "http-headers",
                "analysis_excerpt": "Server: Microsoft-IIS/10.0\r\nAllow: OPTIONS, PROPFIND",
            }],
            recent_processes=[],
            target={
                "hostname": "web01.local",
                "host_open_services": ["http"],
            },
        )

        self.assertTrue(signals["web_service"])
        self.assertTrue(signals["iis_detected"])
        self.assertTrue(signals["webdav_detected"])
        self.assertIn("iis", signals["observed_technologies"])


if __name__ == "__main__":
    unittest.main()
