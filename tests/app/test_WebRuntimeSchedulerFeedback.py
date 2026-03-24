import unittest
import threading
import json
from unittest import mock
from types import SimpleNamespace


class WebRuntimeSchedulerFeedbackTest(unittest.TestCase):
    def test_shodan_enabled_uses_scheduler_integrations_key(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime.scheduler_config = SimpleNamespace(load=lambda: {
            "integrations": {
                "shodan": {
                    "api_key": "scheduler-owned-key",
                }
            }
        })

        self.assertTrue(runtime._shodan_integration_enabled())
        self.assertTrue(runtime._shodan_integration_enabled({
            "integrations": {
                "shodan": {
                    "api_key": "another-key",
                }
            }
        }))
        self.assertFalse(runtime._shodan_integration_enabled({
            "integrations": {
                "shodan": {
                    "api_key": "",
                }
            }
        }))

    def test_ingest_discovered_hosts_imports_targets_and_queues_subfinder_followup(self):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.state import get_target_state
        from app.web.runtime import WebRuntime
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            runtime = WebRuntime.__new__(WebRuntime)
            runtime._lock = threading.RLock()
            runtime.logic = SimpleNamespace(activeProject=project)

            captured = {}
            bootstrap_captured = {}

            def fake_start_nmap_scan_job(**kwargs):
                captured.update(kwargs)
                return {
                    "id": 91,
                    "type": "nmap-scan",
                    "payload": {"targets": list(kwargs.get("targets", []))},
                }

            def fake_start_httpx_bootstrap_job(targets):
                bootstrap_captured["targets"] = list(targets or [])
                return {
                    "id": 92,
                    "type": "httpx-bootstrap",
                    "payload": {"targets": list(targets or [])},
                }

            runtime.start_nmap_scan_job = fake_start_nmap_scan_job
            runtime.start_httpx_bootstrap_job = fake_start_httpx_bootstrap_job

            result = runtime._ingest_discovered_hosts(
                ["api.example.com", "admin.example.com", "api.example.com"],
                source_tool_id="subfinder",
            )

            host_rows = project.repositoryContainer.hostRepository.getAllHostObjs()
            imported_hosts = {
                str(getattr(item, "hostname", "") or getattr(item, "ip", "") or "").strip()
                for item in list(host_rows or [])
            }

            self.assertEqual({"api.example.com", "admin.example.com"}, set(result["added_hosts"]))
            self.assertEqual({"api.example.com", "admin.example.com"}, imported_hosts)
            self.assertEqual({"api.example.com", "admin.example.com"}, set(captured["targets"]))
            self.assertEqual({"api.example.com", "admin.example.com"}, set(bootstrap_captured["targets"]))
            self.assertFalse(bool(captured["run_actions"]))
            self.assertEqual("easy", captured["scan_mode"])
            self.assertEqual(100, int(captured["scan_options"]["top_ports"]))
            self.assertEqual(92, int(result["bootstrap_job"]["id"]))

            host_rows_by_name = {
                str(getattr(item, "hostname", "") or getattr(item, "ip", "") or "").strip(): item
                for item in list(host_rows or [])
            }
            subfinder_actions = []
            for host_name in ("api.example.com", "admin.example.com"):
                target_state = get_target_state(project.database, int(getattr(host_rows_by_name[host_name], "id", 0) or 0)) or {}
                for item in list(target_state.get("attempted_actions", []) or []):
                    if str(item.get("tool_id", "") or "").strip().lower() == "subfinder":
                        subfinder_actions.append(item)
            self.assertEqual(2, len(subfinder_actions))
        finally:
            project_manager.closeProject(project)

    def test_run_httpx_bootstrap_materializes_web_targets_and_runs_scoped_scheduler_followup(self):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.state import get_target_state
        from app.web.runtime import WebRuntime
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="api.example.com", ipv4="api.example.com", hostname="api.example.com")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.close()

            runtime = WebRuntime.__new__(WebRuntime)
            runtime._lock = threading.RLock()
            runtime.logic = SimpleNamespace(activeProject=project)
            runtime.jobs = SimpleNamespace(is_cancel_requested=lambda _job_id: False)

            scheduled = {}

            def fake_run_scheduler_actions_web(*, host_ids=None, dig_deeper=False, job_id=0):
                scheduled["host_ids"] = set(host_ids or set())
                scheduled["dig_deeper"] = bool(dig_deeper)
                scheduled["job_id"] = int(job_id or 0)
                return {"host_ids": sorted(int(item) for item in list(host_ids or set()))}

            def fake_run_command_with_tracking(**kwargs):
                output_prefix = str(kwargs.get("outputfile", "") or "")
                artifact_path = f"{output_prefix}.jsonl"
                with open(artifact_path, "w", encoding="utf-8") as handle:
                    handle.write(
                        '{"url":"https://api.example.com","host":"api.example.com","scheme":"https",'
                        '"port":"443","status-code":200,"title":"Portal","webserver":"nginx/1.25.3"}\n'
                    )
                return (
                    True,
                    "completed",
                    17,
                    {
                        "started_at": "",
                        "finished_at": "",
                        "stdout_ref": "",
                        "stderr_ref": "",
                        "artifact_refs": [artifact_path],
                    },
                )

            runtime._run_scheduler_actions_web = fake_run_scheduler_actions_web
            runtime._run_command_with_tracking = fake_run_command_with_tracking
            runtime.get_process_output = lambda *_args, **_kwargs: {"output": ""}

            with mock.patch("app.web.runtime.rebuild_evidence_graph"):
                result = runtime._run_httpx_bootstrap(["api.example.com"], job_id=0)

            port_rows = project.repositoryContainer.portRepository.getPortsByHostId(host_id)
            port_map = {
                str(getattr(item, "portId", "") or "").strip(): item
                for item in list(port_rows or [])
            }
            https_port = port_map.get("443")
            self.assertIsNotNone(https_port)
            self.assertEqual("open", str(getattr(https_port, "state", "") or "").strip().lower())

            service_row = project.repositoryContainer.serviceRepository.getServiceById(getattr(https_port, "serviceId", None))
            self.assertIsNotNone(service_row)
            self.assertEqual("https", str(getattr(service_row, "name", "") or "").strip().lower())

            self.assertEqual([host_id], list(result["materialized_hosts"]))
            self.assertEqual({host_id}, scheduled["host_ids"])
            self.assertFalse(bool(scheduled["dig_deeper"]))

            target_state = get_target_state(project.database, host_id) or {}
            attempted_httpx = [
                item for item in list(target_state.get("attempted_actions", []) or [])
                if str(item.get("tool_id", "") or "").strip().lower() == "httpx"
            ]
            observed_urls = {
                str(item.get("url", "") or "").strip()
                for item in list(target_state.get("urls", []) or [])
            }
            self.assertEqual(1, len(attempted_httpx))
            self.assertEqual("443", str(attempted_httpx[0].get("port", "") or "").strip())
            self.assertIn("https://api.example.com", observed_urls)
        finally:
            project_manager.closeProject(project)

    def test_existing_attempt_summary_treats_subfinder_as_host_scoped(self):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.state import upsert_target_state
        from app.web.runtime import WebRuntime
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="portal.example.com", ipv4="portal.example.com", hostname="portal.example.com")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "portal.example.com",
                "attempted_actions": [{
                    "tool_id": "subfinder",
                    "status": "executed",
                    "port": "80",
                    "protocol": "tcp",
                    "attempted_at": "2026-03-23T00:00:00Z",
                }],
            }, merge=True)

            runtime = WebRuntime.__new__(WebRuntime)
            runtime._lock = threading.RLock()
            runtime.logic = SimpleNamespace(activeProject=project)

            summary = runtime._existing_attempt_summary_for_target(
                host_id,
                "portal.example.com",
                "443",
                "tcp",
            )

            self.assertIn("subfinder", summary["tool_ids"])
        finally:
            project_manager.closeProject(project)

    def test_existing_attempt_summary_treats_shodan_as_host_scoped(self):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.state import upsert_target_state
        from app.web.runtime import WebRuntime
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="connect.example.com", ipv4="connect.example.com", hostname="connect.example.com")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "connect.example.com",
                "attempted_actions": [{
                    "tool_id": "shodan-enrichment",
                    "status": "executed",
                    "port": "",
                    "protocol": "tcp",
                    "attempted_at": "2026-03-24T00:00:00Z",
                }],
            }, merge=True)

            runtime = WebRuntime.__new__(WebRuntime)
            runtime._lock = threading.RLock()
            runtime.logic = SimpleNamespace(activeProject=project)

            summary = runtime._existing_attempt_summary_for_target(
                host_id,
                "connect.example.com",
                "443",
                "tcp",
            )

            self.assertIn("shodan-enrichment", summary["tool_ids"])
        finally:
            project_manager.closeProject(project)

    def test_find_active_job_filters_by_type_status_and_host(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime.jobs = SimpleNamespace(
            list_jobs=lambda limit=200: [
                {"id": 12, "type": "scheduler-dig-deeper", "status": "completed", "payload": {"host_id": 11}},
                {"id": 11, "type": "scheduler-dig-deeper", "status": "queued", "payload": {"host_id": 9}},
                {"id": 10, "type": "scheduler-dig-deeper", "status": "running", "payload": {"host_id": 11}},
            ]
        )

        selected = runtime._find_active_job(job_type="scheduler-dig-deeper", host_id=11)
        self.assertIsNotNone(selected)
        self.assertEqual(10, selected["id"])

    def test_start_host_dig_deeper_requires_ai_provider(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._resolve_host = lambda host_id: SimpleNamespace(id=int(host_id), ip="192.168.3.10")
        runtime.scheduler_config = SimpleNamespace(load=lambda: {
            "mode": "deterministic",
            "provider": "none",
            "providers": {},
        })
        runtime.jobs = SimpleNamespace(
            list_jobs=lambda limit=200: [],
            start=lambda *args, **kwargs: {"id": 1},
        )

        with self.assertRaises(ValueError):
            runtime.start_host_dig_deeper_job(11)

    def test_start_host_dig_deeper_deduplicates_existing_job(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._resolve_host = lambda host_id: SimpleNamespace(id=int(host_id), ip="192.168.3.10")
        runtime.scheduler_config = SimpleNamespace(load=lambda: {
            "mode": "ai",
            "provider": "openai",
            "providers": {"openai": {"enabled": True}},
        })
        runtime.jobs = SimpleNamespace(
            list_jobs=lambda limit=200: [
                {
                    "id": 55,
                    "type": "scheduler-dig-deeper",
                    "status": "running",
                    "payload": {"host_id": 11, "host_ip": "192.168.3.10", "dig_deeper": True},
                }
            ],
            start=lambda *args, **kwargs: {"id": 99},
        )

        result = runtime.start_host_dig_deeper_job(11)
        self.assertEqual(55, result["id"])
        self.assertTrue(result.get("existing"))

    def test_scheduler_feedback_config_clamps_values(self):
        from app.web.runtime import WebRuntime

        cfg = WebRuntime._scheduler_feedback_config({
            "ai_feedback": {
                "enabled": True,
                "max_rounds_per_target": 100,
                "max_actions_per_round": -3,
                "recent_output_chars": 10,
                "reflection_enabled": False,
                "stall_rounds_without_progress": 99,
                "stall_repeat_selection_threshold": 0,
                "max_reflections_per_target": 99,
            }
        })
        self.assertTrue(cfg["enabled"])
        self.assertEqual(12, cfg["max_rounds_per_target"])
        self.assertEqual(1, cfg["max_actions_per_round"])
        self.assertEqual(320, cfg["recent_output_chars"])
        self.assertFalse(cfg["reflection_enabled"])
        self.assertEqual(6, cfg["stall_rounds_without_progress"])
        self.assertEqual(1, cfg["stall_repeat_selection_threshold"])
        self.assertEqual(4, cfg["max_reflections_per_target"])

    def test_load_host_ai_analysis_exposes_last_reflection(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._normalize_ai_technologies = lambda items: list(items or [])
        runtime._normalize_ai_findings = lambda items: list(items or [])
        runtime._merge_technologies = lambda existing, incoming, limit=0: list(incoming or existing or [])
        runtime._merge_ai_items = lambda existing, incoming, key_fields=None, limit=0: list(incoming or existing or [])
        runtime._load_cves_for_host = lambda project, host_id: []
        runtime._infer_host_technologies = lambda project, host_id, host_ip: []
        runtime._infer_host_findings = lambda project, host_id, host_ip, host_cves_raw: []

        project = SimpleNamespace(database=object())
        ai_row = {
            "host_ip": "10.0.0.5",
            "provider": "openai",
            "goal_profile": "external_pentest",
            "last_port": "443",
            "last_protocol": "tcp",
            "last_service": "https",
            "hostname": "portal.local",
            "hostname_confidence": 92,
            "os_match": "Linux",
            "os_confidence": 77,
            "next_phase": "targeted_checks",
            "technologies": [{"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "banner"}],
            "findings": [{"title": "Admin portal", "severity": "medium", "cve": "", "evidence": "/admin"}],
            "manual_tests": [{"why": "validate auth", "command": "curl -k https://10.0.0.5/admin", "scope_note": "safe"}],
            "raw": {
                "reflection": {
                    "state": "stalled",
                    "priority_shift": "manual_validation",
                    "trigger_reason": "repeated_failures",
                    "reason": "Coverage has stopped moving.",
                    "promote_tool_ids": ["whatweb"],
                    "suppress_tool_ids": ["nikto"],
                }
            },
        }

        with mock.patch("app.web.runtime.ensure_scheduler_ai_state_table"), \
                mock.patch("app.web.runtime.get_host_ai_state", return_value=ai_row):
            loaded = runtime._load_host_ai_analysis(project, 11, "10.0.0.5")

        self.assertEqual("openai", loaded["provider"])
        self.assertEqual("stalled", loaded["reflection"]["state"])
        self.assertEqual("manual_validation", loaded["reflection"]["priority_shift"])
        self.assertEqual("repeated_failures", loaded["reflection"]["trigger_reason"])
        self.assertEqual(["nikto"], loaded["reflection"]["suppress_tool_ids"])

    def test_build_scheduler_context_summary_prioritizes_focus_failures_and_reflection(self):
        from app.web.runtime import WebRuntime

        summary = WebRuntime._build_scheduler_context_summary(
            target={
                "hostname": "edge.local",
                "os": "Linux",
                "service": "https",
                "port": "443",
                "protocol": "tcp",
                "service_product": "nginx",
                "service_version": "1.25.3",
            },
            analysis_mode="dig_deeper",
            coverage={
                "stage": "baseline",
                "missing": ["missing_nmap_vuln", "missing_nuclei_auto"],
                "recommended_tool_ids": ["nmap-vuln.nse", "nuclei-web"],
            },
            signals={
                "web_service": True,
                "tls_detected": True,
                "wordpress_detected": False,
            },
            attempted_tool_ids={"banner", "whatweb"},
            attempted_family_ids={"web:banner", "web:whatweb"},
            summary_technologies=[
                {"name": "Jetty", "version": "10.0.13", "cpe": "cpe:/a:eclipse:jetty:10.0.13"},
                {"name": "nginx", "version": "1.25.3", "cpe": "cpe:/a:nginx:nginx:1.25.3"},
            ],
            host_cves=[
                {"name": "CVE-2025-1111", "severity": "high", "product": "nginx"},
            ],
            host_ai_state={
                "next_phase": "deep_web",
                "findings": [{"title": "Admin console exposed", "severity": "medium", "cve": "", "evidence": "/admin"}],
                "manual_tests": [{"command": "curl -k https://10.0.0.5/admin", "why": "validate auth"}],
                "reflection": {
                    "state": "stalled",
                    "priority_shift": "manual_validation",
                    "trigger_reason": "phase_transition",
                    "reason": "Coverage plateaued",
                    "suppress_tool_ids": ["nikto"],
                    "promote_tool_ids": ["whatweb"],
                },
            },
            recent_processes=[
                {"tool_id": "feroxbuster", "status": "Crashed", "output_excerpt": "feroxbuster: command not found"},
            ],
            target_recent_processes=[
                {"tool_id": "ffuf", "status": "Failed", "output_excerpt": "timeout reached"},
            ],
        )

        self.assertEqual("dig_deeper", summary["focus"]["analysis_mode"])
        self.assertEqual("deep_web", summary["focus"]["current_phase"])
        self.assertIn("hostname: edge.local", summary["confirmed_facts"])
        self.assertIn("service: https on 443/tcp (nginx 1.25.3)", summary["confirmed_facts"])
        self.assertIn("missing_nmap_vuln", summary["coverage_missing"])
        self.assertIn("missing_nmap_vuln", summary["missing_coverage"])
        self.assertIn("nmap-vuln.nse", summary["recommended_tools"])
        self.assertIn("nmap-vuln.nse", summary["followup_candidates"])
        self.assertIn("tls_detected", summary["active_signals"])
        self.assertIn("Jetty 10.0.13", summary["known_technologies"])
        self.assertIn("Jetty 10.0.13", summary["likely_technologies"])
        self.assertTrue(any("Admin console exposed" in item for item in summary["top_findings"]))
        self.assertTrue(any("Admin console exposed" in item for item in summary["important_findings"]))
        self.assertIn("web:banner", summary["attempted_families"])
        self.assertTrue(any(item.startswith("ffuf:") or item.startswith("feroxbuster:") for item in summary["recent_failures"]))
        self.assertIn("banner", summary["recent_attempts"])
        self.assertIn("curl -k https://10.0.0.5/admin", summary["manual_tests"])
        self.assertEqual("stalled", summary["reflection_posture"]["state"])
        self.assertEqual("manual_validation", summary["reflection_posture"]["priority_shift"])
        self.assertEqual("phase_transition", summary["reflection_posture"]["trigger_reason"])

    def test_build_scheduler_rationale_feed_items_summarizes_scores_and_outcomes(self):
        from app.web.runtime import WebRuntime

        provider_logs = [{
            "timestamp": "2026-03-22T05:35:17+00:00",
            "request_body": json.dumps({
                "messages": [
                    {"role": "system", "content": "Return strict JSON only."},
                    {
                        "role": "user",
                        "content": (
                            "Context:\n"
                            "{\"target\":{\"host_ip\":\"192.168.3.133\",\"port\":\"5357\",\"protocol\":\"tcp\",\"service\":\"http\"}}\n"
                            "Candidates:\n"
                            "{\"tool_id\":\"nmap-vuln.nse\"}\n"
                            "{\"tool_id\":\"whatweb\"}\n"
                            "{\"tool_id\":\"nikto\"}\n"
                        ),
                    },
                ],
            }),
            "response_body": json.dumps({
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "actions": [
                                {"tool_id": "nmap-vuln.nse", "score": 92, "rationale": "Best baseline gap filler for the confirmed HTTP service."},
                                {"tool_id": "whatweb", "score": 84, "rationale": "Safe technology fingerprinting can refine Microsoft HTTPAPI evidence."},
                                {"tool_id": "nikto", "score": 78, "rationale": "Broad HTTP validation remains explicitly missing."},
                            ],
                            "host_updates": {},
                            "findings": [],
                            "manual_tests": [],
                            "next_phase": "protocol_checks",
                        })
                    }
                }]
            }),
            "prompt_metadata": {
                "prompt_type": "ranking",
                "prompt_profile": "web:broad_vuln",
                "current_phase": "broad_vuln",
                "visible_candidate_tool_ids": ["nmap-vuln.nse", "whatweb", "nikto"],
            },
        }]
        decisions = [{
            "id": 41,
            "timestamp": "22 Mar 2026 00:35:18.000000",
            "host_ip": "192.168.3.133",
            "port": "5357",
            "protocol": "tcp",
            "service": "http",
            "tool_id": "nmap-vuln.nse",
            "approved": "True",
            "executed": "True",
            "requires_approval": "False",
            "reason": "approved & completed",
            "rationale": "Best baseline gap filler for the confirmed HTTP service.",
        }]
        executions = [{
            "execution_id": "exec-12",
            "tool_id": "nmap-vuln.nse",
            "host_ip": "192.168.3.133",
            "port": "5357",
            "protocol": "tcp",
            "service": "http",
            "started_at": "2026-03-22T05:35:18+00:00",
            "exit_status": "0",
        }]

        feed = WebRuntime._build_scheduler_rationale_feed_items(provider_logs, decisions, executions, limit=10)

        self.assertEqual(1, len(feed))
        self.assertEqual("ranking", feed[0]["kind"])
        self.assertEqual("192.168.3.133", feed[0]["host_ip"])
        self.assertEqual("nmap-vuln.nse, whatweb, nikto", feed[0]["headline"])
        self.assertIn("Ranking", feed[0]["tags"])
        self.assertTrue(any("Scores: nmap-vuln.nse 92, whatweb 84, nikto 78" == line for line in feed[0]["details"]))
        self.assertTrue(any("Outcome: nmap-vuln.nse executed [exec-12, exit 0]" == line for line in feed[0]["details"]))
        self.assertTrue(any("Next phase: protocol_checks" == line for line in feed[0]["details"]))

    def test_build_scheduler_rationale_feed_filters_non_visible_model_suggestions(self):
        from app.web.runtime import WebRuntime

        provider_logs = [{
            "timestamp": "2026-03-22T05:35:09+00:00",
            "request_body": json.dumps({
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "{\"target\":{\"host_ip\":\"192.168.3.133\",\"port\":\"5357\",\"protocol\":\"tcp\",\"service\":\"http\"}}\n"
                            "Candidates:\n"
                            "{\"tool_id\":\"curl-headers\"}\n"
                            "{\"tool_id\":\"curl-options\"}\n"
                        ),
                    }
                ],
            }),
            "response_body": json.dumps({
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "focus": "tech_validation",
                            "selected_tool_ids": ["curl-headers", "nmap-vuln.nse"],
                            "reason": "Validate the observed HTTP stack with bounded read-only checks.",
                            "manual_tests": [],
                        })
                    }
                }]
            }),
            "prompt_metadata": {
                "prompt_type": "web_followup",
                "prompt_profile": "web",
                "current_phase": "broad_vuln",
                "visible_candidate_tool_ids": ["curl-headers", "curl-options"],
            },
        }]

        feed = WebRuntime._build_scheduler_rationale_feed_items(provider_logs, [], [], limit=10)

        self.assertEqual(1, len(feed))
        self.assertEqual("curl-headers", feed[0]["headline"])
        self.assertTrue(any("Ignored out-of-scope suggestions: nmap-vuln.nse" == line for line in feed[0]["details"]))

    def test_tool_audit_availability_tracks_installed_and_missing_tools(self):
        from app.web.runtime import WebRuntime

        snapshot = WebRuntime._tool_audit_availability([
            {"key": "whatweb", "status": "installed"},
            {"key": "nikto", "status": "missing"},
            {"key": "dirsearch", "status": "configured-missing"},
            {"key": "curl", "status": "installed"},
        ])

        self.assertEqual(["curl", "whatweb"], snapshot["available_tool_ids"])
        self.assertEqual(["dirsearch", "nikto"], snapshot["unavailable_tool_ids"])

    def test_context_summary_does_not_treat_wrapper_command_excerpt_as_missing_tool(self):
        from app.web.runtime import WebRuntime

        summary = WebRuntime._build_scheduler_context_summary(
            target={"service": "http", "service_product": "nginx"},
            analysis_mode="standard",
            coverage={},
            signals={},
            attempted_tool_ids=set(),
            recent_processes=[
                {
                    "tool_id": "whatweb-http",
                    "status": "Finished",
                    "command_excerpt": "(command -v whatweb >/dev/null 2>&1 && whatweb http://unifi.local:8080 --color=never) || echo whatweb not found",
                    "output_excerpt": "http://unifi.local:8080 [400 Bad Request] nginx, HTML5",
                }
            ],
            target_recent_processes=[
                {
                    "tool_id": "whatweb-http",
                    "status": "Finished",
                    "command_excerpt": "(command -v whatweb >/dev/null 2>&1 && whatweb http://unifi.local:8080 --color=never) || echo whatweb not found",
                    "output_excerpt": "http://unifi.local:8080 [400 Bad Request] nginx, HTML5",
                }
            ],
        )

        self.assertNotIn("recent_failures", summary)

    def test_scheduler_max_concurrency_clamps_values(self):
        from app.web.runtime import WebRuntime

        self.assertEqual(1, WebRuntime._scheduler_max_concurrency({"max_concurrency": "x"}))
        self.assertEqual(1, WebRuntime._scheduler_max_concurrency({"max_concurrency": 0}))
        self.assertEqual(16, WebRuntime._scheduler_max_concurrency({"max_concurrency": 24}))
        self.assertEqual(6, WebRuntime._scheduler_max_concurrency({"max_concurrency": 6}))

    def test_scheduler_max_host_concurrency_clamps_values(self):
        from app.web.runtime import WebRuntime

        self.assertEqual(1, WebRuntime._scheduler_max_host_concurrency({"max_host_concurrency": "x"}))
        self.assertEqual(1, WebRuntime._scheduler_max_host_concurrency({"max_host_concurrency": 0}))
        self.assertEqual(8, WebRuntime._scheduler_max_host_concurrency({"max_host_concurrency": 24}))
        self.assertEqual(4, WebRuntime._scheduler_max_host_concurrency({"max_host_concurrency": 4}))

    def test_scheduler_max_jobs_clamps_values(self):
        from app.web.runtime import WebRuntime

        self.assertEqual(200, WebRuntime._scheduler_max_jobs({"max_jobs": "x"}))
        self.assertEqual(20, WebRuntime._scheduler_max_jobs({"max_jobs": 0}))
        self.assertEqual(2000, WebRuntime._scheduler_max_jobs({"max_jobs": 99999}))
        self.assertEqual(350, WebRuntime._scheduler_max_jobs({"max_jobs": 350}))

    def test_group_scheduler_targets_by_host_preserves_host_order(self):
        from app.web.runtime import WebRuntime

        targets = [
            SimpleNamespace(host_id=11, host_ip="10.0.0.5", hostname="host-a", port="80"),
            SimpleNamespace(host_id=12, host_ip="10.0.0.6", hostname="host-b", port="22"),
            SimpleNamespace(host_id=11, host_ip="10.0.0.5", hostname="host-a", port="443"),
        ]

        groups = WebRuntime._group_scheduler_targets_by_host(targets)

        self.assertEqual(2, len(groups))
        self.assertEqual(["80", "443"], [item.port for item in groups[0]])
        self.assertEqual(["22"], [item.port for item in groups[1]])

    def test_run_scheduler_targets_can_fan_out_by_host_for_easy_scan(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        barrier = threading.Barrier(2, timeout=1.0)
        parallel_hits = []

        def run_targets(**kwargs):
            try:
                barrier.wait()
                parallel_hits.append(True)
            except threading.BrokenBarrierError:
                parallel_hits.append(False)
            target_count = len(list(kwargs.get("targets", []) or []))
            return {
                "considered": target_count,
                "approval_queued": 0,
                "executed": target_count,
                "skipped": 0,
                "host_scope_count": target_count,
                "dig_deeper": False,
                "reflections": 0,
                "reflection_stops": 0,
            }

        runtime.scheduler_orchestrator = SimpleNamespace(run_targets=run_targets)
        targets = [
            SimpleNamespace(host_id=11, host_ip="10.0.0.5", hostname="host-a", port="80"),
            SimpleNamespace(host_id=12, host_ip="10.0.0.6", hostname="host-b", port="443"),
        ]

        summary = runtime._run_scheduler_targets(
            settings=SimpleNamespace(),
            targets=targets,
            engagement_policy={},
            options=SimpleNamespace(host_concurrency=2, dig_deeper=False),
            should_cancel=None,
            existing_attempts=None,
            build_context=None,
            on_ai_analysis=None,
            reflect_progress=None,
            on_reflection_analysis=None,
            handle_blocked=None,
            handle_approval=None,
            execute_batch=None,
            on_execution_result=None,
        )

        self.assertEqual([True, True], sorted(parallel_hits))
        self.assertEqual(2, summary["considered"])
        self.assertEqual(2, summary["executed"])

    def test_extract_scheduler_signals_detects_common_markers(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="https",
            scripts=[
                {"script_id": "ssl-cert", "excerpt": "Subject: CN=portal.local; CVE-2025-1111"},
                {"script_id": "smb-security-mode", "excerpt": "message signing enabled but not required"},
            ],
            recent_processes=[
                {"tool_id": "nuclei-web", "status": "Finished", "output_excerpt": "CVE-2024-9999 found"},
                {"tool_id": "feroxbuster", "status": "Crashed", "output_excerpt": "feroxbuster: command not found"},
            ],
        )

        self.assertTrue(signals["web_service"])
        self.assertTrue(signals["tls_detected"])
        self.assertTrue(signals["smb_signing_disabled"])
        self.assertGreaterEqual(int(signals["vuln_hits"]), 2)
        self.assertIn("feroxbuster", signals["missing_tools"])

    def test_extract_scheduler_signals_marks_missing_nse_scripts_unavailable(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="http",
            scripts=[],
            recent_processes=[
                {
                    "tool_id": "http-wordpress-plugins.nse",
                    "status": "Problem",
                    "output_excerpt": (
                        "NSE: failed to initialize the script engine:\n"
                        "/usr/bin/../share/nmap/nse_main.lua:818: "
                        "'http-wordpress-plugins.nse' did not match a category, filename, or directory"
                    ),
                }
            ],
        )

        self.assertIn("http-wordpress-plugins.nse", signals["missing_tools"])

    def test_extract_scheduler_signals_marks_tool_dependency_tracebacks_unavailable(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="https",
            scripts=[],
            recent_processes=[
                {
                    "tool_id": "sslyze",
                    "status": "Problem",
                    "output_excerpt": (
                        "Traceback (most recent call last):\n"
                        "  File \"/usr/local/bin/sslyze\", line 3, in <module>\n"
                        "    from sslyze.__main__ import main\n"
                        "ModuleNotFoundError: No module named 'cryptography.hazmat.backends.openssl.ocsp'"
                    ),
                },
                {
                    "tool_id": "wafw00f",
                    "status": "Problem",
                    "output_excerpt": (
                        "Traceback (most recent call last):\n"
                        "  File \"/usr/bin/wafw00f\", line 4, in <module>\n"
                        "    from wafw00f import main\n"
                        "ImportError: cannot import name 'MutableMapping' from 'collections'"
                    ),
                },
            ],
        )

        self.assertIn("sslyze", signals["missing_tools"])
        self.assertIn("wafw00f", signals["missing_tools"])

    def test_persist_scheduler_ai_analysis_keeps_target_state_scoped_to_current_payload(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime.logic = SimpleNamespace(activeProject=SimpleNamespace(database=object()))
        runtime._normalize_ai_technologies = lambda items: list(items or [])
        runtime._normalize_ai_findings = lambda items: list(items or [])
        runtime._normalize_ai_manual_tests = lambda items: list(items or [])
        runtime._sanitize_ai_hostname = lambda value: str(value or "").strip()
        runtime._ai_confidence_value = lambda value: float(value or 0.0)
        runtime._load_cves_for_host = lambda project, host_id: []
        runtime._infer_host_technologies = lambda project, host_id, host_ip: [
            {"name": "OpenSSH", "version": "9.0", "cpe": "cpe:/a:openbsd:openssh:9.0", "evidence": "22/tcp"}
        ]
        runtime._merge_technologies = lambda existing, incoming, limit=220: list(incoming or []) + list(existing or [])
        runtime._infer_host_findings = lambda project, host_id, host_ip, host_cves_raw: [
            {"title": "Host wide stale finding", "severity": "medium", "cve": "", "evidence": "host scope"}
        ]
        runtime._merge_ai_items = lambda existing, incoming, key_fields=None, limit=0: list(incoming or []) + list(existing or [])
        runtime._apply_ai_host_updates = lambda **kwargs: None

        captured = {}
        runtime._persist_shared_target_state = lambda **kwargs: captured.update(kwargs)

        existing_state = {
            "provider": "openai",
            "goal_profile": "internal_asset_discovery",
            "engagement_preset": "internal_recon",
            "findings": [{"title": "Older host finding", "severity": "medium", "cve": "", "evidence": "older"}],
            "technologies": [{"name": "OpenSSH", "version": "9.0", "cpe": "cpe:/a:openbsd:openssh:9.0", "evidence": "22/tcp"}],
            "manual_tests": [{"why": "host check", "command": "echo host", "scope_note": ""}],
            "raw": {},
        }

        with mock.patch("app.web.runtime.ensure_scheduler_ai_state_table"), \
                mock.patch("app.web.runtime.get_host_ai_state", return_value=existing_state), \
                mock.patch("app.web.runtime.upsert_host_ai_state") as upsert_host_state:
            runtime._persist_scheduler_ai_analysis(
                host_id=11,
                host_ip="10.0.0.5",
                port="443",
                protocol="tcp",
                service_name="https",
                goal_profile="internal_asset_discovery",
                provider_payload={
                    "provider": "openai",
                    "host_updates": {
                        "hostname": "portal.local",
                        "hostname_confidence": 90,
                        "os": "Linux",
                        "os_confidence": 75,
                    },
                    "technologies": [
                        {"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "443/tcp"}
                    ],
                    "findings": [
                        {"title": "Target-specific web finding", "severity": "medium", "cve": "", "evidence": "/admin"}
                    ],
                    "manual_tests": [
                        {"why": "validate web", "command": "curl -k https://10.0.0.5/admin", "scope_note": "safe"}
                    ],
                    "next_phase": "targeted_checks",
                },
            )

        persisted_titles = {str(item.get("title", "")).strip() for item in list(captured.get("findings", []) or [])}
        persisted_technologies = {str(item.get("name", "")).strip() for item in list(captured.get("technologies", []) or [])}
        persisted_commands = {str(item.get("command", "")).strip() for item in list(captured.get("manual_tests", []) or [])}
        host_state_payload = dict(upsert_host_state.call_args.args[2] or {})

        self.assertEqual({"Target-specific web finding"}, persisted_titles)
        self.assertEqual({"nginx"}, persisted_technologies)
        self.assertEqual({"curl -k https://10.0.0.5/admin"}, persisted_commands)
        self.assertFalse(bool(host_state_payload.get("_sync_target_state", True)))

    def test_scheduler_prompt_excerpt_preserves_high_signal_lines(self):
        from app.web.runtime import WebRuntime

        raw_output = "\n".join(
            [
                "HTTP/1.1 200 OK",
                "Header check started",
            ]
            + [f"filler line {idx} with repeated body text" for idx in range(40)]
            + [
                "Server: Jetty/10.0.13",
                "Allow: GET, POST, OPTIONS, PROPFIND",
                "Interesting path: /api-docs (302)",
                "timeout reached while checking redirect chain",
            ]
        )

        excerpt = WebRuntime._build_scheduler_prompt_excerpt(raw_output, 220)

        self.assertLessEqual(len(excerpt), 220)
        self.assertIn("Server: Jetty/10.0.13", excerpt)
        self.assertIn("PROPFIND", excerpt)
        self.assertIn("/api-docs", excerpt)
        self.assertIn("...[truncated]", excerpt)

    def test_extract_scheduler_signals_prefers_analysis_excerpt(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="http",
            scripts=[],
            recent_processes=[
                {
                    "tool_id": "curl-headers",
                    "status": "Finished",
                    "output_excerpt": "headers checked",
                    "analysis_excerpt": "HTTP/1.1 200 OK\nAllow: GET, POST, OPTIONS, PROPFIND",
                }
            ],
        )

        self.assertTrue(signals["webdav_detected"])
        self.assertIn("webdav", signals["observed_technologies"])

    def test_infer_technologies_prefers_analysis_excerpt_when_prompt_excerpt_is_compact(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "curl-headers",
                    "output_excerpt": "headers checked",
                    "analysis_excerpt": "HTTP/1.1 200 OK\nServer: Jetty(10.0.13)\nAllow: GET, POST, OPTIONS",
                }
            ],
            limit=16,
        )

        names = {str(item.get("name", "")).lower() for item in technologies}
        self.assertIn("jetty", names)

    def test_extract_scheduler_signals_uses_target_metadata_for_vendor_fingerprint(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="https",
            scripts=[{"script_id": "http-title", "excerpt": "UniFi OS"}],
            recent_processes=[],
            target={
                "hostname": "unknown",
                "os": "unknown",
                "service": "https",
                "service_product": "nginx",
                "service_extrainfo": "Ubiquiti UniFi Dream Machine",
                "host_open_services": ["http", "https", "domain"],
            },
        )

        self.assertTrue(signals["ubiquiti_detected"])
        self.assertFalse(signals["vmware_detected"])
        self.assertIn("ubiquiti", signals["observed_technologies"])

    def test_extract_scheduler_signals_detects_cloud_provider_and_storage_markers(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="https",
            scripts=[],
            recent_processes=[
                {
                    "tool_id": "nuclei-cloud",
                    "status": "Finished",
                    "output_excerpt": (
                        "[aws-public-bucket] [http] [medium] https://tenant-assets.s3.amazonaws.com "
                        "Amazon S3 bucket listing exposed x-amz-request-id: 1234"
                    ),
                }
            ],
            target={
                "hostname": "tenant-assets.s3.amazonaws.com",
                "service": "https",
                "host_open_services": ["https"],
            },
        )

        self.assertTrue(signals["cloud_provider_detected"])
        self.assertTrue(signals["aws_detected"])
        self.assertTrue(signals["storage_service_detected"])
        self.assertTrue(signals["aws_storage_detected"])
        self.assertIn("aws", signals["observed_technologies"])
        self.assertIn("cloud_storage", signals["observed_technologies"])

    def test_extract_scheduler_signals_detects_managed_db_markers(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="postgresql",
            scripts=[],
            recent_processes=[
                {
                    "tool_id": "nuclei-cloud",
                    "status": "Finished",
                    "output_excerpt": (
                        "[aws-rds-endpoint] [tcp] [info] db-prod.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com "
                        "Amazon Aurora PostgreSQL endpoint"
                    ),
                },
                {
                    "tool_id": "nuclei-cloud",
                    "status": "Finished",
                    "output_excerpt": (
                        "[azure-cosmos-endpoint] [http] [info] https://tenant.documents.azure.com "
                        "Azure Cosmos DB endpoint"
                    ),
                },
            ],
            target={
                "hostname": "db-prod.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com",
                "service": "postgresql",
                "host_open_services": ["postgresql"],
            },
        )

        self.assertTrue(signals["cloud_provider_detected"])
        self.assertTrue(signals["rds_detected"])
        self.assertTrue(signals["aurora_detected"])
        self.assertTrue(signals["cosmos_detected"])
        self.assertTrue(signals["postgresql_detected"])
        self.assertIn("aurora", signals["observed_technologies"])
        self.assertIn("cosmos", signals["observed_technologies"])

    def test_extract_scheduler_signals_detects_internal_database_services(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="mysql",
            scripts=[],
            recent_processes=[
                {
                    "tool_id": "mysql-info.nse",
                    "status": "Finished",
                    "output_excerpt": "Version: 10.6.18-MariaDB Authentication Plugin Name: mysql_native_password",
                }
            ],
            target={
                "hostname": "db.internal.example",
                "service": "mysql",
                "host_open_services": ["mysql"],
            },
        )

        self.assertTrue(signals["mysql_detected"])
        self.assertFalse(signals["postgresql_detected"])
        self.assertFalse(signals["mssql_detected"])
        self.assertIn("mysql", signals["observed_technologies"])

    def test_extract_scheduler_signals_ignores_script_and_tool_names_without_positive_evidence(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        signals = runtime._extract_scheduler_signals(
            service_name="http",
            scripts=[
                {"script_id": "http-wordpress-enum.nse", "excerpt": ""},
                {"script_id": "http-vmware-path-vuln.nse", "excerpt": "check completed"},
                {"script_id": "http-coldfusion-subzero.nse", "excerpt": ""},
                {"script_id": "http-huawei-hg5xx-vuln.nse", "excerpt": ""},
                {"script_id": "http-iis-webdav-vuln.nse", "excerpt": "no issue reported"},
                {"script_id": "http-vuln-cve2011-3192.nse", "excerpt": "range header check completed with no finding"},
            ],
            recent_processes=[
                {"tool_id": "nuclei-wordpress", "status": "Finished", "output_excerpt": ""},
                {"tool_id": "wafw00f", "status": "Finished", "output_excerpt": ""},
            ],
            target={
                "service": "http",
                "service_product": "nginx",
                "host_open_services": ["http"],
                "host_banners": ["80/tcp:nginx"],
            },
        )

        self.assertFalse(signals["wordpress_detected"])
        self.assertFalse(signals["vmware_detected"])
        self.assertFalse(signals["coldfusion_detected"])
        self.assertFalse(signals["huawei_detected"])
        self.assertFalse(signals["webdav_detected"])
        self.assertFalse(signals["waf_detected"])
        self.assertEqual(0, int(signals["vuln_hits"]))
        self.assertNotIn("wordpress", signals["observed_technologies"])
        self.assertNotIn("vmware", signals["observed_technologies"])
        self.assertNotIn("coldfusion", signals["observed_technologies"])
        self.assertNotIn("huawei", signals["observed_technologies"])
        self.assertNotIn("webdav", signals["observed_technologies"])

    def test_build_scheduler_coverage_summary_flags_missing_web_baseline(self):
        from app.web.runtime import WebRuntime

        coverage = WebRuntime._build_scheduler_coverage_summary(
            service_name="http",
            signals={"web_service": True, "rdp_service": False, "vnc_service": False},
            observed_tool_ids={"nmap", "banner"},
            host_cves=[],
            inferred_technologies=[],
            analysis_mode="standard",
        )

        self.assertIn("missing_screenshot", coverage["missing"])
        self.assertIn("missing_nmap_vuln", coverage["missing"])
        self.assertIn("missing_nuclei_auto", coverage["missing"])
        self.assertIn("screenshooter", coverage["recommended_tool_ids"])
        self.assertIn("nmap-vuln.nse", coverage["recommended_tool_ids"])
        self.assertIn("nuclei-web", coverage["recommended_tool_ids"])

    def test_build_scheduler_coverage_summary_reports_deep_analysis_for_dig_deeper(self):
        from app.web.runtime import WebRuntime

        coverage = WebRuntime._build_scheduler_coverage_summary(
            service_name="https",
            signals={"web_service": True, "rdp_service": False, "vnc_service": False},
            observed_tool_ids={
                "nmap",
                "screenshooter",
                "nmap-vuln.nse",
                "nuclei-web",
                "whatweb",
                "nikto",
                "web-content-discovery",
                "curl-headers",
                "sslscan",
                "testssl.sh",
                "wafw00f",
            },
            host_cves=[],
            inferred_technologies=[{"name": "Jetty", "version": "10.0.13", "cpe": "cpe:/a:eclipse:jetty:10.0.13", "evidence": "service"}],
            analysis_mode="dig_deeper",
        )

        self.assertEqual("deep_analysis", coverage["stage"])
        self.assertEqual([], coverage["missing"])

    def test_build_scheduler_coverage_summary_flags_missing_internal_safe_enum(self):
        from app.web.runtime import WebRuntime

        coverage = WebRuntime._build_scheduler_coverage_summary(
            service_name="smb",
            signals={"web_service": False, "rdp_service": False, "vnc_service": False},
            observed_tool_ids={"banner", "smb-security-mode"},
            host_cves=[],
            inferred_technologies=[],
            analysis_mode="standard",
        )

        self.assertIn("missing_internal_safe_enum", coverage["missing"])
        self.assertIn("enum4linux-ng", coverage["recommended_tool_ids"])
        self.assertIn("smbmap", coverage["recommended_tool_ids"])
        self.assertIn("rpcclient-enum", coverage["recommended_tool_ids"])

    def test_infer_technologies_from_service_product_adds_jetty_cpe(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[
                {
                    "port": "8082",
                    "protocol": "tcp",
                    "service_name": "http",
                    "service_product": "Jetty",
                    "service_version": "10.0.13",
                    "service_extrainfo": "Traccar",
                    "banner": "Traccar",
                }
            ],
            script_records=[],
            process_records=[],
            limit=32,
        )
        names = {str(item.get("name", "")).lower() for item in technologies}
        cpes = {str(item.get("cpe", "")).lower() for item in technologies}
        self.assertIn("jetty", names)
        self.assertIn("cpe:/a:eclipse:jetty:10.0.13", cpes)
        self.assertIn("traccar", names)

    def test_infer_technologies_extracts_cpe_tokens_from_output(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[
                {
                    "script_id": "nmap-vuln.nse",
                    "excerpt": "Service Info: CPE: cpe:/a:eclipse:jetty:10.0.13",
                }
            ],
            process_records=[],
            limit=32,
        )
        cpes = {str(item.get("cpe", "")).lower() for item in technologies}
        self.assertIn("cpe:/a:eclipse:jetty:10.0.13", cpes)

    def test_infer_technologies_prefers_stronger_signal_and_filters_weak_noise(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[
                {
                    "port": "22",
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "service_product": "OpenSSH",
                    "service_version": "8.4p1 Debian 5+deb11u3",
                    "service_extrainfo": "protocol 2.0",
                    "banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
                },
                {
                    "port": "5002",
                    "protocol": "tcp",
                    "service_name": "rfe",
                    "service_product": "",
                    "service_version": "",
                    "service_extrainfo": "",
                    "banner": "",
                },
            ],
            script_records=[
                {
                    "script_id": "nmap-vuln.nse",
                    "excerpt": (
                        "Starting Nmap 7.80 ( https://nmap.org ) "
                        "OpenSSH_8.4p1 Debian 5+deb11u3"
                    ),
                }
            ],
            process_records=[
                {
                    "tool_id": "banner",
                    "output_excerpt": "SSH banner: SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
                },
                {
                    "tool_id": "banner",
                    "output_excerpt": "fingerprint token OpenSSH 192.168.3.135",
                },
            ],
            limit=80,
        )

        names = {str(item.get("name", "")).lower() for item in technologies}
        self.assertIn("openssh", names)
        self.assertNotIn("rfe", names)

        openssh_rows = [item for item in technologies if str(item.get("name", "")).strip().lower() == "openssh"]
        self.assertEqual(1, len(openssh_rows))
        self.assertNotEqual("192.168.3.135", str(openssh_rows[0].get("version", "")))

    def test_coverage_summary_requests_cpe_cve_enrichment_when_missing(self):
        from app.web.runtime import WebRuntime

        coverage = WebRuntime._build_scheduler_coverage_summary(
            service_name="https",
            signals={"web_service": True, "rdp_service": False, "vnc_service": False, "vuln_hits": 0},
            observed_tool_ids={"nmap", "screenshooter"},
            host_cves=[],
            inferred_technologies=[
                {
                    "name": "OpenSSH",
                    "version": "8.4p1",
                    "cpe": "cpe:/a:openbsd:openssh:8.4p1",
                    "evidence": "SSH banner on 22/tcp",
                }
            ],
            analysis_mode="standard",
        )

        self.assertIn("missing_cpe_cve_enrichment", coverage["missing"])
        self.assertIn("nmap-vuln.nse", coverage["recommended_tool_ids"])
        self.assertIn("nuclei-web", coverage["recommended_tool_ids"])

    def test_infer_technologies_detects_pihole_from_http_title_and_comment(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[
                {
                    "script_id": "http-title",
                    "excerpt": (
                        "<title>Pi-hole Cray4.hyrule.local</title> "
                        "Pi-hole: A black hole for Internet advertisements "
                        "(c) 2017 Pi-hole, LLC"
                    ),
                }
            ],
            process_records=[],
            limit=32,
        )

        pihole_rows = [
            item for item in technologies
            if str(item.get("name", "")).strip().lower() == "pi-hole"
        ]
        self.assertEqual(1, len(pihole_rows))
        self.assertEqual("", str(pihole_rows[0].get("version", "")).strip())

    def test_infer_technologies_uses_tool_specific_whatweb_and_httpx_parsers(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "whatweb-http",
                    "output_excerpt": (
                        "https://portal.example [200 OK] Apache[2.4.57], PHP[8.2.8], "
                        "Country[UNITED STATES][US], HTTPServer[Apache/2.4.57 (Ubuntu)]"
                    ),
                },
                {
                    "tool_id": "httpx-web",
                    "output_excerpt": (
                        '{"url":"https://portal.example/admin","title":"Admin Console",'
                        '"tech":["Bootstrap","Vue.js"],"webserver":"nginx/1.25.3"}'
                    ),
                },
            ],
            limit=64,
        )

        names = {str(item.get("name", "")).strip().lower() for item in technologies}
        self.assertIn("apache", names)
        self.assertIn("php", names)
        self.assertIn("bootstrap", names)
        self.assertIn("nginx", names)

    def test_infer_technologies_ignores_whatweb_header_pseudo_technologies(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "whatweb-http",
                    "output_excerpt": (
                        "https://portal.example:443 [200 OK] Apache[2.4.57], "
                        "Content-Language[en], "
                        "RedirectLocation[https://portal.example/login], "
                        "Strict-Transport-Security[max-age=15552000; includeSubDomains], "
                        "X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], "
                        "HTTPServer[Apache/2.4.57 (Ubuntu)]"
                    ),
                }
            ],
            limit=64,
        )

        names = {str(item.get("name", "")).strip().lower() for item in technologies}
        apache_versions = {
            str(item.get("version", "")).strip()
            for item in technologies
            if str(item.get("name", "")).strip().lower() in {"apache", "apache http server"}
        }
        self.assertIn("apache", names)
        self.assertNotIn("content-language", names)
        self.assertNotIn("redirectlocation", names)
        self.assertNotIn("strict-transport-security", names)
        self.assertNotIn("x-frame-options", names)
        self.assertNotIn("x-xss-protection", names)
        self.assertIn("2.4.57", apache_versions)

    def test_infer_technologies_strips_nmap_and_ansi_version_noise(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[
                {
                    "script_id": "http-vuln-cve2011-3192.nse",
                    "excerpt": (
                        "Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-17 07:15 CDT\n"
                        "| http-vuln-cve2011-3192: Apache HTTP Server Range header DoS check\n"
                        "|_  Apache HTTP Server appears present\n"
                    ),
                }
            ],
            process_records=[
                {
                    "tool_id": "nuclei-web",
                    "output_excerpt": "\u001b[0m nginx login panel detected",
                }
            ],
            limit=64,
        )

        bad_versions = {
            str(item.get("version", "")).strip()
            for item in technologies
            if str(item.get("version", "")).strip()
        }
        names = {str(item.get("name", "")).strip().lower() for item in technologies}
        self.assertIn("apache http server", names)
        self.assertIn("nginx", names)
        self.assertNotIn("7.80", bad_versions)
        self.assertNotIn("0m", bad_versions)

    def test_infer_technologies_drops_invalid_php_major_versions_from_weak_fingerprints(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._infer_technologies_from_observations(
            service_records=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "http-useragent-tester.nse",
                    "output_excerpt": "Possible stack fingerprint: PHP 2.5 on upstream service",
                }
            ],
            limit=64,
        )

        php_versions = {
            str(item.get("version", "")).strip()
            for item in technologies
            if str(item.get("name", "")).strip().lower() == "php"
        }
        self.assertNotIn("2.5", php_versions)

    def test_normalize_ai_technologies_strips_nmap_release_leakage_from_versions_and_cpes(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._normalize_ai_technologies([
            {
                "name": "nginx",
                "version": "7.80",
                "cpe": "cpe:/a:nginx:nginx:7.80",
                "evidence": "http-headers.nse output fingerprint",
            },
            {
                "name": "Apache HTTP Server",
                "version": "7.80",
                "cpe": "cpe:/a:apache:http_server:7.80",
                "evidence": "http-vuln-cve2011-3192.nse output fingerprint",
            },
        ])

        by_name = {
            str(item.get("name", "")).strip().lower(): item
            for item in technologies
        }
        self.assertEqual("", str(by_name["nginx"].get("version", "")).strip())
        self.assertEqual("cpe:/a:nginx:nginx", str(by_name["nginx"].get("cpe", "")).strip())
        self.assertEqual("", str(by_name["apache http server"].get("version", "")).strip())
        self.assertEqual("cpe:/a:apache:http_server", str(by_name["apache http server"].get("cpe", "")).strip())

    def test_normalize_ai_technologies_drops_placeholder_names_and_truncated_evidence(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        technologies = runtime._normalize_ai_technologies([
            {
                "name": "True",
                "version": "",
                "cpe": "",
                "evidence": "httpx fingerprint cdn True",
            },
            {
                "name": "Cloudflare",
                "version": "",
                "cpe": "",
                "evidence": "whatweb-http fingerprint ...[truncated]",
            },
        ])

        by_name = {
            str(item.get("name", "")).strip().lower(): item
            for item in technologies
        }
        self.assertNotIn("true", by_name)
        self.assertIn("cloudflare", by_name)
        self.assertIn("whatweb-http fingerprint", str(by_name["cloudflare"].get("evidence", "")).strip())

    def test_normalize_ai_findings_drops_truncation_placeholder_titles(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        findings = runtime._normalize_ai_findings([
            {
                "title": "truncated",
                "severity": "info",
                "cvss": 0.0,
                "cve": "",
                "evidence": "...[truncated]",
            },
            {
                "title": "Directory listing observed",
                "severity": "low",
                "cvss": 0.0,
                "cve": "",
                "evidence": "...[truncated]",
            },
        ])

        self.assertEqual(1, len(findings))
        self.assertEqual("Directory listing observed", findings[0]["title"])
        self.assertEqual("Directory listing observed", findings[0]["evidence"])

    def test_infer_findings_uses_tool_specific_nuclei_and_tls_parsers(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        findings = runtime._infer_findings_from_observations(
            host_cves_raw=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "nuclei-cves",
                    "output_excerpt": (
                        "[\u001b[31mWRN\u001b[0m] no templates provided for scan\n"
                        "[0:00:05] | Templates: 0 | Hosts: 1 | RPS: 0 | Matched: 0 | Errors: 0 | Requests: 0/0 (9223372036854775808%)\n"
                        "[CVE-2025-1111] [http] [critical] https://portal.example/admin "
                        "authenticated admin panel exposure"
                    ),
                },
                {
                    "tool_id": "sslscan",
                    "output_excerpt": "TLSv1.0 enabled\nSelf signed certificate",
                },
            ],
            limit=64,
        )

        finding_titles = {str(item.get("title", "")).strip() for item in findings}
        finding_cves = {str(item.get("cve", "")).strip().upper() for item in findings}
        self.assertIn("CVE-2025-1111", finding_cves)
        self.assertIn("TLSv1.0 supported", finding_titles)
        self.assertIn("Self-signed TLS certificate", finding_titles)
        self.assertNotIn("WRN", finding_titles)
        self.assertNotIn("0:00:05", finding_titles)

    def test_infer_findings_filters_suppressed_nuclei_rate_limited_matches(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        findings = runtime._infer_findings_from_observations(
            host_cves_raw=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "nuclei-cves",
                    "output_excerpt": (
                        "[CVE-2026-1111] [http] [critical] https://portal.example/admin "
                        "429 Too Many Requests Retry-After: 120"
                    ),
                }
            ],
            limit=32,
        )

        self.assertEqual([], findings)

    def test_infer_findings_uses_line_level_cve_evidence_for_nmap_output(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        findings = runtime._infer_findings_from_observations(
            host_cves_raw=[],
            script_records=[],
            process_records=[
                {
                    "tool_id": "nmap-vuln.nse",
                    "output_excerpt": (
                        "Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-20 15:44 CDT\n"
                        "NSE: Loaded 149 scripts for scanning.\n"
                        "| http-vuln-cve2011-3192:\n"
                        "|   IDs: CVE:CVE-2011-3192\n"
                        "|_  Apache HTTP Server byterange filter DoS\n"
                        "Nmap done: 1 IP address (1 host up) scanned in 4.72 seconds\n"
                    ),
                }
            ],
            limit=32,
        )

        finding = next(item for item in findings if str(item.get("cve", "")).strip().upper() == "CVE-2011-3192")
        self.assertIn("IDs: CVE:CVE-2011-3192", str(finding.get("evidence", "")))
        self.assertNotIn("Starting Nmap", str(finding.get("evidence", "")))

    def test_infer_urls_extracts_urls_from_httpx_and_nuclei_outputs(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        urls = runtime._infer_urls_from_observations(
            script_records=[],
            process_records=[
                {
                    "tool_id": "httpx-web",
                    "output_excerpt": (
                        '{"url":"https://portal.example:443/admin/","title":"Admin Console",'
                        '"tech":["Vue.js"]}'
                    ),
                },
                {
                    "tool_id": "nuclei-web",
                    "output_excerpt": "[exposed-panel] [medium] https://portal.example:443/login/",
                },
            ],
            limit=32,
        )

        extracted_urls = {str(item.get("url", "")).strip() for item in urls}
        self.assertIn("https://portal.example/admin", extracted_urls)
        self.assertIn("https://portal.example/login", extracted_urls)

    def test_infer_urls_normalizes_default_ports_and_malformed_suffixes(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        urls = runtime._infer_urls_from_observations(
            script_records=[],
            process_records=[
                {
                    "tool_id": "httpx-web",
                    "output_excerpt": '{"url":"http://atlas.tantalumlabs.io:80/:","title":"Atlas"}',
                },
                {
                    "tool_id": "nuclei-web",
                    "output_excerpt": "[login-panel] [medium] https://tantalumlabs.io:443/",
                },
                {
                    "tool_id": "nuclei-web",
                    "output_excerpt": "[alt-panel] [medium] https://tantalumlabs.io:8080/",
                },
            ],
            limit=32,
        )

        extracted_urls = {str(item.get("url", "")).strip() for item in urls}
        self.assertIn("http://atlas.tantalumlabs.io", extracted_urls)
        self.assertIn("https://tantalumlabs.io", extracted_urls)
        self.assertIn("https://tantalumlabs.io:8080", extracted_urls)
        self.assertNotIn("http://atlas.tantalumlabs.io:80/:", extracted_urls)
        self.assertNotIn("https://tantalumlabs.io:443/", extracted_urls)

    def test_infer_urls_ignores_nmap_boilerplate_urls(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        urls = runtime._infer_urls_from_observations(
            script_records=[
                {
                    "script_id": "nmap-vuln.nse",
                    "excerpt": (
                        "Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-17 07:15 CDT\n"
                        "| http-title: example portal\n"
                        "Service detection performed. Please report any incorrect results at "
                        "https://nmap.org/submit/ .\n"
                    ),
                }
            ],
            process_records=[],
            limit=16,
        )

        extracted_urls = {str(item.get("url", "")).strip() for item in urls}
        self.assertNotIn("https://nmap.org", extracted_urls)
        self.assertNotIn("https://nmap.org/submit/", extracted_urls)

    def test_strip_nmap_preamble_removes_header_and_footer_reference_lines(self):
        from app.web.runtime import WebRuntime

        cleaned = WebRuntime._strip_nmap_preamble(
            "Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-17 07:15 CDT\n"
            "| http-title: portal.example\n"
            "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n"
            "Nmap done: 1 IP address (1 host up) scanned in 4.72 seconds\n"
        )

        self.assertEqual("| http-title: portal.example", cleaned)

    def test_normalize_ai_manual_tests_dedupes_by_command(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        manual_tests = runtime._normalize_ai_manual_tests([
            {
                "why": "Confirm headers",
                "command": "curl -k -I https://10.0.0.5",
                "scope_note": "safe",
            },
            {
                "why": "Validate front door",
                "command": "curl -k -I https://10.0.0.5",
                "scope_note": "same command",
            },
        ])

        self.assertEqual(1, len(manual_tests))
        self.assertEqual("curl -k -I https://10.0.0.5", manual_tests[0]["command"])


if __name__ == "__main__":
    unittest.main()
