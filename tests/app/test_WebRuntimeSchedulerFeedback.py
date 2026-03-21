import unittest
import threading
from unittest import mock
from types import SimpleNamespace


class WebRuntimeSchedulerFeedbackTest(unittest.TestCase):
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
                "sslyze",
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
