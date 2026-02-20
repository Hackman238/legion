import unittest
import threading
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
            }
        })
        self.assertTrue(cfg["enabled"])
        self.assertEqual(12, cfg["max_rounds_per_target"])
        self.assertEqual(1, cfg["max_actions_per_round"])
        self.assertEqual(320, cfg["recent_output_chars"])

    def test_scheduler_max_concurrency_clamps_values(self):
        from app.web.runtime import WebRuntime

        self.assertEqual(1, WebRuntime._scheduler_max_concurrency({"max_concurrency": "x"}))
        self.assertEqual(1, WebRuntime._scheduler_max_concurrency({"max_concurrency": 0}))
        self.assertEqual(16, WebRuntime._scheduler_max_concurrency({"max_concurrency": 24}))
        self.assertEqual(6, WebRuntime._scheduler_max_concurrency({"max_concurrency": 6}))

    def test_scheduler_max_jobs_clamps_values(self):
        from app.web.runtime import WebRuntime

        self.assertEqual(200, WebRuntime._scheduler_max_jobs({"max_jobs": "x"}))
        self.assertEqual(20, WebRuntime._scheduler_max_jobs({"max_jobs": 0}))
        self.assertEqual(2000, WebRuntime._scheduler_max_jobs({"max_jobs": 99999}))
        self.assertEqual(350, WebRuntime._scheduler_max_jobs({"max_jobs": 350}))

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


if __name__ == "__main__":
    unittest.main()
