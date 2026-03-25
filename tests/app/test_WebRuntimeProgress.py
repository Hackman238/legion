import os
import tempfile
import threading
import unittest
from types import SimpleNamespace


class _DummyProgressRepo:
    def __init__(self):
        self.calls = []

    def storeProcessProgress(self, process_id, percent=None, estimated_remaining=None):
        self.calls.append({
            "process_id": process_id,
            "percent": percent,
            "estimated_remaining": estimated_remaining,
        })


class WebRuntimeNmapProgressTest(unittest.TestCase):
    def test_count_rfc1918_scan_batches_splits_private_space_into_two_subnet_batches(self):
        from app.web.runtime import WebRuntime

        self.assertEqual(2, WebRuntime._count_rfc1918_scan_batches(["192.168.0.0/22"]))
        self.assertEqual(128, WebRuntime._count_rfc1918_scan_batches(["192.168.0.0/16"]))

    def test_extracts_percent_and_eta_from_nmap_stats_line(self):
        from app.web.runtime import WebRuntime

        line = "SYN Stealth Scan Timing: About 39.44% done; ETC: 10:45 (0:03:10 remaining)"
        percent, remaining = WebRuntime._extract_nmap_progress_from_text(line)

        self.assertEqual(39.44, percent)
        self.assertEqual(190, remaining)

    def test_extracts_percent_and_eta_from_taskprogress_line(self):
        from app.web.runtime import WebRuntime

        line = '<taskprogress task="SYN Stealth Scan" percent="15.32" remaining="741" etc="..."/>'
        percent, remaining = WebRuntime._extract_nmap_progress_from_text(line)

        self.assertEqual(15.32, percent)
        self.assertEqual(741, remaining)

    def test_extracts_percent_without_eta_and_keeps_remaining_empty(self):
        from app.web.runtime import WebRuntime

        line = "NSE Timing: About 0.00% done"
        percent, remaining = WebRuntime._extract_nmap_progress_from_text(line)

        self.assertEqual(0.0, percent)
        self.assertIsNone(remaining)

    def test_update_nmap_process_progress_clears_stale_eta_when_line_has_no_eta(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        repo = _DummyProgressRepo()
        state = {"percent": 12.0, "remaining": 99, "updated_at": 0.0}
        emit_calls = []
        runtime._emit_ui_invalidation = lambda *channels, **kwargs: emit_calls.append((channels, kwargs))

        runtime._update_nmap_process_progress(
            repo,
            process_id=7,
            text_chunk="NSE Timing: About 0.00% done",
            state=state,
        )

        self.assertEqual(0.0, state["percent"])
        self.assertIsNone(state["remaining"])
        self.assertEqual("0.0", repo.calls[-1]["percent"])
        self.assertIsNone(repo.calls[-1]["estimated_remaining"])
        self.assertEqual([(("processes",), {"throttle_seconds": 5.0})], emit_calls)

    def test_update_nmap_process_progress_emits_only_when_state_changes(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        repo = _DummyProgressRepo()
        emit_calls = []
        runtime._emit_ui_invalidation = lambda *channels, **kwargs: emit_calls.append((channels, kwargs))
        state = {"percent": 0.0, "remaining": None, "updated_at": 0.0}

        runtime._update_nmap_process_progress(
            repo,
            process_id=9,
            text_chunk="NSE Timing: About 0.00% done",
            state=state,
        )

        first_update_at = state["updated_at"]

        runtime._update_nmap_process_progress(
            repo,
            process_id=9,
            text_chunk="NSE Timing: About 0.00% done",
            state=state,
        )

        self.assertEqual(1, len(repo.calls))
        self.assertEqual(1, len(emit_calls))
        self.assertEqual(first_update_at, state["updated_at"])

    def test_append_nmap_stats_every_once(self):
        from app.web.runtime import WebRuntime

        args = ["-Pn", "--stats-every", "10s"]
        updated = WebRuntime._append_nmap_stats_every(args, interval="15s")
        self.assertEqual(["-Pn", "--stats-every", "10s", "-vv"], updated)

        updated_new = WebRuntime._append_nmap_stats_every(["-Pn"], interval="15s")
        self.assertEqual(["-Pn", "--stats-every", "15s", "-vv"], updated_new)

        updated_existing_verbose = WebRuntime._append_nmap_stats_every(["-Pn", "--stats-every", "15s", "-vv"], interval="15s")
        self.assertEqual(["-Pn", "--stats-every", "15s", "-vv"], updated_existing_verbose)

    def test_build_single_scan_plan_honors_force_pn_option(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        plan = runtime._build_single_scan_plan(
            targets=["192.168.3.1"],
            nmap_path="nmap",
            output_prefix="/tmp/scan",
            mode="easy",
            options={
                "discovery": True,
                "host_discovery_only": False,
                "skip_dns": True,
                "timing": "T3",
                "service_detection": True,
                "default_scripts": True,
                "os_detection": False,
                "aggressive": False,
                "full_ports": False,
                "vuln_scripts": False,
                "top_ports": 1000,
                "arp_ping": False,
                "force_pn": True,
            },
            extra_args=[],
        )
        command = str(plan["stages"][0]["command"])
        self.assertIn(" -Pn ", f" {command} ")
        self.assertIn("--stats-every 15s", command)
        self.assertIn(" -vv ", f" {command} ")

    def test_build_single_scan_plan_ignores_force_pn_for_discovery_only_mode(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        plan = runtime._build_single_scan_plan(
            targets=["192.168.3.1"],
            nmap_path="nmap",
            output_prefix="/tmp/scan",
            mode="rfc1918_discovery",
            options={
                "discovery": True,
                "host_discovery_only": True,
                "skip_dns": True,
                "timing": "T3",
                "service_detection": False,
                "default_scripts": False,
                "os_detection": False,
                "aggressive": False,
                "full_ports": False,
                "vuln_scripts": False,
                "top_ports": 100,
                "arp_ping": True,
                "force_pn": True,
            },
            extra_args=[],
        )
        command = str(plan["stages"][0]["command"])
        self.assertIn(" -sn ", f" {command} ")
        self.assertNotIn(" -Pn ", f" {command} ")
        self.assertIn("--stats-every 15s", command)
        self.assertIn(" -vv ", f" {command} ")

    def test_run_nmap_scan_and_import_chunks_rfc1918_sweep(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime.jobs = SimpleNamespace(is_cancel_requested=lambda _job_id: False)
        runtime._emit_ui_invalidation = lambda *args, **kwargs: None

        with tempfile.TemporaryDirectory() as temp_dir:
            host_repo = SimpleNamespace(getAllHostObjs=lambda: [])
            project = SimpleNamespace(
                properties=SimpleNamespace(runningFolder=temp_dir),
                repositoryContainer=SimpleNamespace(hostRepository=host_repo),
            )
            runtime.logic = SimpleNamespace(activeProject=project)
            runtime._require_active_project = lambda: project

            commands = []
            imported_xmls = []
            status_updates = []

            def fake_run_command_with_tracking(**kwargs):
                commands.append(str(kwargs.get("command", "") or ""))
                xml_path = f"{kwargs.get('outputfile', '')}.xml"
                with open(xml_path, "w", encoding="utf-8") as handle:
                    handle.write("<nmaprun/>")
                return True, "", 1

            runtime._run_command_with_tracking = fake_run_command_with_tracking
            runtime._import_nmap_xml = lambda xml_path, run_actions=False: imported_xmls.append((xml_path, run_actions)) or {"xml_path": xml_path}
            runtime._run_scheduler_actions_web = lambda: {"ran": True}
            runtime._update_scan_submission_status = lambda **kwargs: status_updates.append(dict(kwargs))

            result = runtime._run_nmap_scan_and_import(
                targets=["192.168.0.0/22"],
                discovery=True,
                staged=False,
                run_actions=True,
                nmap_path="nmap",
                nmap_args="",
                scan_mode="rfc1918_discovery",
                scan_options={
                    "host_discovery_only": False,
                    "scan_profile": "quick",
                    "service_detection": False,
                    "default_scripts": False,
                    "os_detection": False,
                },
                job_id=7,
            )

        self.assertEqual(2, result["chunks_total"])
        self.assertEqual(2, result["chunks_completed"])
        self.assertEqual(1, result["chunk_concurrency"])
        self.assertEqual(2, len(imported_xmls))
        self.assertTrue(all(bool(path) and run_actions is False for path, run_actions in imported_xmls))
        self.assertEqual({"ran": True}, result["scheduler_result"])
        self.assertEqual(2, len(commands))
        self.assertIn("192.168.0.0/24", commands[0])
        self.assertIn("192.168.1.0/24", commands[0])
        self.assertIn("192.168.2.0/24", commands[1])
        self.assertIn("192.168.3.0/24", commands[1])
        self.assertEqual("completed", str(status_updates[-1].get("status", "")))

    def test_run_nmap_scan_and_import_respects_rfc1918_chunk_concurrency(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime.jobs = SimpleNamespace(is_cancel_requested=lambda _job_id: False)
        runtime._emit_ui_invalidation = lambda *args, **kwargs: None

        with tempfile.TemporaryDirectory() as temp_dir:
            host_repo = SimpleNamespace(getAllHostObjs=lambda: [])
            project = SimpleNamespace(
                properties=SimpleNamespace(runningFolder=temp_dir),
                repositoryContainer=SimpleNamespace(hostRepository=host_repo),
            )
            runtime.logic = SimpleNamespace(activeProject=project)
            runtime._require_active_project = lambda: project

            imported_xmls = []
            status_updates = []
            active_count = 0
            max_active = 0
            active_lock = threading.Lock()
            second_started = threading.Event()

            def fake_run_command_with_tracking(**kwargs):
                nonlocal active_count, max_active
                with active_lock:
                    active_count += 1
                    max_active = max(max_active, active_count)
                    if active_count >= 2:
                        second_started.set()
                second_started.wait(0.5)
                xml_path = f"{kwargs.get('outputfile', '')}.xml"
                with open(xml_path, "w", encoding="utf-8") as handle:
                    handle.write("<nmaprun/>")
                with active_lock:
                    active_count -= 1
                return True, "", 1

            runtime._run_command_with_tracking = fake_run_command_with_tracking
            runtime._import_nmap_xml = lambda xml_path, run_actions=False: imported_xmls.append((xml_path, run_actions)) or {"xml_path": xml_path}
            runtime._run_scheduler_actions_web = lambda: {"ran": True}
            runtime._update_scan_submission_status = lambda **kwargs: status_updates.append(dict(kwargs))

            result = runtime._run_nmap_scan_and_import(
                targets=["192.168.0.0/22"],
                discovery=True,
                staged=False,
                run_actions=False,
                nmap_path="nmap",
                nmap_args="",
                scan_mode="rfc1918_discovery",
                scan_options={
                    "host_discovery_only": False,
                    "scan_profile": "quick",
                    "chunk_concurrency": 2,
                    "service_detection": False,
                    "default_scripts": False,
                    "os_detection": False,
                },
                job_id=7,
            )

        self.assertEqual(2, result["chunks_total"])
        self.assertEqual(2, result["chunks_completed"])
        self.assertEqual(2, result["chunk_concurrency"])
        self.assertEqual(2, max_active)
        self.assertEqual(2, len(imported_xmls))
        self.assertEqual("completed", str(status_updates[-1].get("status", "")))


if __name__ == "__main__":
    unittest.main()
