import unittest
from unittest.mock import patch

from app.web.runtime_scan_planning import build_staged_scan_plan, parse_stage_spec, staged_stage_specs


class StagedScanPlanTest(unittest.TestCase):
    def test_stage_specs_accept_both_config_spellings(self):
        self.assertEqual({"kind": "ports", "ports": "T:80,81,443"}, parse_stage_spec('"PORTS|T:80,81,443"'))
        self.assertEqual({"kind": "ports", "ports": "T:25,U:161"}, parse_stage_spec("T:25,U:161"))
        self.assertEqual({"kind": "scripts", "scripts": ["vulners"]}, parse_stage_spec("NSE|vulners"))
        self.assertEqual({"kind": "scripts", "scripts": ["vulners"]}, parse_stage_spec("Vulners,CVE"))

    def test_privilege_detection_honours_nmap_environment_overrides(self):
        import os
        from app.web.runtime_scan_planning import can_raw_socket

        with patch.dict(os.environ, {"NMAP_UNPRIVILEGED": "1"}, clear=False):
            self.assertFalse(can_raw_socket())  # even as root: the operator says nmap must not use raw sockets
        env = {key: value for key, value in os.environ.items() if key != "NMAP_UNPRIVILEGED"}
        env["NMAP_PRIVILEGED"] = "1"
        with patch.dict(os.environ, env, clear=True), patch("os.geteuid", return_value=1000):
            self.assertTrue(can_raw_socket())  # capabilities (docker --cap-add NET_RAW) asserted the nmap way

    def test_windows_nmap_under_wsl_counts_as_privileged(self):
        import os
        from app.web import runtime_scan_planning as planning

        env = {key: value for key, value in os.environ.items() if key not in {"NMAP_PRIVILEGED", "NMAP_UNPRIVILEGED"}}
        with patch.dict(os.environ, env, clear=True), patch("os.geteuid", return_value=1000):
            with patch.object(planning, "is_wsl", return_value=True):
                # Npcap grants raw sockets to nmap.exe; the WSL euid says nothing about it
                self.assertTrue(planning.can_raw_socket("/mnt/c/Program Files/Nmap/nmap.exe"))
                self.assertFalse(planning.can_raw_socket("nmap"))  # a Linux nmap in WSL still needs root
            with patch.object(planning, "is_wsl", return_value=False):
                self.assertFalse(planning.can_raw_socket("nmap.exe"))

    def test_dropped_os_detection_is_logged_once_per_process_and_only_when_wanted(self):
        import logging
        from app.web import runtime_scan_planning as planning

        planning.reset_os_detection_warning()
        self.addCleanup(planning.reset_os_detection_warning)
        logger = logging.getLogger("app.web.runtime_scan_planning")
        with patch.object(planning, "can_raw_socket", return_value=False):
            # a scripts-only staged plan never carries -O: nothing to warn about
            with patch.object(logger, "warning") as warning:
                plan = planning.build_staged_scan_plan(
                    nmap_path="nmap", targets=["10.0.0.5"], output_prefix="/tmp/legion-test/out",
                    discovery=True, extra_args=[], stage_specs=["NSE|vulners"],
                )
            warning.assert_not_called()
            with self.assertLogs("app.web.runtime_scan_planning", level="WARNING") as logs:
                plan = planning.build_staged_scan_plan(
                    nmap_path="nmap", targets=["10.0.0.5"], output_prefix="/tmp/legion-test/out",
                    discovery=True, extra_args=[], stage_specs=["T:80", "T:443", "NSE|vulners"],
                )
                # a chunked sweep builds one plan per chunk: the same reason is not repeated
                plan2 = planning.build_single_scan_plan(
                    runtime=None, targets=["10.0.0.5"], nmap_path="nmap", output_prefix="/tmp/legion-test/out",
                    mode="hard", options={"aggressive": True}, extra_args=[],
                )
            self.assertEqual(1, len(logs.records))
            self.assertIn("OS detection is left out", logs.output[0])
            self.assertFalse(any(" -O" in stage["command"] for stage in plan["stages"]))
            self.assertIn("-sV -sC", plan2["stages"][0]["command"])
            self.assertNotIn("-A", plan2["stages"][0]["command"].split())
        with patch.object(planning, "can_raw_socket", return_value=True):
            plan = planning.build_single_scan_plan(
                runtime=None, targets=["10.0.0.5"], nmap_path="nmap", output_prefix="/tmp/legion-test/out",
                mode="hard", options={"service_detection": True}, extra_args=[],
            )
            # nothing asked for OS detection: nothing to warn about either
            self.assertNotIn("-O", plan["stages"][0]["command"].split())

    def test_unprivileged_plans_leave_out_os_detection(self):
        from app.web import runtime_scan_planning as planning

        with patch.object(planning, "can_raw_socket", return_value=False):
            plan = planning.build_staged_scan_plan(
                nmap_path="nmap", targets=["10.0.0.5"], output_prefix="/tmp/legion-test/out",
                discovery=False, extra_args=[], stage_specs=["T:80,443"],
            )
            self.assertNotIn(" -O", plan["stages"][0]["command"])
            self.assertIn("-sV", plan["stages"][0]["command"])
        with patch.object(planning, "can_raw_socket", return_value=True):
            plan = planning.build_staged_scan_plan(
                nmap_path="nmap", targets=["10.0.0.5"], output_prefix="/tmp/legion-test/out",
                discovery=False, extra_args=[], stage_specs=["T:80,443"],
            )
            self.assertIn("-sV -O", plan["stages"][0]["command"])

    def test_plan_chains_discovery_port_groups_and_scripts_and_imports_every_stage(self):
        privileged = patch("app.web.runtime_scan_planning.can_raw_socket", return_value=True)
        privileged.start()
        self.addCleanup(privileged.stop)
        plan = build_staged_scan_plan(
            nmap_path="nmap", targets=["10.0.0.0/24"], output_prefix="/tmp/legion-test/scan", discovery=True,
            extra_args=[], stage_specs=['"PORTS|T:80,443"', "NSE|vulners", "PORTS|T:22", ""],
        )
        commands = [stage["command"] for stage in plan["stages"]]
        self.assertTrue(plan["import_each_stage"])
        self.assertEqual(4, len(commands))
        self.assertIn("nmap -sn", commands[0])
        self.assertIn("-sV -O -p T:80,443", commands[1])
        self.assertIn("--script vulners -p T:80,443", commands[2])  # scripts run on the ports found so far
        self.assertIn("-sV -p T:22", commands[3])
        self.assertNotIn("-Pn", commands[1])
        self.assertEqual(plan["stages"][-1]["xml_path"], plan["xml_path"])

    def test_without_discovery_stages_use_pn_and_no_sweep(self):
        plan = build_staged_scan_plan(
            nmap_path="/usr/bin/nmap", targets=["10.0.0.5"], output_prefix="/tmp/legion-test/scan", discovery=False,
            extra_args=["--min-rate", "100"], stage_specs=["T:445"],
        )
        self.assertEqual(1, len(plan["stages"]))
        self.assertIn("-Pn", plan["stages"][0]["command"])
        self.assertIn("--min-rate 100", plan["stages"][0]["command"])

    def test_settings_stage_values_are_read_in_order(self):
        class Settings:
            tools_nmap_stage1_ports = '"PORTS|T:80"'
            tools_nmap_stage2_ports = ""
            tools_nmap_stage3_ports = "NSE|vulners"
        self.assertEqual(['PORTS|T:80', "NSE|vulners"], staged_stage_specs(Settings()))


class HeadlessRunNmapScanTest(unittest.TestCase):
    def test_discovery_only_runs_a_ping_sweep(self):
        from app import cli_utils
        calls = []
        with patch.object(cli_utils.subprocess, "run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            written = cli_utils.run_nmap_scan("10.0.0.0/24 host.example", "/tmp/legion-test/out", discovery=True, staged=False)
        self.assertEqual(["/tmp/legion-test/out.xml"], written)
        self.assertEqual(["nmap", "-sn", "10.0.0.0/24", "host.example", "-oA", "/tmp/legion-test/out"], calls[0])

    def test_staged_runs_every_configured_stage_and_returns_all_reports(self):
        from app import cli_utils
        calls = []
        with patch.object(cli_utils.subprocess, "run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            written = cli_utils.run_nmap_scan(
                "10.0.0.5", "/tmp/legion-test/out", discovery=False, staged=True,
                stage_specs=["T:80", "NSE|vulners"], nmap_args="-T4",
            )
        self.assertEqual(2, len(calls))
        self.assertEqual(["/tmp/legion-test/out_stage1.xml", "/tmp/legion-test/out_stage2.xml"], written)
        self.assertIn("-Pn", calls[0])
        self.assertIn("-T4", calls[0])

    def test_staged_failure_after_a_completed_stage_raises_with_the_written_reports(self):
        from app import cli_utils

        def fake_run(cmd, **_kw):
            if "--script" in cmd:
                raise cli_utils.subprocess.CalledProcessError(1, cmd)
            return None

        with patch.object(cli_utils.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(cli_utils.NmapStageError) as raised:
                cli_utils.run_nmap_scan(
                    "10.0.0.5", "/tmp/legion-test/out", discovery=False, staged=True,
                    stage_specs=["T:80", "NSE|vulners"],
                )
        self.assertEqual(["/tmp/legion-test/out_stage1.xml"], raised.exception.written)
        self.assertEqual("nmap-stage2", raised.exception.stage_name)

    def test_staged_reports_keep_local_paths_when_nmap_exe_runs_under_wsl(self):
        from app import cli_utils

        calls = []
        with patch("app.web.runtime_scan_planning.is_wsl", return_value=True), \
                patch("app.web.runtime_scan_planning.to_windows_path", side_effect=lambda path: "C:" + path.replace("/", "\\")), \
                patch.object(cli_utils.subprocess, "run", side_effect=lambda cmd, **kw: calls.append(cmd)):
            written = cli_utils.run_nmap_scan(
                "10.0.0.5", "/mnt/c/Users/op/out", discovery=False, staged=True,
                nmap_path="nmap.exe", stage_specs=["T:80"],
            )
        self.assertEqual(["/mnt/c/Users/op/out_stage1.xml"], written)
        self.assertTrue(any(str(token).startswith("C:") for token in calls[0]), calls[0])


if __name__ == "__main__":
    unittest.main()
