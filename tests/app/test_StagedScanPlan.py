import unittest
from unittest.mock import patch

from app.web.runtime_scan_planning import build_staged_scan_plan, parse_stage_spec, staged_stage_specs


class StagedScanPlanTest(unittest.TestCase):
    def test_stage_specs_accept_both_config_spellings(self):
        self.assertEqual({"kind": "ports", "ports": "T:80,81,443"}, parse_stage_spec('"PORTS|T:80,81,443"'))
        self.assertEqual({"kind": "ports", "ports": "T:25,U:161"}, parse_stage_spec("T:25,U:161"))
        self.assertEqual({"kind": "scripts", "scripts": ["vulners"]}, parse_stage_spec("NSE|vulners"))
        self.assertEqual({"kind": "scripts", "scripts": ["vulners"]}, parse_stage_spec("Vulners,CVE"))

    def test_plan_chains_discovery_port_groups_and_scripts_and_imports_every_stage(self):
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
