import unittest


class WebRuntimeNmapProgressTest(unittest.TestCase):
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

    def test_append_nmap_stats_every_once(self):
        from app.web.runtime import WebRuntime

        args = ["-Pn", "--stats-every", "10s"]
        updated = WebRuntime._append_nmap_stats_every(args, interval="15s")
        self.assertEqual(args, updated)

        updated_new = WebRuntime._append_nmap_stats_every(["-Pn"], interval="15s")
        self.assertEqual(["-Pn", "--stats-every", "15s"], updated_new)

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


if __name__ == "__main__":
    unittest.main()
