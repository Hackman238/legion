import collections
import collections.abc
import unittest
from types import SimpleNamespace
from unittest.mock import patch

for legacy_name in ("Mapping", "MutableMapping", "Sequence", "Callable"):
    if not hasattr(collections, legacy_name):
        setattr(collections, legacy_name, getattr(collections.abc, legacy_name))


class WebRuntimeNucleiBuildCommandTest(unittest.TestCase):
    def test_build_command_uses_http_scheme_for_http_service_and_adds_as(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = (
            "(command -v nuclei >/dev/null 2>&1 && "
            "(nuclei -u https://[IP]:[PORT] -ni -silent -no-color -o [OUTPUT].txt || "
            "nuclei -u http://[IP]:[PORT] -ni -silent -no-color -o [OUTPUT].txt)) || echo nuclei not found"
        )

        command, outputfile = runtime._build_command(
            template,
            "192.168.3.1",
            "80",
            "tcp",
            "nuclei-web",
            "http",
        )

        self.assertIn("command -v nuclei >/dev/null 2>&1", command)
        self.assertIn("nuclei -as -stats -si 15 -u http://192.168.3.1:80", command)
        self.assertNotIn("https://192.168.3.1:80", command)
        self.assertIn(f"{outputfile}.txt", command)
        self.assertIn("-nuclei-web-192.168.3.1-80", outputfile)
        self.assertNotIn("nuclei -as >/dev/null", command)
        self.assertNotIn("nuclei -as-web", command)
        self.assertIn("-silent", command)
        self.assertNotIn("-no-color", command)

    def test_build_command_uses_https_scheme_for_https_service_without_forcing_as(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = (
            "(command -v nuclei >/dev/null 2>&1 && "
            "(nuclei -tags cve -u https://[IP]:[PORT] -ni -silent -o [OUTPUT].txt || "
            "nuclei -tags cve -u http://[IP]:[PORT] -ni -silent -o [OUTPUT].txt)) || echo nuclei not found"
        )

        command, outputfile = runtime._build_command(
            template,
            "192.168.3.1",
            "443",
            "tcp",
            "nuclei-cves",
            "https",
        )

        self.assertIn("nuclei -stats -si 15 -tags cve -u https://192.168.3.1:443", command)
        self.assertNotIn("http://192.168.3.1:443", command)
        self.assertNotIn("nuclei -as -tags cve", command)
        self.assertIn(f"{outputfile}.txt", command)
        self.assertIn("-silent", command)

    def test_build_command_normalizes_legacy_gobuster_dir_template(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = (
            "(command -v feroxbuster >/dev/null 2>&1 && "
            "(feroxbuster -u https://[IP]:[PORT] -k --silent -o [OUTPUT].txt || "
            "feroxbuster -u http://[IP]:[PORT] --silent -o [OUTPUT].txt)) || "
            "(command -v gobuster >/dev/null 2>&1 && "
            "gobuster dir -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt) || "
            "echo feroxbuster/gobuster not found"
        )

        command, outputfile = runtime._build_command(
            template,
            "192.168.3.1",
            "443",
            "tcp",
            "web-content-discovery",
            "https",
        )

        self.assertIn("gobuster -m dir", command)
        self.assertIn("gobuster dir -q -u https://192.168.3.1:443/", command)
        self.assertNotIn("http://192.168.3.1:443/", command)
        self.assertIn(f"{outputfile}.txt", command)

    def test_build_command_normalizes_legacy_wapiti_template(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = "wapiti https://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT]"

        command, outputfile = runtime._build_command(
            template,
            "192.168.3.100",
            "443",
            "tcp",
            "https-wapiti",
            "https",
        )

        self.assertIn("wapiti -u https://192.168.3.100:443", command)
        self.assertNotIn(" -u -v ", command)
        self.assertNotIn("wapiti https://192.168.3.100 ", command)
        self.assertIn(outputfile, command)

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_build_command_prefers_resolvable_hostname_for_command_target(self, mock_getaddrinfo):
        from app.screenshot_targets import resolve_hostname_addresses
        from app.web.runtime import WebRuntime

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [
            ("family", "socktype", "proto", "", ("150.171.27.10", 0)),
        ]

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running"),
            repositoryContainer=SimpleNamespace(
                hostRepository=SimpleNamespace(
                    getHostByIP=lambda _ip: SimpleNamespace(hostname="bing.com")
                )
            ),
        )

        command, _outputfile = runtime._build_command(
            "feroxbuster -u https://[IP]:[PORT] -o [OUTPUT].txt",
            "150.171.27.10",
            "443",
            "tcp",
            "web-content-discovery",
            "https",
        )

        self.assertIn("https://bing.com:443", command)
        self.assertNotIn("https://150.171.27.10:443", command)

    def test_build_command_keeps_hostname_target_for_nmap_and_removes_skip_dns(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running"),
            repositoryContainer=SimpleNamespace(
                hostRepository=SimpleNamespace(
                    getHostByIP=lambda _ip: SimpleNamespace(hostname="portal.example")
                )
            ),
        )

        command, _outputfile = runtime._build_command(
            "nmap -Pn -n -sV [IP] -p [PORT]",
            "203.0.113.55",
            "443",
            "tcp",
            "nmap-fast-tcp",
            "https",
        )

        self.assertIn("nmap -Pn -sV portal.example -p 443", command)
        self.assertNotIn("nmap -Pn -sV 203.0.113.55 -p 443", command)
        self.assertNotIn(" -n ", command)

    def test_build_command_inserts_nmap_output_inside_fallback_group(self):
        from app.settings import AppSettings
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = (
            "(nmap -Pn -n -sV -p [PORT] --script=vuln,vulners --stats-every 15s [IP] || "
            "nmap -Pn -n -sV -p [PORT] --script=vuln --stats-every 15s [IP])"
        )

        command, outputfile = runtime._build_command(
            template,
            "192.168.3.1",
            "443",
            "tcp",
            "nmap-vuln.nse",
            "https",
        )

        self.assertEqual(command.count(f"-oA {outputfile}"), 2)
        self.assertNotIn(f") -oA {outputfile}", command)
        self.assertEqual(
            command,
            AppSettings._ensure_nmap_output_argument(
                AppSettings._ensure_nmap_stats_every(
                    template.replace("[IP]", "192.168.3.1").replace("[PORT]", "443")
                ),
                outputfile,
            ),
        )

    def test_build_command_adds_stats_every_to_generic_nmap_actions(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        command, _outputfile = runtime._build_command(
            "nmap -Pn -sV [IP] -p [PORT]",
            "192.168.3.1",
            "22",
            "tcp",
            "nmap-fast-tcp",
            "",
        )

        self.assertIn("--stats-every 15s", command)
        self.assertIn("-vv", command)
        self.assertEqual(1, command.count("--stats-every"))

    def test_build_command_normalizes_banner_template(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        command, _outputfile = runtime._build_command(
            'bash -c \\"echo \\"\\" | nc -v -n -w1 [IP] [PORT]\\"',
            "192.168.3.1",
            "21",
            "tcp",
            "banner",
            "ftp",
        )

        self.assertEqual(
            "LEGION_BANNER_TARGET=192.168.3.1 LEGION_BANNER_PORT=21 "
            "LEGION_BANNER_PROTOCOL=tcp python3 -m app.banner_probe",
            command,
        )


if __name__ == "__main__":
    unittest.main()
