import os
import tempfile
import unittest
from unittest.mock import patch


LEGACY_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
dirbuster=Launch dirbuster, java -Xmx256M -jar /usr/share/dirbuster/DirBuster.jar -u http://[IP]:[PORT], "http,https"
nuclei-web=Run nuclei web scan, "nuclei -u http://[IP]:[PORT] -silent -o [OUTPUT].txt", "http,https"
banner=Grab banner, echo hi, http

[SchedulerSettings]
whatweb-http="http,soap,http-proxy,http-alt", tcp
"""

LEGACY_WEB_CONTENT_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
web-content-discovery=Run web content discovery (feroxbuster/gobuster), "(command -v feroxbuster >/dev/null 2>&1 && (feroxbuster -u https://[IP]:[PORT] -k --silent -o [OUTPUT].txt || feroxbuster -u http://[IP]:[PORT] --silent -o [OUTPUT].txt)) || (command -v gobuster >/dev/null 2>&1 && gobuster dir -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt) || echo feroxbuster/gobuster not found", "http,https,ssl,soap,http-proxy,http-alt,https-alt"
"""

LEGACY_WAPITI_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
http-wapiti=http-wapiti, wapiti http://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT], http
https-wapiti=https-wapiti, wapiti https://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT], https
"""

LEGACY_VULN_AND_SCREENSHOT_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
nmap-vuln.nse=nmap-vuln.nse, "nmap -Pn -n -sV -p [PORT] --script=vuln --stats-every 15s [IP]", "http,https,ssl,soap,http-proxy,http-alt,https-alt"

[SchedulerSettings]
screenshooter="http,https,ssl,http-proxy,http-alt,https-alt", tcp
"""


class SettingsMigrationTest(unittest.TestCase):
    def test_legacy_dirbuster_is_replaced_with_headless_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()

                port_action_ids = {row[1] for row in app_settings.getPortActions()}
                self.assertNotIn("dirbuster", port_action_ids)
                self.assertIn("web-content-discovery", port_action_ids)
                self.assertIn("nmap-vuln.nse", port_action_ids)
                self.assertIn("nuclei-web", port_action_ids)
                self.assertIn("nikto", port_action_ids)
                self.assertIn("wafw00f", port_action_ids)
                self.assertIn("sslscan", port_action_ids)
                self.assertIn("sslyze", port_action_ids)
                self.assertIn("wpscan", port_action_ids)

                port_actions = {row[1]: row for row in app_settings.getPortActions()}
                nuclei_cmd = str(port_actions["nuclei-web"][2])
                self.assertIn("nuclei -as", nuclei_cmd)

                scheduler_ids = {row[0] for row in app_settings.getSchedulerSettings()}
                self.assertIn("web-content-discovery", scheduler_ids)
                self.assertIn("nmap-vuln.nse", scheduler_ids)
                self.assertIn("nuclei-web", scheduler_ids)
                self.assertIn("screenshooter", scheduler_ids)

    def test_nuclei_normalization_does_not_mutate_probe_or_output_tokens(self):
        from app.settings import AppSettings

        command = (
            "(command -v nuclei >/dev/null 2>&1 && "
            "nuclei -u https://1.2.3.4:443 -silent -o /tmp/scan-nuclei-web-1.2.3.4.txt)"
        )
        normalized = AppSettings._ensure_nuclei_auto_scan(command)

        self.assertIn("command -v nuclei >/dev/null 2>&1", normalized)
        self.assertIn("nuclei -as -u https://1.2.3.4:443", normalized)
        self.assertIn("/tmp/scan-nuclei-web-1.2.3.4.txt", normalized)
        self.assertNotIn("nuclei -as >/dev/null", normalized)
        self.assertNotIn("nuclei -as-web", normalized)

    def test_wapiti_normalization_fixes_missing_url_argument_and_inserts_port(self):
        from app.settings import AppSettings

        legacy_http = "wapiti http://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT]"
        normalized_http = AppSettings._ensure_wapiti_command(legacy_http, scheme="http")
        self.assertIn("wapiti -u http://[IP]:[PORT]", normalized_http)
        self.assertNotIn(" -u -v ", normalized_http)
        self.assertNotIn("wapiti http://[IP] ", normalized_http)

        legacy_https = "wapiti https://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT]"
        normalized_https = AppSettings._ensure_wapiti_command(legacy_https, scheme="https")
        self.assertIn("wapiti -u https://[IP]:[PORT]", normalized_https)
        self.assertNotIn(" -u -v ", normalized_https)
        self.assertNotIn("wapiti https://[IP] ", normalized_https)

        wrapped = (
            "(command -v wapiti >/dev/null 2>&1 && "
            "wapiti https://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT]) || "
            "echo wapiti not found"
        )
        wrapped_normalized = AppSettings._ensure_wapiti_command(wrapped, scheme="https")
        self.assertIn("command -v wapiti >/dev/null 2>&1", wrapped_normalized)
        self.assertIn("wapiti -u https://[IP]:[PORT] -n 10 -b folder -v 1 -f txt -o [OUTPUT]", wrapped_normalized)

    def test_web_content_discovery_normalization_rewrites_legacy_gobuster_syntax(self):
        from app.settings import AppSettings

        legacy = AppSettings.LEGACY_WEB_CONTENT_DISCOVERY_COMMAND
        normalized = AppSettings._ensure_web_content_discovery_command(legacy)

        self.assertIn("gobuster -m dir", normalized)
        self.assertIn("gobuster dir -q -u http://[IP]:[PORT]/", normalized)
        self.assertIn("feroxbuster -u https://[IP]:[PORT] -k", normalized)

    def test_existing_web_content_discovery_action_is_migrated_for_gobuster_v2(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_WEB_CONTENT_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()
                port_actions = {row[1]: row for row in app_settings.getPortActions()}
                command = str(port_actions["web-content-discovery"][2])

                self.assertIn("gobuster -m dir", command)
                self.assertNotIn(
                    "command -v gobuster >/dev/null 2>&1 && gobuster dir -u http://[IP]:[PORT]/",
                    command,
                )

    def test_existing_wapiti_actions_are_migrated_to_valid_url_arguments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_WAPITI_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()
                port_actions = {row[1]: row for row in app_settings.getPortActions()}
                http_cmd = str(port_actions["http-wapiti"][2])
                https_cmd = str(port_actions["https-wapiti"][2])

                self.assertIn("wapiti -u http://[IP]:[PORT]", http_cmd)
                self.assertIn("wapiti -u https://[IP]:[PORT]", https_cmd)
                self.assertNotIn(" -u -v ", http_cmd)
                self.assertNotIn(" -u -v ", https_cmd)

    def test_nmap_vuln_command_and_screenshooter_scope_are_migrated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_VULN_AND_SCREENSHOT_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()
                port_actions = {row[1]: row for row in app_settings.getPortActions()}
                vuln_command = str(port_actions["nmap-vuln.nse"][2])
                self.assertIn("--script=vuln,vulners", vuln_command)
                self.assertIn("||", vuln_command)

                scheduler_actions = {row[0]: row for row in app_settings.getSchedulerSettings()}
                screenshooter_scope = str(scheduler_actions["screenshooter"][1])
                self.assertIn("ms-wbt-server", screenshooter_scope)
                self.assertIn("vmrdp", screenshooter_scope)
                self.assertIn("vnc", screenshooter_scope)


if __name__ == "__main__":
    unittest.main()
