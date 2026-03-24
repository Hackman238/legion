import os
import tempfile
import unittest
from unittest.mock import patch


LEGACY_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
dirbuster=Launch dirbuster, java -Xmx256M -jar /usr/share/dirbuster/DirBuster.jar -u http://[IP]:[PORT], "http,https"
nuclei-web=Run nuclei web scan, "nuclei -u http://[IP]:[PORT] -silent -o [OUTPUT].txt", "http,https"
banner=Grab banner, bash -c \"echo \"\" | nc -v -n -w1 [IP] [PORT]\", http

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
sslyze=Run sslyze, sslyze --regular [IP]:[PORT], "https,ssl"
http-wordpress-plugins.nse=http-wordpress-plugins.nse, "nmap -Pn [IP] -p [PORT] --script=http-wordpress-plugins.nse --script-args=unsafe=1", "http,https"
"""

LEGACY_VULN_AND_SCREENSHOT_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
nmap-vuln.nse=nmap-vuln.nse, "nmap -Pn -n -sV -p [PORT] --script=vuln --stats-every 15s [IP]", "http,https,ssl,soap,http-proxy,http-alt,https-alt"

[SchedulerSettings]
screenshooter="http,https,ssl,http-proxy,http-alt,https-alt", tcp
"""

LEGACY_DISABLED_ACTIONS_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
http-drupal-modules.nse=http-drupal-modules.nse, "nmap -Pn [IP] -p [PORT] --script=http-drupal-modules.nse --script-args=unsafe=1", "http,https"
http-vuln-zimbra-lfi.nse=http-vuln-zimbra-lfi.nse, "nmap -Pn [IP] -p [PORT] --script=http-vuln-zimbra-lfi.nse --script-args=unsafe=1", "http,https"

[SchedulerSettings]
http-drupal-modules.nse="http,https", tcp
http-vuln-zimbra-lfi.nse="http,https", tcp
"""

LEGACY_SMB_ACTIONS_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
smb-enum-admins=Enumerate domain admins (net), "net rpc group members \\"Domain Admins\\" -I [IP] -U% ", "netbios-ssn,microsoft-ds"
smb-enum-users-rpc=Enumerate users (rpcclient), bash -c \\"echo 'enumdomusers' | rpcclient [IP] -U%\\", "netbios-ssn,microsoft-ds"
smb-null-sessions=Check for null sessions (rpcclient), bash -c \\"echo 'srvinfo' | rpcclient [IP] -U%\\", "netbios-ssn,microsoft-ds"
samrdump=Run samrdump, python /usr/share/doc/python-impacket-doc/examples/samrdump.py [IP] [PORT]/SMB, "netbios-ssn,microsoft-ds"
"""

LEGACY_SHELL_WRAPPER_CONFIG = """[GeneralSettings]
default-terminal=xterm

[PortActions]
snmp-brute=Bruteforce community strings (medusa), bash -c \\"medusa -h [IP] -u root -P ./wordlists/snmp-default.txt -M snmp | grep SUCCESS\\", "snmp,snmptrap"

[PortTerminalActions]
rpcclient=Open with rpcclient (NULL session), [term] rpcclient [IP] -p [PORT] -U%, "netbios-ssn,microsoft-ds"
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
                self.assertIn("nuclei-cves", port_action_ids)
                self.assertIn("nuclei-exposures", port_action_ids)
                self.assertIn("curl-headers", port_action_ids)
                self.assertIn("curl-options", port_action_ids)
                self.assertIn("curl-robots", port_action_ids)
                self.assertIn("nikto", port_action_ids)
                self.assertIn("wafw00f", port_action_ids)
                self.assertIn("sslscan", port_action_ids)
                self.assertIn("testssl.sh", port_action_ids)
                self.assertIn("wpscan", port_action_ids)
                self.assertIn("httpx", port_action_ids)
                self.assertIn("subfinder", port_action_ids)
                self.assertIn("grayhatwarfare", port_action_ids)
                self.assertIn("shodan-enrichment", port_action_ids)
                self.assertIn("nuclei-cloud", port_action_ids)
                self.assertIn("nuclei-aws-storage", port_action_ids)
                self.assertIn("nuclei-azure-storage", port_action_ids)
                self.assertIn("nuclei-gcp-storage", port_action_ids)
                self.assertIn("whatweb", port_action_ids)
                self.assertIn("whatweb-http", port_action_ids)
                self.assertIn("whatweb-https", port_action_ids)
                self.assertIn("dirsearch", port_action_ids)
                self.assertIn("ffuf", port_action_ids)
                self.assertIn("enum4linux-ng", port_action_ids)
                self.assertIn("smbmap", port_action_ids)
                self.assertIn("rpcclient-enum", port_action_ids)
                self.assertIn("netexec", port_action_ids)
                self.assertIn("responder", port_action_ids)
                self.assertIn("ntlmrelayx", port_action_ids)
                self.assertNotIn("sslyze", port_action_ids)
                self.assertNotIn("http-wapiti", port_action_ids)
                self.assertNotIn("https-wapiti", port_action_ids)

                port_actions = {row[1]: row for row in app_settings.getPortActions()}
                nuclei_cmd = str(port_actions["nuclei-web"][2])
                nuclei_cloud_cmd = str(port_actions["nuclei-cloud"][2])
                ffuf_cmd = str(port_actions["ffuf"][2])
                self.assertIn("nuclei -as", nuclei_cmd)
                self.assertIn("-stats -si 15", nuclei_cmd)
                self.assertIn("-silent", nuclei_cmd)
                self.assertNotIn("-no-color", nuclei_cmd)
                self.assertIn("-tags cloud,aws,azure,gcp", nuclei_cloud_cmd)
                self.assertIn("ffuf -s -of json -o [OUTPUT].json -u [WEB_URL]/FUZZ", ffuf_cmd)
                self.assertNotIn("-json", ffuf_cmd)
                self.assertNotIn("-noninteractive", ffuf_cmd)
                self.assertEqual("host", str(port_actions["subfinder"][3]))
                self.assertEqual("host", str(port_actions["grayhatwarfare"][3]))
                self.assertEqual("host", str(port_actions["shodan-enrichment"][3]))
                self.assertEqual(
                    "LEGION_BANNER_TARGET=[IP] LEGION_BANNER_PORT=[PORT] "
                    "LEGION_BANNER_PROTOCOL=tcp python3 -m app.banner_probe",
                    str(port_actions["banner"][2]),
                )

                scheduler_ids = {row[0] for row in app_settings.getSchedulerSettings()}
                self.assertIn("web-content-discovery", scheduler_ids)
                self.assertIn("nmap-vuln.nse", scheduler_ids)
                self.assertIn("nuclei-web", scheduler_ids)
                self.assertIn("screenshooter", scheduler_ids)
                self.assertIn("httpx", scheduler_ids)
                self.assertIn("whatweb", scheduler_ids)
                self.assertIn("dirsearch", scheduler_ids)
                self.assertIn("ffuf", scheduler_ids)
                self.assertIn("enum4linux-ng", scheduler_ids)
                self.assertIn("smbmap", scheduler_ids)
                self.assertIn("rpcclient-enum", scheduler_ids)
                self.assertIn("netexec", scheduler_ids)
                self.assertNotIn("subfinder", scheduler_ids)
                self.assertNotIn("grayhatwarfare", scheduler_ids)
                self.assertNotIn("shodan-enrichment", scheduler_ids)
                self.assertNotIn("nuclei-cloud", scheduler_ids)
                self.assertNotIn("nuclei-aws-storage", scheduler_ids)
                self.assertNotIn("nuclei-azure-storage", scheduler_ids)
                self.assertNotIn("nuclei-gcp-storage", scheduler_ids)
                self.assertNotIn("responder", scheduler_ids)
                self.assertNotIn("ntlmrelayx", scheduler_ids)

    def test_nuclei_normalization_does_not_mutate_probe_or_output_tokens(self):
        from app.settings import AppSettings

        command = (
            "(command -v nuclei >/dev/null 2>&1 && "
            "nuclei -u https://1.2.3.4:443 -silent -o /tmp/scan-nuclei-web-1.2.3.4.txt)"
        )
        normalized = AppSettings._ensure_nuclei_auto_scan(command)

        self.assertIn("command -v nuclei >/dev/null 2>&1", normalized)
        self.assertIn("nuclei -as -stats -si 15 -u https://1.2.3.4:443", normalized)
        self.assertIn("/tmp/scan-nuclei-web-1.2.3.4.txt", normalized)
        self.assertNotIn("nuclei -as >/dev/null", normalized)
        self.assertNotIn("nuclei -as-web", normalized)
        self.assertIn("-silent", normalized)
        self.assertNotIn("-no-color", normalized)

    def test_subfinder_normalization_preserves_wrapped_probe_and_output_tokens(self):
        from app.settings import AppSettings

        command = (
            "(command -v subfinder >/dev/null 2>&1 && "
            "subfinder -silent -recursive -duc -max-time 5 -oJ -d tantalumlabs.io -o /tmp/out.jsonl) || "
            "echo subfinder not found"
        )

        normalized = AppSettings._ensure_subfinder_command(command)

        self.assertIn("command -v subfinder >/dev/null 2>&1", normalized)
        self.assertIn("subfinder -silent -recursive -duc -max-time 5 -oJ -d [IP]", normalized)
        self.assertIn("-o [OUTPUT].jsonl", normalized)
        self.assertNotIn("command -v subfinder -silent", normalized)
        self.assertNotIn("subfinder not found -o", normalized)

    def test_nuclei_normalization_rewrites_existing_stats_interval_to_15_seconds(self):
        from app.settings import AppSettings

        normalized = AppSettings._ensure_nuclei_auto_scan(
            "nuclei -as -stats -si 30 -u https://portal.example:443 -o /tmp/out.txt"
        )

        self.assertIn("-si 15", normalized)
        self.assertNotIn("-si 30", normalized)

    def test_targeted_nuclei_normalization_adds_stats_without_forcing_automatic_scan(self):
        from app.settings import AppSettings

        normalized = AppSettings._ensure_nuclei_command(
            "nuclei -tags cve -u https://portal.example:443 -silent -o /tmp/out.txt",
            automatic_scan=False,
        )

        self.assertIn("nuclei -stats -si 15 -tags cve -u https://portal.example:443", normalized)
        self.assertNotIn("nuclei -as -tags cve", normalized)
        self.assertIn("-silent", normalized)

    def test_nmap_hostname_target_support_removes_skip_dns_for_hostnames(self):
        from app.settings import AppSettings

        normalized = AppSettings._ensure_nmap_hostname_target_support(
            "nmap -Pn -n -sV portal.example -p 443 --stats-every 15s",
            "portal.example",
        )

        self.assertIn("portal.example", normalized)
        self.assertNotIn(" -n ", normalized)

    def test_ffuf_normalization_rewrites_legacy_flags_to_supported_output_syntax(self):
        from app.settings import AppSettings

        normalized = AppSettings._ensure_ffuf_command(
            "ffuf -u [WEB_URL]/FUZZ -w /usr/share/wordlists/dirb/common.txt -json -noninteractive -s > [OUTPUT].jsonl"
        )

        self.assertIn("ffuf -s -of json -o [OUTPUT].json -u [WEB_URL]/FUZZ", normalized)
        self.assertNotIn("-json", normalized)
        self.assertNotIn("-noninteractive", normalized)
        self.assertNotIn("> [OUTPUT].jsonl", normalized)

    def test_hydra_normalization_strips_escaped_output_quotes(self):
        from app.settings import AppSettings

        normalized = AppSettings._ensure_hydra_command(
            'hydra -s [PORT] -C ./wordlists/routers-userpass.txt -u -t 4 -o \\"[OUTPUT].txt\\" -f [IP] ssh'
        )

        self.assertIn("-o [OUTPUT].txt", normalized)
        self.assertNotIn('\\"[OUTPUT].txt\\"', normalized)

    def test_netexec_normalization_rewrites_legacy_aliases_to_safe_default_command(self):
        from app.settings import AppSettings

        for command in (
            "netexec smb [IP] -u guest -p guest --shares",
            "nxc smb [IP] -u '' -p '' --users",
            "crackmapexec smb [IP] --shares",
        ):
            with self.subTest(command=command):
                normalized = AppSettings._ensure_netexec_command(command)
                self.assertIn("--shares --users --pass-pol", normalized)
                self.assertIn("--port [PORT]", normalized)
                self.assertIn("[OUTPUT].txt", normalized)

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

    def test_httpx_nikto_wpscan_and_smb_family_normalization_use_parser_friendly_output(self):
        from app.settings import AppSettings

        httpx_normalized = AppSettings._ensure_httpx_command("httpx -u https://[IP]:[PORT]")
        httpx_wrapped_normalized = AppSettings._ensure_httpx_command(
            "(command -v httpx >/dev/null 2>&1 && httpx -silent -json -title -tech-detect "
            "-web-server -status-code -content-type -u https://[IP]:[PORT]) || echo httpx not found"
        )
        nikto_normalized = AppSettings._ensure_nikto_command("nikto -h [IP] -p [PORT] -C all")
        wpscan_normalized = AppSettings._ensure_wpscan_command(
            "(command -v wpscan >/dev/null 2>&1 && "
            "(wpscan --url https://[IP]:[PORT] --disable-tls-checks || wpscan --url http://[IP]:[PORT])) || "
            "echo wpscan not found"
        )
        enum4linux_ng_normalized = AppSettings._ensure_enum4linux_ng_command(
            "(command -v enum4linux-ng >/dev/null 2>&1 && enum4linux-ng -A -oJ [OUTPUT] [IP]) || "
            "echo enum4linux-ng not found"
        )
        smbmap_normalized = AppSettings._ensure_smbmap_command(
            "(command -v smbmap >/dev/null 2>&1 && smbmap -H [IP] -P [PORT] --no-banner --no-color --csv [OUTPUT].csv) || "
            "echo smbmap not found"
        )
        rpcclient_normalized = AppSettings._ensure_rpcclient_enum_command(
            "(command -v rpcclient >/dev/null 2>&1 && rpcclient [IP] -p [PORT] -U '%' -c 'srvinfo;enumdomusers;netshareenumall' > [OUTPUT].txt) || "
            "echo rpcclient not found"
        )
        httpx_malformed_fallback = AppSettings._ensure_httpx_command(
            "(command -v httpx >/dev/null 2>&1 && httpx -silent -json -title -tech-detect "
            "-web-server -status-code -content-type -u http://[IP]:[PORT]) || echo httpx not found -o [OUTPUT].jsonl"
        )
        httpx_malformed_missing_paren = AppSettings._ensure_httpx_command(
            "(command -v httpx >/dev/null 2>&1 && httpx -silent -json -title -tech-detect "
            "-web-server -status-code -content-type -u http://[IP]:[PORT] || echo httpx not found -o [OUTPUT].jsonl"
        )

        self.assertIn("httpx -silent -json -title -tech-detect -web-server -status-code -content-type", httpx_normalized)
        self.assertIn("-u [WEB_URL]", httpx_normalized)
        self.assertIn("-o [OUTPUT].jsonl", httpx_normalized)
        self.assertIn("command -v httpx >/dev/null 2>&1 &&", httpx_wrapped_normalized)
        self.assertIn("httpx -silent -json -title -tech-detect -web-server -status-code -content-type", httpx_wrapped_normalized)
        self.assertIn("-u [WEB_URL] -o [OUTPUT].jsonl) || echo httpx not found", httpx_wrapped_normalized)
        self.assertIn("-u [WEB_URL] -o [OUTPUT].jsonl) || echo httpx not found", httpx_malformed_fallback)
        self.assertIn("-u [WEB_URL] -o [OUTPUT].jsonl) || echo httpx not found", httpx_malformed_missing_paren)
        self.assertIn("nikto -nointeractive -Format txt -output [OUTPUT].txt", nikto_normalized)
        self.assertIn("-h [WEB_URL]", nikto_normalized)
        self.assertNotIn("-p [PORT]", nikto_normalized)
        self.assertIn("wpscan --disable-tls-checks --no-update --format json --output [OUTPUT].json", wpscan_normalized)
        self.assertIn("--url [WEB_URL]", wpscan_normalized)
        self.assertEqual(
            "if command -v enum4linux-ng >/dev/null 2>&1; then enum4linux-ng -A -oJ [OUTPUT] [IP]; else echo enum4linux-ng not found; fi",
            enum4linux_ng_normalized,
        )
        self.assertEqual(
            "if command -v smbmap >/dev/null 2>&1; then smbmap -H [IP] -P [PORT] --no-write-check -q | tee [OUTPUT].txt; else echo smbmap not found; fi",
            smbmap_normalized,
        )
        self.assertEqual(
            "if command -v rpcclient >/dev/null 2>&1; then rpcclient [IP] -p [PORT] -U '%' -c 'srvinfo;enumdomusers;netshareenumall' > [OUTPUT].txt; else echo rpcclient not found; fi",
            rpcclient_normalized,
        )

        self.assertEqual(
            enum4linux_ng_normalized,
            AppSettings._ensure_enum4linux_ng_command(enum4linux_ng_normalized),
        )
        self.assertEqual(
            smbmap_normalized,
            AppSettings._ensure_smbmap_command(smbmap_normalized),
        )
        self.assertEqual(
            rpcclient_normalized,
            AppSettings._ensure_rpcclient_enum_command(rpcclient_normalized),
        )

    def test_allowed_nonzero_exit_codes_include_cyberstrike_tool_metadata(self):
        from app.settings import AppSettings

        self.assertEqual({1}, AppSettings.allowed_nonzero_exit_codes("nikto"))
        self.assertEqual({4}, AppSettings.allowed_nonzero_exit_codes("wpscan"))
        self.assertEqual(set(), AppSettings.allowed_nonzero_exit_codes("nmap"))

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

    def test_deprecated_web_actions_are_removed_and_testssl_is_added(self):
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
                self.assertNotIn("http-wapiti", port_actions)
                self.assertNotIn("https-wapiti", port_actions)
                self.assertNotIn("sslyze", port_actions)
                self.assertNotIn("http-wordpress-plugins.nse", port_actions)
                self.assertIn("testssl.sh", port_actions)

                scheduler_settings = {row[0]: row for row in app_settings.getSchedulerSettings()}
                self.assertNotIn("http-wapiti", scheduler_settings)
                self.assertNotIn("https-wapiti", scheduler_settings)
                self.assertNotIn("sslyze", scheduler_settings)
                self.assertNotIn("http-wordpress-plugins.nse", scheduler_settings)
                self.assertIn("testssl.sh", scheduler_settings)

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
                self.assertEqual(vuln_command.count("-oA [OUTPUT]"), 2)

                scheduler_actions = {row[0]: row for row in app_settings.getSchedulerSettings()}
                screenshooter_scope = str(scheduler_actions["screenshooter"][1])
                self.assertIn("ms-wbt-server", screenshooter_scope)
                self.assertIn("vmrdp", screenshooter_scope)
                self.assertIn("vnc", screenshooter_scope)

    def test_nmap_output_normalization_adds_output_to_grouped_commands_only(self):
        from app.settings import AppSettings

        grouped = (
            "(nmap -Pn -n -sV -p [PORT] --script=vuln,vulners [IP] || "
            "nmap -Pn -n -sV -p [PORT] --script=vuln [IP])"
        )
        normalized = AppSettings._ensure_nmap_output_argument(grouped, "[OUTPUT]")

        self.assertEqual(normalized.count("-oA [OUTPUT]"), 2)
        self.assertNotIn(") -oA [OUTPUT]", normalized)

        wrapped = "(command -v nmap >/dev/null 2>&1 && nmap -Pn [IP]) || echo nmap not found"
        wrapped_normalized = AppSettings._ensure_nmap_output_argument(wrapped, "[OUTPUT]")

        self.assertIn("command -v nmap >/dev/null 2>&1", wrapped_normalized)
        self.assertIn("&& nmap -Pn [IP] -oA [OUTPUT])", wrapped_normalized)
        self.assertNotIn("command -v nmap >/dev/null 2>&1 -oA [OUTPUT]", wrapped_normalized)

    def test_nmap_stats_normalization_adds_stats_every_once(self):
        from app.settings import AppSettings

        command = "nmap -Pn -sV [IP] -p [PORT]"
        normalized = AppSettings._ensure_nmap_stats_every(command)
        self.assertIn("--stats-every 15s", normalized)
        self.assertIn("-vv", normalized)
        self.assertEqual(1, normalized.count("--stats-every"))

    def test_nmap_stats_normalization_adds_verbose_when_stats_already_present(self):
        from app.settings import AppSettings

        command = "nmap -Pn -sV [IP] -p [PORT] --stats-every 15s"
        normalized = AppSettings._ensure_nmap_stats_every(command)
        self.assertIn("--stats-every 15s", normalized)
        self.assertIn("-vv", normalized)
        self.assertEqual(1, normalized.count("--stats-every"))
        self.assertEqual(1, normalized.count("-vv"))

    def test_banner_normalization_replaces_broken_bash_wrapper(self):
        from app.settings import AppSettings

        command = 'bash -c \\"echo \\"\\" | nc -v -n -w1 [IP] [PORT]\\"'
        normalized = AppSettings._ensure_banner_command(command)
        self.assertEqual(
            "LEGION_BANNER_TARGET=[IP] LEGION_BANNER_PORT=[PORT] "
            "LEGION_BANNER_PROTOCOL=tcp python3 -m app.banner_probe",
            normalized,
        )

    def test_legacy_smb_action_migrations_replace_broken_quote_wrappers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_SMB_ACTIONS_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()
                port_actions = {row[1]: row for row in app_settings.getPortActions()}

                self.assertEqual(
                    "net rpc group members 'Domain Admins' -I [IP] -U '%'",
                    str(port_actions["smb-enum-admins"][2]),
                )
                self.assertEqual(
                    "rpcclient [IP] -U '%' -c 'enumdomusers'",
                    str(port_actions["smb-enum-users-rpc"][2]),
                )
                self.assertEqual(
                    "rpcclient [IP] -U '%' -c 'srvinfo'",
                    str(port_actions["smb-null-sessions"][2]),
                )
                self.assertIn("rpcclient [IP] -p [PORT] -U '%'", str(port_actions["rpcclient-enum"][2]))
                self.assertIn("impacket-samrdump -no-pass -port [PORT] [IP]", str(port_actions["samrdump"][2]))

    def test_legacy_shell_wrapper_actions_are_normalized_for_port_and_terminal_actions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_SHELL_WRAPPER_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()
                port_actions = {row[1]: row for row in app_settings.getPortActions()}
                terminal_actions = {row[1]: row for row in app_settings.getPortTerminalActions()}

                self.assertEqual(
                    "medusa -h [IP] -u root -P ./wordlists/snmp-default.txt -M snmp | grep SUCCESS",
                    str(port_actions["snmp-brute"][2]),
                )
                self.assertEqual(
                    "[term] rpcclient [IP] -p [PORT] -U '%'",
                    str(terminal_actions["rpcclient"][2]),
                )

    def test_disabled_broken_nse_actions_are_pruned_from_settings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = os.path.join(tmpdir, ".local", "share", "legion")
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, "legion.conf")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(LEGACY_DISABLED_ACTIONS_CONFIG)

            with patch.dict(os.environ, {"HOME": tmpdir}, clear=False):
                from app.settings import AppSettings

                app_settings = AppSettings()
                port_action_ids = {row[1] for row in app_settings.getPortActions()}
                scheduler_ids = {row[0] for row in app_settings.getSchedulerSettings()}

                self.assertNotIn("http-drupal-modules.nse", port_action_ids)
                self.assertNotIn("http-vuln-zimbra-lfi.nse", port_action_ids)
                self.assertNotIn("http-drupal-modules.nse", scheduler_ids)
                self.assertNotIn("http-vuln-zimbra-lfi.nse", scheduler_ids)


if __name__ == "__main__":
    unittest.main()
