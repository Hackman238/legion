import os
import tempfile
import unittest
import json


class ObservationParsersTest(unittest.TestCase):
    def test_extract_tool_observations_suppresses_nuclei_rate_limited_matches(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = json.dumps({
            "template-id": "generic-admin-panel",
            "matched-at": "https://portal.example/admin",
            "info": {
                "name": "Authenticated admin panel exposure",
                "severity": "high",
                "classification": {"cve-id": ["CVE-2026-1111"]},
            },
            "extracted-results": ["429 Too Many Requests", "Retry-After: 120"],
        })

        parsed = extract_tool_observations(
            "nuclei-cves",
            output,
            port="443",
            protocol="tcp",
            service="https",
        )

        self.assertEqual([], parsed["findings"])
        quality_events = parsed["finding_quality_events"]
        self.assertEqual(1, len(quality_events))
        self.assertEqual("suppressed", quality_events[0]["action"])
        self.assertEqual("rate_limited_response", quality_events[0]["reason"])
        self.assertEqual("https://portal.example/admin", quality_events[0]["matched_url"])

    def test_extract_tool_observations_suppresses_nuclei_waf_block_page_matches(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "[CVE-2026-2222] [http] [critical] https://portal.example/login "
            "Attention Required! Cloudflare - Sorry, you have been blocked"
        )

        parsed = extract_tool_observations(
            "nuclei-cves",
            output,
            port="443",
            protocol="tcp",
            service="https",
        )

        self.assertEqual([], parsed["findings"])
        quality_events = parsed["finding_quality_events"]
        self.assertEqual(1, len(quality_events))
        self.assertEqual("suppressed", quality_events[0]["action"])
        self.assertEqual("waf_block_page", quality_events[0]["reason"])

    def test_extract_tool_observations_downgrades_nuclei_reflection_only_matches(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "[reflected-debug-endpoint] [http] [high] https://portal.example/debug "
            "request payload reflected in response"
        )

        parsed = extract_tool_observations(
            "nuclei-web",
            output,
            port="443",
            protocol="tcp",
            service="https",
        )

        self.assertEqual(1, len(parsed["findings"]))
        finding = parsed["findings"][0]
        self.assertEqual("info", finding["severity"])
        self.assertEqual("downgraded", finding["quality_action"])
        self.assertEqual("reflection_only_response", finding["quality_reason"])
        self.assertEqual("high", finding["severity_before"])

        quality_events = parsed["finding_quality_events"]
        self.assertEqual(1, len(quality_events))
        self.assertEqual("downgraded", quality_events[0]["action"])
        self.assertEqual("info", quality_events[0]["severity_after"])

    def test_extract_tool_observations_parses_nikto_findings_urls_and_technologies(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "- Nikto v2.5.0\n"
            "+ Server: Apache/2.4.57\n"
            "+ /admin/: Admin login page/section found.\n"
            "+ /phpinfo.php: Output from the phpinfo() function was found.\n"
            "+ Retrieved x-powered-by header: PHP/8.2.15\n"
            "+ OSVDB-1234: /cgi-bin/test.cgi: default CGI script found\n"
            "+ /: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS\n"
        )

        parsed = extract_tool_observations(
            "nikto",
            output,
            port="443",
            protocol="tcp",
            service="https",
            hostname="portal.example",
        )

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("https://portal.example/admin", urls)
        self.assertIn("https://portal.example/phpinfo.php", urls)
        self.assertIn("https://portal.example/cgi-bin/test.cgi", urls)
        self.assertIn("Apache", technologies)
        self.assertIn("PHP", technologies)
        self.assertIn("HTTP methods exposed", findings)
        self.assertTrue(any("Admin login page" in title for title in findings))

    def test_extract_tool_observations_parses_realistic_nikto_method_prefixed_lines(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "- Nikto v2.1.5/2.1.5\n"
            "+ Target Host: unifi.local\n"
            "+ Target Port: 8080\n"
            "+ GET /: The anti-clickjacking X-Frame-Options header is not present.\n"
            "+ OPTIONS /: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS \n"
            "+ -397: GET /: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.\n"
            "+ -5646: GET /: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.\n"
            "+ GET /status?full=true: Uncommon header 'x-frame-options' found, with contents: DENY\n"
        )

        parsed = extract_tool_observations(
            "nikto",
            output,
            port="8080",
            protocol="tcp",
            service="http",
            hostname="unifi.local",
        )

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("http://unifi.local:8080/status?full=true", urls)
        self.assertTrue(any("anti-clickjacking" in title.lower() for title in findings))
        self.assertIn("HTTP methods exposed", findings)
        self.assertTrue(any("'PUT'" in title for title in findings))

    def test_extract_tool_observations_ignores_nikto_uncommon_header_noise(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "- Nikto v2.1.5/2.1.5\n"
            "+ Target Host: unifi.local\n"
            "+ Target Port: 443\n"
            "+ GET /: The anti-clickjacking X-Frame-Options header is not present.\n"
            "+ GET .: Uncommon header 'referrer-policy' found, with contents: no-referrer\n"
            "+ GET .: Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN\n"
        )

        parsed = extract_tool_observations(
            "nikto",
            output,
            port="443",
            protocol="tcp",
            service="https",
            hostname="unifi.local",
        )

        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("The anti-clickjacking X-Frame-Options header is not present.", findings)
        self.assertFalse(any("Uncommon header" in title for title in findings))

    def test_extract_tool_observations_parses_dirsearch_artifact_urls(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = os.path.join(tmpdir, "dirsearch.json")
            with open(artifact, "w", encoding="utf-8") as handle:
                handle.write('{"results":[{"status":200,"path":"/admin/"},{"status":403,"path":"/login"}]}')

            parsed = extract_tool_observations(
                "dirsearch",
                "",
                artifact_refs=[artifact],
                port="443",
                protocol="tcp",
                service="https",
                hostname="portal.example",
            )

            urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
            finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
            self.assertIn("https://portal.example/admin", urls)
            self.assertIn("https://portal.example/login", urls)
            self.assertIn("Interesting web paths discovered (2)", finding_titles)

    def test_extract_tool_observations_parses_ffuf_json_artifact(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = os.path.join(tmpdir, "ffuf.json")
            with open(artifact, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"results":['
                    '{"url":"https://api.example/graphql","status":200},'
                    '{"url":"https://api.example/swagger","status":401}'
                    ']}'
                )

            parsed = extract_tool_observations(
                "ffuf",
                "",
                artifact_refs=[artifact],
                port="443",
                protocol="tcp",
                service="https",
                hostname="api.example",
            )

            urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
            self.assertIn("https://api.example/graphql", urls)
            self.assertIn("https://api.example/swagger", urls)

    def test_extract_tool_observations_ignores_ffuf_placeholder_url_when_results_are_empty(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            '{"commandline":"ffuf -u http://192.168.3.133:5357/FUZZ -w /usr/share/wordlists/dirb/common.txt",'
            '"results":[],'
            '"url":"http://192.168.3.133:5357/FUZZ"}'
        )

        parsed = extract_tool_observations("ffuf", output)

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        self.assertEqual(set(), urls)

    def test_extract_tool_observations_parses_realistic_dirsearch_nested_results(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            '{'
            '"results":['
            '{"http://192.168.3.133:5357/":['
            '{"content-length":312,"path":"/%2e%2e//google.com","redirect":null,"status":403},'
            '{"content-length":312,"path":"/\\\\..\\\\..\\\\etc\\\\passwd","redirect":null,"status":403}'
            ']}'
            ']'
            '}'
        )

        parsed = extract_tool_observations(
            "dirsearch",
            output,
            port="5357",
            protocol="tcp",
            service="http",
            host_ip="192.168.3.133",
        )

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        self.assertIn("http://192.168.3.133:5357/%2e%2e/google.com", urls)
        self.assertTrue(any(url.startswith("http://192.168.3.133:5357/") and "passwd" in url for url in urls))

    def test_extract_tool_observations_parses_nmap_vuln_and_http_vuln_blocks(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-20 15:44 CDT\n"
            "| http-vuln-cve2011-3192:\n"
            "|   VULNERABLE:\n"
            "|   Apache HTTP Server byterange filter DoS\n"
            "|     State: LIKELY VULNERABLE\n"
            "|     IDs: CVE:CVE-2011-3192\n"
            "|_    Risk factor: Medium\n"
            "Nmap done: 1 IP address (1 host up) scanned in 4.72 seconds\n"
        )

        parsed = extract_tool_observations("nmap-vuln.nse", output)

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        findings = list(parsed["findings"])
        cves = {str(item.get("cve", "")).strip().upper() for item in findings}
        evidence_rows = {str(item.get("evidence", "")).strip() for item in findings}

        self.assertIn("Apache HTTP Server", technologies)
        self.assertIn("CVE-2011-3192", cves)
        self.assertTrue(any("IDs: CVE:CVE-2011-3192" in row for row in evidence_rows))
        self.assertFalse(any("Starting Nmap" in row for row in evidence_rows))

    def test_extract_tool_observations_ignores_negative_nmap_vuln_runs(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "# Nmap 7.80 scan initiated Sat Mar 21 13:33:46 2026 as: nmap -Pn -sV -p 80 --script=vuln,vulners\n"
            "Nmap scan report for unifi.local (192.168.3.1)\n"
            "PORT   STATE SERVICE VERSION\n"
            "80/tcp open  http    nginx\n"
            "|_http-csrf: Couldn't find any CSRF vulnerabilities.\n"
            "|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php\n"
            "# Nmap done at Sat Mar 21 13:35:21 2026 -- 1 IP address (1 host up) scanned in 94.97 seconds\n"
        )

        parsed = extract_tool_observations("nmap-vuln.nse", output)

        self.assertEqual([], parsed["findings"])
        self.assertEqual([], parsed["technologies"])
        self.assertEqual([], parsed["urls"])

    def test_extract_tool_observations_parses_positive_nmap_vuln_suite_blocks(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "# Nmap 7.80 scan initiated Sat Mar 21 13:57:41 2026 as: nmap -Pn -sV -p 443 --script=vuln,vulners\n"
            "Nmap scan report for ruckuspki-devicesubca-1 (192.168.3.100)\n"
            "PORT    STATE SERVICE VERSION\n"
            "443/tcp open  ssl/https\n"
            "| http-csrf: \n"
            "| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ruckuspki-devicesubca-1\n"
            "|   Found the following possible CSRF vulnerabilities: \n"
            "|     \n"
            "|     Path: https://ruckuspki-devicesubca-1:443/admin/login.jsp\n"
            "|     Form id: login\n"
            "|_    Form action: login.jsp\n"
            "| http-slowloris-check: \n"
            "|   VULNERABLE:\n"
            "|   Slowloris DOS attack\n"
            "|     State: LIKELY VULNERABLE\n"
            "|     IDs:  CVE:CVE-2007-6750\n"
            "|     References:\n"
            "|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750\n"
            "|_      http://ha.ckers.org/slowloris/\n"
        )

        parsed = extract_tool_observations("nmap-vuln.nse", output)

        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        cves = {str(item.get("cve", "")).strip().upper() for item in parsed["findings"]}
        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}

        self.assertIn("Possible CSRF vulnerabilities detected", findings)
        self.assertIn("Slowloris DOS attack", findings)
        self.assertIn("CVE-2007-6750", cves)
        self.assertIn("https://ruckuspki-devicesubca-1/admin/login.jsp", urls)

    def test_extract_tool_observations_ignores_no_output_http_vuln_runs(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "# Nmap 7.80 scan initiated Sat Mar 21 13:35:42 2026 as: nmap -Pn -p 80 --script=http-vuln-cve2013-0156.nse\n"
            "Nmap scan report for unifi.local (192.168.3.1)\n"
            "Host is up.\n"
            "\n"
            "PORT   STATE SERVICE\n"
            "80/tcp open  http\n"
            "\n"
            "# Nmap done at Sat Mar 21 13:35:43 2026 -- 1 IP address (1 host up) scanned in 0.30 seconds\n"
        )

        parsed = extract_tool_observations("http-vuln-cve2013-0156.nse", output)

        self.assertEqual([], parsed["findings"])
        self.assertEqual([], parsed["technologies"])
        self.assertEqual([], parsed["urls"])

    def test_extract_tool_observations_parses_tls_and_waf_outputs(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        tls_output = (
            "TLSv1.0 enabled\n"
            "Preferred server cipher(s): TLS_RSA_WITH_RC4_128_SHA accepted\n"
            "Certificate is self-signed\n"
            "Secure renegotiation: not supported\n"
        )
        waf_output = (
            "[*] Checking https://portal.example\n"
            "[+] The site https://portal.example is behind Cloudflare (Cloudflare Inc.) WAF.\n"
        )

        tls_parsed = extract_tool_observations("sslscan", tls_output)
        waf_parsed = extract_tool_observations("wafw00f", waf_output)

        tls_titles = {str(item.get("title", "")).strip() for item in tls_parsed["findings"]}
        waf_titles = {str(item.get("title", "")).strip() for item in waf_parsed["findings"]}
        waf_technologies = {str(item.get("name", "")).strip() for item in waf_parsed["technologies"]}

        self.assertIn("TLSv1.0 supported", tls_titles)
        self.assertIn("Weak TLS cipher supported", tls_titles)
        self.assertIn("Self-signed TLS certificate", tls_titles)
        self.assertIn("Insecure TLS renegotiation", tls_titles)
        self.assertIn("WAF detected: Cloudflare", waf_titles)
        self.assertIn("Cloudflare WAF", waf_technologies)

    def test_extract_tool_observations_ignores_sslscan_not_vulnerable_heartbleed_and_session_renegotiation_noise(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "Heartbleed:\n"
            "TLSv1.2 not vulnerable to heartbleed\n"
            "Session renegotiation not supported\n"
            "TLSv1.0 enabled\n"
        )

        parsed = extract_tool_observations("sslscan", output)

        titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("TLSv1.0 supported", titles)
        self.assertNotIn("Heartbleed exposure", titles)
        self.assertNotIn("Insecure TLS renegotiation", titles)

    def test_extract_tool_observations_parses_realistic_sslscan_posture_findings(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "SSL/TLS Protocols:\n"
            "TLSv1.0   enabled\n"
            "TLSv1.1   enabled\n"
            "TLSv1.2   enabled\n"
            "TLS Fallback SCSV:\n"
            "Server does not support TLS Fallback SCSV\n"
            "TLS renegotiation:\n"
            "Secure session renegotiation supported\n"
            "SSL Certificate:\n"
            "RSA Key Strength:    1024\n"
            "Subject:  UniFi\n"
            "Issuer:   UniFi\n"
        )

        parsed = extract_tool_observations("sslscan", output)

        titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("TLSv1.0 supported", titles)
        self.assertIn("TLSv1.1 supported", titles)
        self.assertIn("TLS downgrade protection missing", titles)
        self.assertIn("Weak TLS certificate key size", titles)
        self.assertIn("Self-signed TLS certificate", titles)

    def test_extract_tool_observations_dedupes_sslscan_legacy_protocol_findings_from_cipher_lines(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "SSL/TLS Protocols:\n"
            "TLSv1.0   enabled\n"
            "TLSv1.1   enabled\n"
            "Accepted  TLSv1.1  128 bits  AES128-SHA\n"
            "Accepted  TLSv1.1  256 bits  AES256-SHA\n"
            "Accepted  TLSv1.0  128 bits  AES128-SHA\n"
            "Accepted  TLSv1.0  256 bits  AES256-SHA\n"
        )

        parsed = extract_tool_observations("sslscan", output)

        titles = [str(item.get("title", "")).strip() for item in parsed["findings"]]

        self.assertEqual(1, titles.count("TLSv1.0 supported"))
        self.assertEqual(1, titles.count("TLSv1.1 supported"))

    def test_extract_tool_observations_parses_realistic_sslyze_posture_findings(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            " * TLS 1.0 Cipher Suites:\n"
            "     Attempted to connect using 80 cipher suites.\n"
            "     The server accepted the following 1 cipher suites:\n"
            "         TLS_RSA_WITH_3DES_EDE_CBC_SHA             112\n"
            " * TLS 1.1 Cipher Suites:\n"
            "     Attempted to connect using 80 cipher suites.\n"
            "     Accepted 1 cipher suites.\n"
            "         TLS_RSA_WITH_AES_128_CBC_SHA             128\n"
            " * Deflate Compression:\n"
            "     VULNERABLE - Server supports Deflate compression\n"
            " * Session Renegotiation:\n"
            "     VULNERABLE - Secure renegotiation not supported\n"
            " * Heartbleed:\n"
            "     OK - Not vulnerable to Heartbleed\n"
            " * Downgrade Attacks:\n"
            "     TLS_FALLBACK_SCSV not supported\n"
            " * Certificate Information:\n"
            "     Subject:  demo.local\n"
            "     Issuer:   demo.local\n"
            "     Public Key Size: 1024\n"
            "     Signature Algorithm: sha1WithRSAEncryption\n"
        )

        parsed = extract_tool_observations("sslyze", output)

        titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("TLSv1.0 supported", titles)
        self.assertIn("TLSv1.1 supported", titles)
        self.assertIn("Weak TLS cipher supported", titles)
        self.assertIn("TLS compression enabled", titles)
        self.assertIn("Insecure TLS renegotiation", titles)
        self.assertIn("TLS downgrade protection missing", titles)
        self.assertIn("Weak TLS certificate key size", titles)
        self.assertIn("TLS certificate uses SHA-1", titles)
        self.assertIn("Self-signed TLS certificate", titles)
        self.assertNotIn("Heartbleed exposure", titles)

    def test_extract_tool_observations_ignores_sslyze_zero_accepted_cipher_sections(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            " * TLS 1.0 Cipher Suites:\n"
            "     Attempted to connect using 80 cipher suites.\n"
            "     Accepted 0 cipher suites.\n"
            " * TLS 1.1 Cipher Suites:\n"
            "     Attempted to connect using 80 cipher suites.\n"
            "     The server accepted the following 1 cipher suites:\n"
            "         TLS_RSA_WITH_AES_128_CBC_SHA             128\n"
        )

        parsed = extract_tool_observations("sslyze", output)

        titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertNotIn("TLSv1.0 supported", titles)
        self.assertIn("TLSv1.1 supported", titles)

    def test_extract_tool_observations_handles_wafw00f_generic_and_negative_output(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        generic_output = (
            "[*] Checking https://portal.example\n"
            "[+] Generic Detection results:\n"
            "[+] The site https://portal.example seems to be behind a WAF or some sort of security solution\n"
        )
        generic_parsed = extract_tool_observations("wafw00f", generic_output)

        generic_titles = {str(item.get("title", "")).strip() for item in generic_parsed["findings"]}
        generic_urls = {str(item.get("url", "")).strip() for item in generic_parsed["urls"]}

        self.assertIn("WAF detected", generic_titles)
        self.assertIn("https://portal.example", generic_urls)

        no_waf_output = (
            "[*] Checking https://portal.example\n"
            "[-] No WAF detected by the generic detection\n"
        )
        no_waf_parsed = extract_tool_observations("wafw00f", no_waf_output)

        self.assertEqual([], no_waf_parsed["findings"])
        self.assertEqual([], no_waf_parsed["technologies"])

    def test_extract_tool_observations_parses_wpscan_plain_text_output(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "[+] URL: https://blog.example/\n"
            "[+] WordPress version 6.5.2 identified (Latest)\n"
            "[+] XML-RPC seems to be enabled: https://blog.example/xmlrpc.php\n"
            "[i] Plugin(s) Identified:\n"
            "[+] akismet\n"
            "| Location: https://blog.example/wp-content/plugins/akismet/\n"
            "| [!] Title: Akismet < 5.3.1 - Authenticated Stored XSS (CVE-2024-12345)\n"
            "[i] Theme(s) Identified:\n"
            "[+] twentytwentyfour\n"
            "| Location: https://blog.example/wp-content/themes/twentytwentyfour/\n"
        )

        parsed = extract_tool_observations("wpscan", output)

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        cves = {str(item.get("cve", "")).strip().upper() for item in parsed["findings"]}

        self.assertIn("WordPress", technologies)
        self.assertIn("akismet", technologies)
        self.assertIn("twentytwentyfour", technologies)
        self.assertIn("https://blog.example/xmlrpc.php", urls)
        self.assertIn("https://blog.example/wp-content/plugins/akismet", urls)
        self.assertTrue(any("XML-RPC seems to be enabled" in title for title in findings))
        self.assertIn("CVE-2024-12345", cves)

    def test_extract_tool_observations_parses_wpscan_scan_aborted_json(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "{"
            "\"banner\":{\"version\":\"3.8.28\"},"
            "\"scan_aborted\":\"The remote website is up, but does not seem to be running WordPress.\","
            "\"target_url\":\"http://ruckuspki-devicesubca-1/\""
            "}"
        )

        parsed = extract_tool_observations("wpscan", output)

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}

        self.assertIn("http://ruckuspki-devicesubca-1", urls)
        self.assertIn("WPScan: target does not appear to be WordPress", findings)
        self.assertNotIn("WordPress", technologies)

    def test_extract_tool_observations_ignores_wpscan_banner_sponsor_urls(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "{"
            "\"banner\":{\"description\":\"WordPress Security Scanner by the WPScan Team\",\"sponsor\":\"Sponsored by Automattic - https://automattic.com/\"},"
            "\"scan_aborted\":\"The remote website is up, but does not seem to be running WordPress.\","
            "\"target_url\":\"http://ruckuspki-devicesubca-1/\""
            "}"
        )

        parsed = extract_tool_observations("wpscan", output)

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        self.assertIn("http://ruckuspki-devicesubca-1", urls)
        self.assertNotIn("https://automattic.com", urls)

    def test_extract_tool_observations_ignores_whatweb_redirect_tokens_as_technologies(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "http://ruckuspki-devicesubca-1/ [302 Found] Cookies[-ejs-session-], Country[RESERVED][ZZ], HTML5, "
            "HttpOnly[-ejs-session-], IP[192.168.3.100], RedirectLocation[http://ruckuspki-devicesubca-1/admin/login.jsp], "
            "Title[Moved Temporarily], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]\n"
            "http://ruckuspki-devicesubca-1/admin/login.jsp [302 Found] Country[RESERVED][ZZ], HTML5, IP[192.168.3.100], "
            "RedirectLocation[http://ruckuspki-devicesubca-1/tohttps.jsp], Title[Moved Temporarily], "
            "UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]\n"
        )

        parsed = extract_tool_observations("whatweb-http", output)

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}

        self.assertNotIn("HttpOnly", technologies)
        self.assertNotIn("login.jsp", technologies)
        self.assertIn("http://ruckuspki-devicesubca-1", urls)
        self.assertIn("http://ruckuspki-devicesubca-1/admin/login.jsp", urls)

    def test_extract_tool_observations_parses_curl_headers_server_and_redirect(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "HTTP/1.1 301 Moved Permanently\n"
            "Server: nginx\n"
            "Date: Sat, 21 Mar 2026 18:35:26 GMT\n"
            "Content-Type: text/html\n"
            "Location: https://unifi.local/\n"
        )

        parsed = extract_tool_observations("curl-headers", output)

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}

        self.assertIn("nginx", technologies)
        self.assertIn("https://unifi.local", urls)

    def test_extract_tool_observations_parses_feroxbuster_and_gobuster_plain_text(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "200 GET 12l 35w 412c https://portal.example/admin\n"
            "301 GET 0l 0w 0c https://portal.example/api-docs => https://portal.example/api-docs/\n"
            "/graphql             (Status: 200) [Size: 512]\n"
        )

        parsed = extract_tool_observations(
            "web-content-discovery",
            output,
            port="443",
            protocol="tcp",
            service="https",
            hostname="portal.example",
        )

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("https://portal.example/admin", urls)
        self.assertIn("https://portal.example/api-docs", urls)
        self.assertIn("https://portal.example/graphql", urls)
        self.assertIn("Interesting web paths discovered (3)", finding_titles)

    def test_extract_tool_observations_parses_sqlmap_injection_and_dbms(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "[INFO] testing URL 'https://portal.example/item.php?id=1'\n"
            "web application technology: Apache 2.4.57, PHP 8.2.15\n"
            "Parameter: id (GET)\n"
            "Type: boolean-based blind\n"
            "Title: AND boolean-based blind - WHERE or HAVING clause\n"
            "back-end DBMS: MySQL >= 5.0.12\n"
            "current user is DBA: True\n"
            "available databases [2]:\n"
            "[*] information_schema\n"
            "[*] acuart\n"
        )

        parsed = extract_tool_observations(
            "sqlmap",
            output,
            port="443",
            protocol="tcp",
            service="https",
        )

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        technologies = {str(item.get("name", "")).strip(): item for item in parsed["technologies"]}
        findings = {str(item.get("title", "")).strip(): item for item in parsed["findings"]}

        self.assertIn("https://portal.example/item.php?id=1", urls)
        self.assertIn("Apache", technologies)
        self.assertEqual("2.4.57", technologies["Apache"]["version"])
        self.assertIn("PHP", technologies)
        self.assertEqual("8.2.15", technologies["PHP"]["version"])
        self.assertIn("MySQL", technologies)
        self.assertEqual(">= 5.0.12", technologies["MySQL"]["version"])
        self.assertIn("SQL injection: GET id parameter injectable", findings)
        self.assertIn("SQLMap: current database user has DBA privileges", findings)
        self.assertIn("SQLMap enumerated databases (2)", findings)
        self.assertIn("acuart", findings["SQLMap enumerated databases (2)"]["evidence_items"])

    def test_extract_tool_observations_parses_http_sqlmap_artifact_output(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "[INFO] testing URL 'http://legacy.example/list.asp?cat=2'\n"
            "Parameter: cat (GET)\n"
            "Type: time-based blind\n"
            "Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)\n"
            "the back-end DBMS is MySQL\n"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = os.path.join(tmpdir, "sqlmap-output.txt")
            with open(artifact, "w", encoding="utf-8") as handle:
                handle.write(output)

            parsed = extract_tool_observations(
                "http-sqlmap",
                "",
                artifact_refs=[artifact],
                port="80",
                protocol="tcp",
                service="http",
            )

        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        findings = {str(item.get("title", "")).strip() for item in parsed["findings"]}

        self.assertIn("http://legacy.example/list.asp?cat=2", urls)
        self.assertIn("MySQL", technologies)
        self.assertIn("SQL injection: GET cat parameter injectable", findings)

    def test_extract_tool_observations_parses_rpcclient_domain_users_and_shares(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "Domain Name: CONTOSO\n"
            "user:[Administrator] rid:[0x1f4]\n"
            "user:[HelpDesk] rid:[0x453]\n"
            "netname: IPC$\n"
            "netname: NETLOGON\n"
        )
        parsed = extract_tool_observations(
            "rpcclient-enum",
            output,
            port="445",
            protocol="tcp",
            service="smb",
            host_ip="10.0.0.5",
        )

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        self.assertIn("Active Directory", technologies)
        self.assertIn("SMB domain identified: CONTOSO", finding_titles)
        self.assertIn("SMB users enumerated (2)", finding_titles)
        self.assertIn("SMB shares enumerated (2)", finding_titles)

    def test_extract_tool_observations_parses_enum4linux_share_tables(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "Domain Name: CONTOSO\n"
            "user:[Administrator] rid:[0x1f4]\n"
            "user:[HelpDesk] rid:[0x453]\n"
            "\n"
            "Sharename       Type      Comment\n"
            "---------       ----      -------\n"
            "ADMIN$          Disk      Remote Admin\n"
            "IPC$            IPC       Remote IPC\n"
        )

        parsed = extract_tool_observations(
            "enum4linux",
            output,
            port="445",
            protocol="tcp",
            service="smb",
            host_ip="10.0.0.5",
        )

        finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        self.assertIn("SMB domain identified: CONTOSO", finding_titles)
        self.assertIn("SMB users enumerated (2)", finding_titles)
        self.assertIn("SMB shares enumerated (2)", finding_titles)

    def test_extract_tool_observations_parses_samrdump_found_users(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "Found domain name: CONTOSO\n"
            "Found user: Administrator, uid = 500\n"
            "Found user: HelpDesk, uid = 1107\n"
        )

        parsed = extract_tool_observations(
            "samrdump",
            output,
            port="445",
            protocol="tcp",
            service="smb",
            host_ip="10.0.0.5",
        )

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        self.assertIn("Active Directory", technologies)
        self.assertIn("SMB domain identified: CONTOSO", finding_titles)
        self.assertIn("SMB users enumerated (2)", finding_titles)

    def test_extract_tool_observations_parses_nbtscan_verbose_output(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "NetBIOS Name Table for Host 192.168.1.123:\n"
            "\n"
            "Name             Service          Type\n"
            "----------------------------------------\n"
            "DPTSERVER        <00>             UNIQUE\n"
            "DPTSERVER        <20>             UNIQUE\n"
            "DEPARTMENT       <00>             GROUP\n"
            "ADMINISTRATOR    <03>             UNIQUE\n"
            "\n"
            "Adapter address: 00-a0-c9-12-34-56\n"
        )

        parsed = extract_tool_observations("nbtscan", output)

        findings = {str(item.get("title", "")).strip(): item for item in parsed["findings"]}
        self.assertIn("NetBIOS hosts enumerated (1)", findings)
        self.assertIn("NetBIOS workgroups/domains enumerated (1)", findings)
        self.assertIn("NetBIOS users enumerated (1)", findings)
        self.assertIn("NetBIOS file servers advertised (1)", findings)
        self.assertIn("DPTSERVER", findings["NetBIOS hosts enumerated (1)"]["evidence_items"])
        self.assertIn("DEPARTMENT", findings["NetBIOS workgroups/domains enumerated (1)"]["evidence_items"])
        self.assertIn("ADMINISTRATOR", findings["NetBIOS users enumerated (1)"]["evidence_items"])
        self.assertIn("192.168.1.123", findings["NetBIOS file servers advertised (1)"]["evidence_items"])

    def test_extract_tool_observations_parses_nbtscan_summary_and_script_friendly_output(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        summary_output = (
            "IP address     NetBIOS Name  Server    User           MAC address\n"
            "-----------------------------------------------------------------------\n"
            "192.168.1.2    MYCOMPUTER              JDOE           00-a0-c9-12-34-56\n"
            "192.168.1.5    WIN98COMP     <server>  RROE           00-a0-c9-78-90-00\n"
        )
        script_output = (
            "192.168.0.1:NT_SERVER:00U\n"
            "192.168.0.1:MY_DOMAIN:00G\n"
            "192.168.0.1:ADMINISTRATOR:03U\n"
            "192.168.0.1:NT_SERVER:20U\n"
        )

        summary_parsed = extract_tool_observations("nbtscan", summary_output)
        script_parsed = extract_tool_observations("nbtscan", script_output)

        summary_titles = {str(item.get("title", "")).strip() for item in summary_parsed["findings"]}
        script_titles = {str(item.get("title", "")).strip() for item in script_parsed["findings"]}

        self.assertIn("NetBIOS hosts enumerated (2)", summary_titles)
        self.assertIn("NetBIOS users enumerated (2)", summary_titles)
        self.assertIn("NetBIOS file servers advertised (1)", summary_titles)
        self.assertIn("NetBIOS hosts enumerated (1)", script_titles)
        self.assertIn("NetBIOS workgroups/domains enumerated (1)", script_titles)
        self.assertIn("NetBIOS users enumerated (1)", script_titles)
        self.assertIn("NetBIOS file servers advertised (1)", script_titles)

    def test_extract_tool_observations_parses_dnsmap_subdomains_and_internal_records(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "dnsmap 0.36 - DNS Network Mapper\n"
            "\n"
            "[+] searching (sub)domains for example.com using /tmp/wordlist.txt\n"
            "www.example.com\n"
            "IPv6 address #1: 2606:4700::6812:1b78\n"
            "\n"
            "www.example.com\n"
            "IP address #1: 104.18.27.120\n"
            "\n"
            "intranet.example.com\n"
            "IP address #1: 10.0.0.5\n"
            "[+] warning: internal IP address disclosed\n"
            "[+] 2 (sub)domains and 3 IP address(es) found\n"
        )

        parsed = extract_tool_observations("dnsmap", output)

        findings = {str(item.get("title", "")).strip(): item for item in parsed["findings"]}

        self.assertIn("DNS subdomains discovered (2)", findings)
        self.assertIn("Internal DNS records disclosed", findings)
        self.assertIn("Internal DNS records disclosed (1)", findings)
        self.assertIn("www.example.com", findings["DNS subdomains discovered (2)"]["evidence_items"])
        self.assertIn("intranet.example.com", findings["DNS subdomains discovered (2)"]["evidence_items"])
        self.assertIn("intranet.example.com -> 10.0.0.5", findings["Internal DNS records disclosed (1)"]["evidence_items"])

    def test_extract_tool_observations_parses_screenshot_metadata_artifact(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_path = os.path.join(temp_dir, "203.0.113.44-80-screenshot.png.json")
            with open(metadata_path, "w", encoding="utf-8") as handle:
                json.dump({
                    "tool_id": "screenshooter",
                    "filename": "203.0.113.44-80-screenshot.png",
                    "host_ip": "203.0.113.44",
                    "hostname": "portal.example",
                    "port": "80",
                    "protocol": "tcp",
                    "service_name": "http",
                    "target_url": "http://portal.example:80",
                    "capture_engine": "EyeWitness",
                }, handle)

            parsed = extract_tool_observations(
                "screenshooter",
                "",
                port="80",
                protocol="tcp",
                service="http",
                artifact_refs=[metadata_path],
                host_ip="203.0.113.44",
                hostname="portal.example",
            )

        titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}

        self.assertIn("Visual capture available for http://portal.example", titles)
        self.assertIn("http://portal.example", urls)


if __name__ == "__main__":
    unittest.main()
