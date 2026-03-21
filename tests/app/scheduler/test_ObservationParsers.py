import os
import tempfile
import unittest


class ObservationParsersTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
