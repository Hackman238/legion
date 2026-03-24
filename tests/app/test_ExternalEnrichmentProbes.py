#!/usr/bin/env python3

import socket
import unittest
from unittest import mock
from urllib.error import HTTPError


class ExternalEnrichmentProbeTests(unittest.TestCase):
    def test_run_shodan_probe_queries_dns_domain_and_falls_back_to_simple_hostname_query(self):
        from app.shodan_probe import run_shodan_probe

        calls = []

        def fake_request(path, *, api_key, params, timeout=30):
            calls.append((path, dict(params)))
            if path == "dns/resolve":
                return {"connect.example.com": "203.0.113.10"}
            if path == "dns/domain/example.com":
                return {
                    "domain": "example.com",
                    "data": [{"subdomain": "api", "type": "A", "value": "203.0.113.30"}],
                }
            if path == "shodan/host/search" and params.get("query") == 'hostname:"connect.example.com"':
                raise HTTPError("https://api.shodan.io/shodan/host/search", 400, "bad request", hdrs=None, fp=None)
            if path == "shodan/host/search" and params.get("query") == "hostname:connect.example.com":
                return {
                    "total": 1,
                    "matches": [
                        {
                            "ip_str": "203.0.113.10",
                            "port": 443,
                            "hostnames": ["connect.example.com"],
                            "domains": ["connect.example.com", "example.com"],
                            "product": "nginx",
                        },
                    ],
                }
            raise AssertionError(f"unexpected request: {path} {params}")

        with mock.patch("app.shodan_probe._perform_request", side_effect=fake_request):
            payload = run_shodan_probe("connect.example.com", "test-key", limit=10, timeout=15)

        self.assertEqual("connect.example.com", payload["exact_hostname"])
        self.assertEqual("example.com", payload["root_domain"])
        self.assertEqual("hostname:connect.example.com", payload["search_query"])
        self.assertIn("connect.example.com", payload["dns_resolve"])
        self.assertEqual("example.com", payload["dns_domain"]["domain"])
        self.assertEqual(4, len(calls))

    def test_run_grayhatwarfare_probe_falls_back_to_keyword_search_on_timeout(self):
        from app.grayhatwarfare_probe import run_grayhatwarfare_probe

        calls = []

        def fake_request(path, *, api_key, params, timeout=30):
            calls.append((path, dict(params)))
            if path == "buckets":
                return {
                    "buckets": [{"bucket": "tantalumlabs-public"}],
                    "meta": {"results": 1},
                }
            if path == "files" and params.get("regexp") == "1":
                raise socket.timeout()
            if path == "files":
                return {
                    "files": [{"bucket": "tantalumlabs-public", "url": "https://example.s3.amazonaws.com/foo.txt"}],
                    "meta": {"results": 1},
                }
            raise AssertionError(f"unexpected request: {path} {params}")

        with mock.patch("app.grayhatwarfare_probe._perform_request", side_effect=fake_request):
            payload = run_grayhatwarfare_probe("connect.tantalumlabs.io", "test-key", limit=5, timeout=10)

        self.assertEqual("tantalumlabs.io", payload["root_domain"])
        self.assertEqual("tantalumlabs", payload["keyword"])
        self.assertEqual("tantalumlabs", payload["meta"]["file_fallback_keyword_query"])
        self.assertEqual("timeout", payload["meta"]["file_fallback_reason"])
        self.assertEqual(3, len(calls))


if __name__ == "__main__":
    unittest.main()
