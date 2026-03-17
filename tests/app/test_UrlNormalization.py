import unittest

from app.url_normalization import normalize_discovered_url


class UrlNormalizationTest(unittest.TestCase):
    def test_normalize_discovered_url_strips_standard_ports_and_trailing_tokens(self):
        self.assertEqual("https://atlas.tantalumlabs.io", normalize_discovered_url("https://atlas.tantalumlabs.io:443/"))
        self.assertEqual("http://atlas.tantalumlabs.io", normalize_discovered_url("http://atlas.tantalumlabs.io:80/:"))
        self.assertEqual("https://tantalumlabs.io/login", normalize_discovered_url("https://tantalumlabs.io:443/login/"))

    def test_normalize_discovered_url_keeps_nonstandard_ports(self):
        self.assertEqual("https://tantalumlabs.io:8080", normalize_discovered_url("https://tantalumlabs.io:8080/"))
        self.assertEqual("http://tantalumlabs.io:8443/admin", normalize_discovered_url("http://tantalumlabs.io:8443/admin/:"))


if __name__ == "__main__":
    unittest.main()
