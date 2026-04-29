import socket
import unittest
from unittest.mock import patch


class ScreenshotTargetSelectionTest(unittest.TestCase):
    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_choose_preferred_host_prefers_resolvable_hostname(self, mock_getaddrinfo):
        from app.screenshot_targets import choose_preferred_host, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()

        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
        ]

        actual = choose_preferred_host("bing.com", "203.0.113.10")

        self.assertEqual("bing.com", actual)

    @patch("app.screenshot_targets.socket.getaddrinfo", side_effect=socket.gaierror("nope"))
    def test_choose_preferred_host_falls_back_to_ip_when_hostname_does_not_resolve(self, _mock_getaddrinfo):
        from app.screenshot_targets import choose_preferred_host, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()

        actual = choose_preferred_host("missing.example", "203.0.113.11")

        self.assertEqual("203.0.113.11", actual)

    @patch("app.screenshot_targets.socket.getaddrinfo", side_effect=socket.gaierror("nope"))
    def test_choose_preferred_screenshot_host_falls_back_to_ip_when_hostname_does_not_resolve(self, _mock_getaddrinfo):
        from app.screenshot_targets import choose_preferred_screenshot_host, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()

        actual = choose_preferred_screenshot_host("portal.example", "203.0.113.11")

        self.assertEqual("203.0.113.11", actual)

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_choose_preferred_screenshot_host_prefers_hostname_when_it_resolves_to_host_ip(self, mock_getaddrinfo):
        from app.screenshot_targets import choose_preferred_screenshot_host, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.11", 0)),
        ]

        actual = choose_preferred_screenshot_host("portal.example", "203.0.113.11")

        self.assertEqual("portal.example", actual)

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_choose_preferred_screenshot_host_falls_back_to_ip_when_hostname_resolves_elsewhere(self, mock_getaddrinfo):
        from app.screenshot_targets import choose_preferred_screenshot_host, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.99", 0)),
        ]

        actual = choose_preferred_screenshot_host("portal.example", "203.0.113.11")

        self.assertEqual("203.0.113.11", actual)

    def test_choose_preferred_host_falls_back_to_ip_for_unknown_hostname(self):
        from app.screenshot_targets import choose_preferred_host

        actual = choose_preferred_host("unknown", "203.0.113.12")

        self.assertEqual("203.0.113.12", actual)

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_apply_preferred_target_placeholders_uses_hostname_when_resolvable(self, mock_getaddrinfo):
        from app.screenshot_targets import apply_preferred_target_placeholders, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.44", 0)),
        ]

        command, target_host = apply_preferred_target_placeholders(
            "feroxbuster -u https://[IP]:[PORT] -o [OUTPUT].txt",
            hostname="bing.com",
            ip="203.0.113.44",
            port="443",
            output="/tmp/out",
        )

        self.assertEqual("bing.com", target_host)
        self.assertIn("https://bing.com:443", command)
        self.assertIn("/tmp/out.txt", command)

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_apply_preferred_target_placeholders_keeps_ip_for_numeric_only_commands(self, mock_getaddrinfo):
        from app.screenshot_targets import apply_preferred_target_placeholders, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.45", 0)),
        ]

        command, target_host = apply_preferred_target_placeholders(
            'bash -c "echo "" | nc -v -n -w1 [IP] [PORT]"',
            hostname="files.example",
            ip="203.0.113.45",
            port="445",
        )

        self.assertEqual("203.0.113.45", target_host)
        self.assertIn("203.0.113.45 445", command)

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_apply_preferred_target_placeholders_keeps_ip_for_nc_combined_short_flags(self, mock_getaddrinfo):
        from app.screenshot_targets import apply_preferred_target_placeholders, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.46", 0)),
        ]

        command, target_host = apply_preferred_target_placeholders(
            "printf '\\n' | nc -nv -w1 [IP] [PORT]",
            hostname="portal.example",
            ip="203.0.113.46",
            port="443",
        )

        self.assertEqual("203.0.113.46", target_host)
        self.assertIn("203.0.113.46 443", command)
        self.assertNotIn("portal.example 443", command)

    @patch("app.screenshot_targets.socket.getaddrinfo", side_effect=socket.gaierror("nope"))
    def test_apply_preferred_target_placeholders_prefers_hostname_for_scanners_even_when_unresolved(self, _mock_getaddrinfo):
        from app.screenshot_targets import apply_preferred_target_placeholders, resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()

        command, target_host = apply_preferred_target_placeholders(
            "nmap -Pn -sV [IP] -p [PORT]",
            hostname="portal.example",
            ip="203.0.113.50",
            port="443",
        )

        self.assertEqual("portal.example", target_host)
        self.assertIn("portal.example", command)
        self.assertNotIn("203.0.113.50", command)


if __name__ == "__main__":
    unittest.main()
