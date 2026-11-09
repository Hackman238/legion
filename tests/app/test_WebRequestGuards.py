import unittest

from app.web import request_host_is_rebound, request_is_cross_site


class CrossSiteRequestGuardTest(unittest.TestCase):
    def test_form_post_from_another_site_is_rejected(self):
        self.assertTrue(request_is_cross_site("POST", {"Origin": "http://evil.example"}, "127.0.0.1:5000"))
        # another local port is another origin (and only newer browsers add Sec-Fetch-Site: same-site)
        self.assertTrue(request_is_cross_site("POST", {"Origin": "http://127.0.0.1:8080"}, "127.0.0.1:5000"))
        self.assertTrue(request_is_cross_site("POST", {"Origin": "https://127.0.0.1"}, "127.0.0.1:5000"))
        self.assertTrue(request_is_cross_site("POST", {"Sec-Fetch-Site": "cross-site"}, "127.0.0.1:5000"))
        self.assertTrue(request_is_cross_site("POST", {"Origin": "null"}, "127.0.0.1:5000"))

    def test_same_origin_and_non_browser_posts_are_accepted(self):
        self.assertFalse(request_is_cross_site("POST", {"Origin": "http://127.0.0.1:5000", "Sec-Fetch-Site": "same-origin"}, "127.0.0.1:5000"))
        self.assertFalse(request_is_cross_site("POST", {}, "127.0.0.1:5000"))  # curl / scripts send no Origin
        self.assertFalse(request_is_cross_site("POST", {"Origin": "http://legion.lab"}, "legion.lab"))  # default port
        self.assertFalse(request_is_cross_site("GET", {"Origin": "http://evil.example"}, "127.0.0.1:5000"))

    def test_dns_rebinding_host_is_rejected_only_for_loopback_binds(self):
        self.assertTrue(request_host_is_rebound("127.0.0.1", "evil.example:5000"))
        self.assertFalse(request_host_is_rebound("127.0.0.1", "localhost:5000"))
        self.assertFalse(request_host_is_rebound("127.0.0.1", "[::1]:5000"))
        self.assertFalse(request_host_is_rebound("0.0.0.0", "legion.lab:5000"))


if __name__ == "__main__":
    unittest.main()
