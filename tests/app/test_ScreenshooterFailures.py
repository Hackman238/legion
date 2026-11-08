import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class IsHttpsRobustnessTest(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_socket_errors_return_false(self, mock_urlopen):
        from app.httputil.isHttps import isHttps
        for exc in (TimeoutError("timed out"), ConnectionResetError("reset"), OSError("boom")):
            mock_urlopen.side_effect = exc
            self.assertFalse(isHttps("10.0.0.1", "443"))

    @patch("urllib.request.urlopen")
    def test_http_error_status_still_means_https(self, mock_urlopen):
        from urllib.error import HTTPError
        from app.httputil.isHttps import isHttps
        for code, msg in ((401, "Unauthorized"), (404, "Not Found"), (500, "Server Error")):
            mock_urlopen.side_effect = HTTPError("https://10.0.0.1:8443", code, msg, {}, None)
            self.assertTrue(isHttps("10.0.0.1", "8443"))

    @patch("urllib.request.urlopen")
    def test_response_is_closed(self, mock_urlopen):
        from app.httputil.isHttps import isHttps
        response = MagicMock()
        response.__enter__.return_value = response
        mock_urlopen.return_value = response
        self.assertTrue(isHttps("10.0.0.1", "443"))
        response.__exit__.assert_called_once()


class ScreenshooterFailureTest(unittest.TestCase):
    def _shooter(self):
        from app.Screenshooter import Screenshooter
        shooter = Screenshooter(1000)
        shooter.outputfolder = "/nonexistent"
        self.emitted = []
        shooter.done.connect(lambda ip, port, name: self.emitted.append((ip, port, name)))
        return shooter

    @patch("app.Screenshooter.run_eyewitness_capture")
    @patch("app.Screenshooter.isHttps", side_effect=OSError("probe failed"))
    def test_done_emitted_when_https_probe_raises(self, _mock_https, mock_capture):
        mock_capture.return_value = {"ok": False, "reason": "screenshot png missing", "attempts": []}
        shooter = self._shooter()
        shooter.addToQueue("10.0.0.1", "80", "10.0.0.1:80")
        shooter.run()
        self.assertEqual([("10.0.0.1", "80", "")], self.emitted)

    @patch("app.Screenshooter.run_eyewitness_capture")
    @patch("app.Screenshooter.isHttps", return_value=False)
    def test_tries_both_schemes_when_capture_fails_for_first_url(self, _mock_https, mock_capture):
        # Without EyeWitness the fallbacks still run per URL, so https must be tried after http fails.
        # A browser fallback exists but failed for this URL: the other scheme must still be tried.
        mock_capture.return_value = {"ok": False, "reason": "screenshot png missing",
                                     "attempts": [{"error": "eyewitness missing"}, {"error": "page load failed"}]}
        shooter = self._shooter()
        shooter.addToQueue("10.0.0.3", "8443", "10.0.0.3:8443")
        shooter.run()
        tried = [call.kwargs["url"] for call in mock_capture.call_args_list]
        self.assertEqual(["http://10.0.0.3:8443", "https://10.0.0.3:8443"], tried)
        self.assertEqual([("10.0.0.3", "8443", "")], self.emitted)

    @patch("app.Screenshooter.run_eyewitness_capture")
    @patch("app.Screenshooter.isHttps", return_value=False)
    def test_stops_after_first_scheme_when_no_capture_tool_exists(self, _mock_https, mock_capture):
        mock_capture.return_value = {
            "ok": False,
            "reason": "eyewitness missing",
            "attempts": [{"error": "no supported browser binary found"}],
        }
        shooter = self._shooter()
        shooter.addToQueue("10.0.0.4", "8443", "10.0.0.4:8443")
        shooter.run()
        self.assertEqual(1, mock_capture.call_count)
        self.assertEqual([("10.0.0.4", "8443", "")], self.emitted)

    def test_done_emitted_when_deferred_url_fails(self):
        shooter = self._shooter()

        def _boom():
            raise RuntimeError("dns failure")

        shooter.addToQueue("10.0.0.2", "443", _boom)
        shooter.run()
        self.assertEqual([("10.0.0.2", "443", "")], self.emitted)


if __name__ == "__main__":
    unittest.main()
