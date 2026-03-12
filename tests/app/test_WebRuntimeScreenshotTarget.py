import collections
import collections.abc
import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch


for _name in ("Mapping", "MutableMapping", "Sequence", "Callable"):
    if not hasattr(collections, _name):
        setattr(collections, _name, getattr(collections.abc, _name))


class _HostRepo:
    def __init__(self, hostname):
        self._hostname = hostname

    def getHostByIP(self, _ip):
        return SimpleNamespace(hostname=self._hostname)


class WebRuntimeScreenshotTargetTest(unittest.TestCase):
    def test_take_screenshot_prefers_hostname_when_helper_returns_hostname(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()

        with tempfile.TemporaryDirectory() as temp_dir:
            screenshot_dir = os.path.join(temp_dir, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            src_path = os.path.join(temp_dir, "capture.png")
            with open(src_path, "wb") as handle:
                handle.write(b"png")

            project = SimpleNamespace(
                properties=SimpleNamespace(outputFolder=temp_dir),
                repositoryContainer=SimpleNamespace(hostRepository=_HostRepo("bing.com")),
            )
            runtime._require_active_project = lambda: project

            with patch("app.web.runtime.choose_preferred_host", return_value="bing.com") as mock_choose:
                with patch("app.web.runtime.isHttps", return_value=False):
                    with patch("app.web.runtime.run_eyewitness_capture", return_value={
                        "ok": True,
                        "screenshot_path": src_path,
                        "returncode": 0,
                    }) as mock_capture:
                        executed, reason = WebRuntime._take_screenshot(runtime, "203.0.113.44", "80", "http")

        self.assertTrue(executed)
        self.assertEqual("completed", reason)
        mock_choose.assert_called_once_with("bing.com", "203.0.113.44")
        self.assertEqual("http://bing.com:80", mock_capture.call_args.kwargs["url"])


if __name__ == "__main__":
    unittest.main()
