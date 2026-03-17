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


class _PortRepo:
    def __init__(self, ports):
        self._ports = list(ports)

    def getPortsByHostId(self, _host_id):
        return list(self._ports)


class _ServiceRepo:
    def __init__(self, services):
        self._services = dict(services)

    def getServiceById(self, service_id):
        return self._services.get(service_id)


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

            with patch("app.web.runtime.choose_preferred_screenshot_host", return_value="bing.com") as mock_choose:
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

    def test_collect_host_screenshot_targets_only_keeps_open_web_ports(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._resolve_host = lambda _host_id: SimpleNamespace(id=11, ip="203.0.113.44", hostname="bing.com")

        project = SimpleNamespace(
            repositoryContainer=SimpleNamespace(
                portRepository=_PortRepo([
                    SimpleNamespace(portId="80", protocol="tcp", state="open", serviceId=1),
                    SimpleNamespace(portId="443", protocol="tcp", state="open", serviceId=2),
                    SimpleNamespace(portId="8443", protocol="tcp", state="open", serviceId=None),
                    SimpleNamespace(portId="3389", protocol="tcp", state="open", serviceId=3),
                    SimpleNamespace(portId="53", protocol="udp", state="open", serviceId=4),
                    SimpleNamespace(portId="8080", protocol="tcp", state="closed", serviceId=5),
                ]),
                serviceRepository=_ServiceRepo({
                    1: SimpleNamespace(name="http"),
                    2: SimpleNamespace(name="https"),
                    3: SimpleNamespace(name="rdp"),
                    4: SimpleNamespace(name="domain"),
                    5: SimpleNamespace(name="http-proxy"),
                }),
            ),
        )
        runtime._require_active_project = lambda: project

        targets = WebRuntime._collect_host_screenshot_targets(runtime, 11)

        self.assertEqual(
            [
                {"port": "80", "protocol": "tcp", "service_name": "http"},
                {"port": "443", "protocol": "tcp", "service_name": "https"},
                {"port": "8443", "protocol": "tcp", "service_name": ""},
            ],
            targets,
        )


if __name__ == "__main__":
    unittest.main()
