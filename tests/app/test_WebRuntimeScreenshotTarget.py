import collections
import collections.abc
import json
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
        runtime._hostname_for_ip = lambda _ip: "bing.com"

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

            with patch("app.web.runtime_screenshots.choose_preferred_screenshot_host", return_value="bing.com") as mock_choose:
                with patch("app.web.runtime_screenshots.isHttps", return_value=False):
                    with patch("app.web.runtime_screenshots.run_eyewitness_capture", return_value={
                        "ok": True,
                        "screenshot_path": src_path,
                        "returncode": 0,
                    }) as mock_capture:
                        executed, reason = WebRuntime._take_screenshot(runtime, "203.0.113.44", "80", "http")

        self.assertTrue(executed)
        self.assertEqual("completed", reason)
        mock_choose.assert_called_once_with("bing.com", "203.0.113.44")
        self.assertEqual("http://bing.com:80", mock_capture.call_args.kwargs["url"])

    @patch("app.screenshot_targets.socket.getaddrinfo", side_effect=OSError("dns unavailable"))
    def test_take_screenshot_uses_ip_when_hostname_is_not_resolvable(self, _mock_getaddrinfo):
        from app.screenshot_targets import resolve_hostname_addresses
        from app.web.runtime import WebRuntime

        resolve_hostname_addresses.cache_clear()

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._hostname_for_ip = lambda _ip: "unifi.local"

        with tempfile.TemporaryDirectory() as temp_dir:
            src_path = os.path.join(temp_dir, "capture.png")
            with open(src_path, "wb") as handle:
                handle.write(b"png")

            project = SimpleNamespace(
                properties=SimpleNamespace(outputFolder=temp_dir),
                repositoryContainer=SimpleNamespace(hostRepository=_HostRepo("unifi.local")),
            )
            runtime._require_active_project = lambda: project

            with patch("app.web.runtime_screenshots.isHttps", return_value=False):
                with patch("app.web.runtime_screenshots.run_eyewitness_capture", return_value={
                    "ok": True,
                    "screenshot_path": src_path,
                    "returncode": 0,
                }) as mock_capture:
                    executed, reason = WebRuntime._take_screenshot(runtime, "203.0.113.44", "80", "http")

        self.assertTrue(executed)
        self.assertEqual("completed", reason)
        self.assertEqual("http://203.0.113.44:80", mock_capture.call_args.kwargs["url"])

    def test_take_screenshot_return_artifacts_writes_metadata_sidecar(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._hostname_for_ip = lambda _ip: "portal.example"

        with tempfile.TemporaryDirectory() as temp_dir:
            screenshot_dir = os.path.join(temp_dir, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            src_path = os.path.join(temp_dir, "capture.png")
            with open(src_path, "wb") as handle:
                handle.write(b"png")

            project = SimpleNamespace(
                properties=SimpleNamespace(outputFolder=temp_dir),
                repositoryContainer=SimpleNamespace(hostRepository=_HostRepo("portal.example")),
            )
            runtime._require_active_project = lambda: project

            with patch("app.web.runtime_screenshots.choose_preferred_screenshot_host", return_value="portal.example"):
                with patch("app.web.runtime_screenshots.isHttps", return_value=False):
                    with patch("app.web.runtime_screenshots.run_eyewitness_capture", return_value={
                        "ok": True,
                        "screenshot_path": src_path,
                        "returncode": 0,
                        "executable": "/usr/local/bin/EyeWitness",
                    }):
                        executed, reason, artifact_refs = WebRuntime._take_screenshot(
                            runtime,
                            "203.0.113.44",
                            "80",
                            "http",
                            return_artifacts=True,
                        )

            self.assertTrue(executed)
            self.assertEqual("completed", reason)
            self.assertEqual(2, len(artifact_refs))
            self.assertTrue(any(str(ref).endswith(".png") for ref in artifact_refs))
            metadata_path = next(str(ref) for ref in artifact_refs if str(ref).endswith(".json"))
            with open(metadata_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual("screenshooter", payload["tool_id"])
            self.assertEqual("http://portal.example:80", payload["target_url"])
            self.assertEqual("EyeWitness", payload["capture_engine"])
            self.assertEqual("80", payload["port"])

    def test_list_screenshots_for_host_includes_sidecar_metadata(self):
        from app.screenshot_metadata import write_screenshot_metadata
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()

        with tempfile.TemporaryDirectory() as temp_dir:
            screenshot_dir = os.path.join(temp_dir, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            screenshot_path = os.path.join(screenshot_dir, "203.0.113.44-80-screenshot.png")
            with open(screenshot_path, "wb") as handle:
                handle.write(b"png")
            write_screenshot_metadata(screenshot_path, {
                "tool_id": "screenshooter",
                "filename": "203.0.113.44-80-screenshot.png",
                "port": "80",
                "protocol": "tcp",
                "service_name": "http",
                "target_url": "http://portal.example:80",
                "capture_engine": "EyeWitness",
                "captured_at": "2026-03-22T06:00:00+00:00",
            })

            project = SimpleNamespace(properties=SimpleNamespace(outputFolder=temp_dir))
            rows = WebRuntime._list_screenshots_for_host(runtime, project, "203.0.113.44")

        self.assertEqual(1, len(rows))
        self.assertEqual("/api/screenshots/203.0.113.44-80-screenshot.png", rows[0]["artifact_ref"])
        self.assertEqual("http://portal.example:80", rows[0]["target_url"])
        self.assertEqual("EyeWitness", rows[0]["capture_engine"])

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
