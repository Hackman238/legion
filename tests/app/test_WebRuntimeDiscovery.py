import threading
import unittest
from unittest.mock import MagicMock


class WebRuntimeDiscoveryTest(unittest.TestCase):
    def test_run_governed_discovery_routes_through_shared_scan_path(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._normalize_targets = lambda targets: [str(targets[0] or "").strip()] if str(targets[0] or "").strip() else []
        runtime.create_new_temporary_project = MagicMock()
        runtime._run_nmap_scan_and_import = MagicMock(return_value={"targets": ["10.0.0.5"], "xml_path": "/tmp/demo.xml"})
        runtime.get_project_details = MagicMock(return_value={"name": "temp.legion"})
        runtime.get_workspace_hosts = MagicMock(return_value=[{"id": 1, "ip": "10.0.0.5"}])
        runtime.get_workspace_services = MagicMock(return_value=[{"service": "http"}])
        runtime.get_scheduler_approvals = MagicMock(return_value=[{"id": 77}])
        runtime.get_scheduler_decisions = MagicMock(return_value=[{"id": 88}])

        result = WebRuntime.run_governed_discovery(runtime, "10.0.0.5", run_actions=True)

        runtime.create_new_temporary_project.assert_called_once_with()
        runtime._run_nmap_scan_and_import.assert_called_once_with(
            ["10.0.0.5"],
            discovery=True,
            staged=False,
            run_actions=True,
            nmap_path="nmap",
            nmap_args="",
            scan_mode="legacy",
            scan_options={},
        )
        self.assertEqual("10.0.0.5", result["target"])
        self.assertEqual([{"id": 1, "ip": "10.0.0.5"}], result["results"])
        self.assertEqual([{"id": 77}], result["approvals"])
        self.assertEqual([{"id": 88}], result["decisions"])

    def test_run_governed_discovery_requires_target(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._normalize_targets = lambda _targets: []

        with self.assertRaises(ValueError):
            WebRuntime.run_governed_discovery(runtime, "", run_actions=False)


if __name__ == "__main__":
    unittest.main()
