import collections
import collections.abc
import threading
import unittest
from types import SimpleNamespace


for _name in ("Mapping", "MutableMapping", "Sequence"):
    if not hasattr(collections, _name):
        setattr(collections, _name, getattr(collections.abc, _name))


class _DummyRetryProcessRepo:
    def __init__(self, command):
        self._details = {
            "id": 9,
            "command": str(command),
            "hostIp": "203.0.113.55",
            "port": "443",
            "protocol": "tcp",
            "name": "nmap-vuln.nse",
            "tabTitle": "nmap-vuln.nse (443/tcp)",
            "outputfile": "/tmp/retry-output",
        }

    def getProcessById(self, process_id):
        if int(process_id) != 9:
            return None
        return dict(self._details)


class WebRuntimeRetryProcessTest(unittest.TestCase):
    def test_retry_process_normalizes_nmap_command_for_web_runtime(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._ensure_process_tables = lambda: None
        runtime.logic = SimpleNamespace(
            activeProject=SimpleNamespace(
                properties=SimpleNamespace(runningFolder="/tmp/legion-running"),
                repositoryContainer=SimpleNamespace(
                    processRepository=_DummyRetryProcessRepo(
                        "nmap -Pn -sV 203.0.113.55 -p 443"
                    )
                ),
            )
        )
        runtime._require_active_project = lambda: runtime.logic.activeProject
        captured = {}

        def _capture_run_command_with_tracking(**kwargs):
            captured.update(kwargs)
            return True, "executed", 77

        runtime._run_command_with_tracking = _capture_run_command_with_tracking

        result = runtime.retry_process(9, timeout=120, job_id=4)

        self.assertTrue(result["executed"])
        self.assertEqual(77, result["process_id"])
        self.assertIn("--stats-every 15s", captured["command"])
        self.assertIn("-vv", captured["command"])
        self.assertEqual("nmap-vuln.nse", captured["tool_name"])


if __name__ == "__main__":
    unittest.main()
