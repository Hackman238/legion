import collections
import collections.abc
import threading
import unittest
from types import SimpleNamespace


for _name in ("Mapping", "MutableMapping", "Sequence"):
    if not hasattr(collections, _name):
        setattr(collections, _name, getattr(collections.abc, _name))


class _DummyRetryProcessRepo:
    def __init__(self, command, *, name="nmap-vuln.nse", host_ip="203.0.113.55", port="443", protocol="tcp"):
        self._details = {
            "id": 9,
            "command": str(command),
            "hostIp": str(host_ip),
            "port": str(port),
            "protocol": str(protocol),
            "name": str(name),
            "tabTitle": f"{name} ({port}/{protocol})",
            "outputfile": "/tmp/retry-output",
        }

    def getProcessById(self, process_id):
        if int(process_id) != 9:
            return None
        return dict(self._details)


class WebRuntimeRetryProcessTest(unittest.TestCase):
    def test_retry_process_falls_back_to_normalized_command_replay_for_unknown_process(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._ensure_process_tables = lambda: None
        runtime.settings = SimpleNamespace(portActions=[])
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
        self.assertEqual("command", result["retry_mode"])
        self.assertEqual("command-replay", result["retry_intent"])

    def test_retry_process_rebuilds_known_tool_from_context(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._ensure_process_tables = lambda: None
        runtime.settings = SimpleNamespace(portActions=[
            ("Run ffuf", "ffuf", "(command -v ffuf >/dev/null 2>&1 && ffuf -u [WEB_URL]/FUZZ -w /tmp/words.txt -s -of json -o [OUTPUT].json) || echo ffuf not found"),
        ])
        runtime.logic = SimpleNamespace(
            activeProject=SimpleNamespace(
                properties=SimpleNamespace(runningFolder="/tmp/legion-running"),
                repositoryContainer=SimpleNamespace(
                    processRepository=_DummyRetryProcessRepo(
                        "(command -v ffuf >/dev/null 2>&1 && ffuf -u https://203.0.113.55/FUZZ -w /tmp/words.txt -json -noninteractive -s > /tmp/out.jsonl) || echo ffuf not found",
                        name="ffuf",
                    )
                ),
            )
        )
        runtime._require_active_project = lambda: runtime.logic.activeProject
        captured = {}

        def _capture_run_manual_tool(**kwargs):
            captured.update(kwargs)
            return {
                "tool_id": kwargs["tool_id"],
                "host_ip": kwargs["host_ip"],
                "port": kwargs["port"],
                "protocol": kwargs["protocol"],
                "command": "ffuf -u https://203.0.113.55/FUZZ -w /tmp/words.txt -s -of json -o /tmp/legion-running/out.json",
                "executed": True,
                "reason": "completed",
                "process_id": 91,
            }

        runtime._run_manual_tool = _capture_run_manual_tool

        result = runtime.retry_process(9, timeout=180, job_id=6)

        self.assertTrue(result["executed"])
        self.assertEqual(91, result["process_id"])
        self.assertEqual("intent", result["retry_mode"])
        self.assertEqual("tool-run", result["retry_intent"])
        self.assertEqual("ffuf", captured["tool_id"])
        self.assertEqual("203.0.113.55", captured["host_ip"])
        self.assertEqual("443", captured["port"])
        self.assertEqual("tcp", captured["protocol"])
        self.assertEqual("", captured["command_override"])
        self.assertEqual(180, captured["timeout"])
        self.assertEqual(6, captured["job_id"])


if __name__ == "__main__":
    unittest.main()
