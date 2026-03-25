import collections
import collections.abc
import unittest
from types import SimpleNamespace


for _name in ("Mapping", "MutableMapping", "Sequence"):
    if not hasattr(collections, _name):
        setattr(collections, _name, getattr(collections.abc, _name))


class _DummyProcessRepo:
    def __init__(self, rows):
        self._rows = list(rows)

    def getProcesses(self, _filters, showProcesses='True', sort='desc', ncol='id'):
        _ = showProcesses
        _ = sort
        _ = ncol
        return list(self._rows)


class WebRuntimeProcessDisplayTest(unittest.TestCase):
    def test_terminal_statuses_hide_eta_and_finished_forces_100_percent(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._ensure_process_tables = lambda: None
        runtime.logic = SimpleNamespace(
            activeProject=SimpleNamespace(
                repositoryContainer=SimpleNamespace(
                    processRepository=_DummyProcessRepo([
                        {
                            "id": 1,
                            "name": "banner",
                            "hostIp": "10.0.0.5",
                            "port": "80",
                            "protocol": "tcp",
                            "status": "Finished",
                            "startTime": "2026-02-17T00:00:00Z",
                            "percent": "0",
                            "estimatedRemaining": 37,
                        },
                        {
                            "id": 2,
                            "name": "nikto",
                            "hostIp": "10.0.0.6",
                            "port": "443",
                            "protocol": "tcp",
                            "status": "Problem",
                            "startTime": "2026-02-17T00:00:00Z",
                            "percent": "23.0",
                            "estimatedRemaining": 111,
                        },
                        {
                            "id": 3,
                            "name": "nmap",
                            "hostIp": "10.0.0.7",
                            "port": "22",
                            "protocol": "tcp",
                            "status": "Running",
                            "startTime": "2026-02-17T00:00:00Z",
                            "percent": "35.2",
                            "estimatedRemaining": 44,
                        },
                    ])
                )
            )
        )

        rows = runtime._processes(limit=10)

        self.assertEqual("100", rows[0]["percent"])
        self.assertIsNone(rows[0]["estimatedRemaining"])
        self.assertIsNone(rows[1]["estimatedRemaining"])
        self.assertEqual("35.2", rows[2]["percent"])
        self.assertEqual(44, rows[2]["estimatedRemaining"])
        self.assertEqual("Problem", rows[1]["status"])

    def test_running_processes_include_structured_progress_summary(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._ensure_process_tables = lambda: None
        runtime.logic = SimpleNamespace(
            activeProject=SimpleNamespace(
                repositoryContainer=SimpleNamespace(
                    processRepository=_DummyProcessRepo([
                        {
                            "id": 9,
                            "name": "nuclei-web",
                            "hostIp": "10.0.0.9",
                            "port": "5357",
                            "protocol": "tcp",
                            "status": "Running",
                            "startTime": "2026-03-22T05:08:46Z",
                            "elapsed": 15,
                            "percent": "53.0",
                            "estimatedRemaining": 13,
                            "progressMessage": "Requests 2534/4720 | RPS 166 | Matches 0 | Errors 16",
                            "progressSource": "nuclei",
                            "progressUpdatedAt": "22 Mar 2026 00:08:46.336234",
                        },
                    ])
                )
            )
        )

        rows = runtime._processes(limit=10)

        self.assertEqual(1, len(rows))
        self.assertEqual(15, rows[0]["elapsed"])
        self.assertEqual("Nuclei", rows[0]["progress"]["source"])
        self.assertIn("53.0%", rows[0]["progress"]["summary"])
        self.assertIn("Requests 2534/4720", rows[0]["progress"]["summary"])
        self.assertEqual("0m 13s", rows[0]["progress"]["estimated_remaining_display"])

    def test_extract_nuclei_progress_from_text_parses_requests_summary(self):
        from app.web.runtime import WebRuntime

        percent, remaining, message = WebRuntime._extract_nuclei_progress_from_text(
            "[0:00:15] | Templates: 2720 | Hosts: 1 | RPS: 166 | Matched: 0 | Errors: 16 | Requests: 2534/4720 (53%)",
            runtime_seconds=15.0,
        )

        self.assertEqual(53.0, percent)
        self.assertGreaterEqual(int(remaining or 0), 12)
        self.assertIn("Requests 2534/4720", message)
        self.assertIn("RPS 166", message)
        self.assertIn("Errors 16", message)

    def test_extract_tshark_passive_progress_uses_duration_and_elapsed(self):
        from app.web.runtime import WebRuntime

        percent, remaining, message = WebRuntime._extract_tshark_passive_progress(
            "tshark -i eth0 -n -q -a duration:900 -f 'arp or broadcast' -w /tmp/capture.pcapng",
            runtime_seconds=362.0,
        )

        self.assertAlmostEqual(40.2, float(percent or 0.0), places=1)
        self.assertEqual(538, remaining)
        self.assertEqual("Elapsed 6m 02s", message)

    def test_running_tshark_processes_include_structured_progress_summary(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._ensure_process_tables = lambda: None
        runtime.logic = SimpleNamespace(
            activeProject=SimpleNamespace(
                repositoryContainer=SimpleNamespace(
                    processRepository=_DummyProcessRepo([
                        {
                            "id": 11,
                            "name": "tshark-passive-capture",
                            "hostIp": "",
                            "port": "",
                            "protocol": "",
                            "status": "Running",
                            "startTime": "2026-03-24T19:00:00Z",
                            "elapsed": 362,
                            "percent": "40.2",
                            "estimatedRemaining": 538,
                            "progressMessage": "Elapsed 6m 02s",
                            "progressSource": "tshark",
                            "progressUpdatedAt": "24 Mar 2026 14:06:02.000000",
                        },
                    ])
                )
            )
        )

        rows = runtime._processes(limit=10)

        self.assertEqual(1, len(rows))
        self.assertEqual("TShark", rows[0]["progress"]["source"])
        self.assertIn("40.2%", rows[0]["progress"]["summary"])
        self.assertIn("ETA 8m 58s", rows[0]["progress"]["summary"])
        self.assertIn("Elapsed 6m 02s", rows[0]["progress"]["summary"])
        self.assertEqual("8m 58s", rows[0]["progress"]["estimated_remaining_display"])


if __name__ == "__main__":
    unittest.main()
