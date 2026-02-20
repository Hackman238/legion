import unittest
from types import SimpleNamespace


class _DummyProcessRepo:
    def __init__(self, rows):
        self._rows = list(rows)

    def getProcesses(self, _filters, showProcesses='True', sort='desc', ncol='id'):
        _ = showProcesses
        _ = sort
        _ = ncol
        return list(self._rows)


class WebRuntimeProcessDisplayTest(unittest.TestCase):
    def test_terminal_statuses_force_zero_eta_and_finished_forces_100_percent(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
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
                            "status": "Crashed",
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
        self.assertEqual(0, rows[0]["estimatedRemaining"])
        self.assertEqual(0, rows[1]["estimatedRemaining"])
        self.assertEqual("35.2", rows[2]["percent"])
        self.assertEqual(44, rows[2]["estimatedRemaining"])


if __name__ == "__main__":
    unittest.main()
