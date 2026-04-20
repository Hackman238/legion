import unittest


class _RuntimeRouteRuntime:
    def __init__(self):
        self.calls = []

    def get_snapshot(self):
        self.calls.append(("get_snapshot",))
        return {"project": {"name": "demo"}, "scheduler_rationale_feed": [{"headline": "smbmap"}]}

    def list_jobs(self, limit=100):
        self.calls.append(("list_jobs", int(limit)))
        return [{"id": 1, "type": "scan", "status": "queued"}]

    def get_workspace_processes(self, limit=100):
        self.calls.append(("get_workspace_processes", int(limit)))
        return [{"id": 7, "name": "nmap", "status": "running"}]

    def get_job(self, job_id):
        self.calls.append(("get_job", int(job_id)))
        if int(job_id) != 1:
            raise KeyError(job_id)
        return {"id": 1, "status": "queued"}

    def stop_job(self, job_id):
        self.calls.append(("stop_job", int(job_id)))
        if int(job_id) != 1:
            raise KeyError(job_id)
        return {"stopped": True, "job_id": int(job_id)}


class WebRuntimeRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = _RuntimeRouteRuntime()
        self.client = create_app(self.runtime).test_client()

    def test_runtime_routes_delegate_to_runtime_service(self):
        snapshot = self.client.get("/api/snapshot")
        self.assertEqual(200, snapshot.status_code)
        self.assertEqual("demo", snapshot.json["project"]["name"])
        self.assertEqual("no-store, max-age=0, must-revalidate", snapshot.headers.get("Cache-Control"))

        jobs = self.client.get("/api/jobs?limit=10")
        self.assertEqual(200, jobs.status_code)
        self.assertEqual(1, len(jobs.json["jobs"]))

        processes = self.client.get("/api/processes?limit=5")
        self.assertEqual(200, processes.status_code)
        self.assertEqual("nmap", processes.json["processes"][0]["name"])

        details = self.client.get("/api/jobs/1")
        self.assertEqual(200, details.status_code)
        self.assertEqual(1, details.json["id"])

        stop = self.client.post("/api/jobs/1/stop", json={})
        self.assertEqual(200, stop.status_code)
        self.assertTrue(stop.json["stopped"])

        missing = self.client.get("/api/jobs/99")
        self.assertEqual(404, missing.status_code)

        missing_stop = self.client.post("/api/jobs/99/stop", json={})
        self.assertEqual(404, missing_stop.status_code)


if __name__ == "__main__":
    unittest.main()
