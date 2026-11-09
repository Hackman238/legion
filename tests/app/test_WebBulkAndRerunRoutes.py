import threading
import unittest
from types import SimpleNamespace


class _BulkRuntime:
    """Minimal runtime for the bulk host, batch tool and scan re-run routes."""

    def __init__(self):
        self.calls = []

    def start_host_rescan_job(self, host_id):
        self.calls.append(("start_host_rescan_job", int(host_id)))
        if int(host_id) == 13:
            raise ValueError("Host 13 does not have a valid IP.")
        return {"id": 900 + int(host_id), "type": "nmap-scan"}

    def start_host_dig_deeper_job(self, host_id):
        self.calls.append(("start_host_dig_deeper_job", int(host_id)))
        return {"id": 800 + int(host_id), "type": "scheduler-dig-deeper"}

    def start_host_screenshot_refresh_job(self, host_id):
        self.calls.append(("start_host_screenshot_refresh_job", int(host_id)))
        return {"id": 700 + int(host_id), "type": "screenshot-refresh"}

    def delete_host_workspace(self, host_id):
        self.calls.append(("delete_host_workspace", int(host_id)))
        return {"deleted": True, "host_id": int(host_id)}

    def start_bulk_host_remove_job(self, host_ids):
        self.calls.append(("start_bulk_host_remove_job", list(host_ids)))
        return {"id": 1200, "type": "hosts-bulk-remove", "status": "queued"}

    def start_tool_run_job(self, host_ip, port, protocol, tool_id, timeout=300, parameters=None):
        self.calls.append(("start_tool_run_job", str(host_ip), str(port), str(protocol), str(tool_id), int(timeout), dict(parameters or {})))
        if str(host_ip) == "10.0.0.9":
            raise KeyError("Unknown tool id: nope")
        return {"id": len(self.calls), "type": "tool-run"}

    def rerun_scan_submission(self, submission_id):
        self.calls.append(("rerun_scan_submission", int(submission_id)))
        if int(submission_id) == 404:
            raise KeyError("Unknown scan submission id: 404")
        if int(submission_id) == 400:
            raise ValueError("Scan submissions of kind 'unknown' cannot be re-run.")
        return {"id": 5000 + int(submission_id), "type": "nmap-scan"}


class WebBulkAndRerunRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = _BulkRuntime()
        self.client = create_app(self.runtime).test_client()

    def test_bulk_host_action_reports_per_host_outcomes(self):
        response = self.client.post("/api/workspace/hosts/bulk-action", json={"action": "rescan", "host_ids": [11, "12", 13, 11, "x"]})
        self.assertEqual(202, response.status_code)
        body = response.json
        self.assertEqual("partial", body["status"])
        self.assertEqual(3, body["requested"])
        self.assertEqual(2, body["succeeded"])
        self.assertEqual(1, body["failed"])
        failed = [item for item in body["results"] if item["status"] == "error"]
        self.assertEqual(13, failed[0]["host_id"])
        self.assertIn("valid IP", failed[0]["error"])
        # duplicates and junk ids are dropped before any call is made
        self.assertEqual(3, len([call for call in self.runtime.calls if call[0] == "start_host_rescan_job"]))

    def test_bulk_remove_queues_one_job_for_the_selection(self):
        response = self.client.post("/api/workspace/hosts/bulk-action", json={"action": "remove", "host_ids": [11, 12, 12]})
        self.assertEqual(202, response.status_code)
        self.assertEqual("accepted", response.json["status"])
        self.assertEqual("hosts-bulk-remove", response.json["job"]["type"])
        self.assertEqual([("start_bulk_host_remove_job", [11, 12])], self.runtime.calls)

    def test_bulk_remove_job_deletes_each_host_and_reports_per_host(self):
        from app.web.runtime_workspace_mutation import start_bulk_host_remove_job

        class _Runtime:
            def __init__(self):
                self.deleted = []
                self.invalidations = []
                self.jobs = SimpleNamespace(is_cancel_requested=lambda _job_id: False)

            def _emit_ui_invalidation(self, *channels, **_kw):
                self.invalidations.append(tuple(channels))

            def _start_job(self, job_type, runner, *, payload=None, **_kw):
                return {"id": 5, "type": job_type, "payload": payload, "result": runner(5)}

        runtime = _Runtime()
        import app.web.runtime_workspace_mutation as mutation

        original = mutation.delete_host_workspace
        mutation.delete_host_workspace = lambda rt, host_id: (
            runtime.deleted.append(host_id) or {"deleted": True}
        ) if host_id != 13 else (_ for _ in ()).throw(KeyError("Unknown host id: 13"))
        try:
            job = start_bulk_host_remove_job(runtime, [11, "12", 13, 11])
        finally:
            mutation.delete_host_workspace = original
        self.assertEqual("hosts-bulk-remove", job["type"])
        self.assertEqual([11, 12], runtime.deleted)
        self.assertEqual(2, job["result"]["succeeded"])
        self.assertEqual(1, job["result"]["failed"])
        self.assertEqual("error", job["result"]["results"][2]["status"])
        # one invalidation for the whole batch, after the deletes, so every browser reloads hosts/services/graph
        self.assertEqual([("overview", "hosts", "services", "graph")], runtime.invalidations)

    def test_bulk_action_validates_input(self):
        self.assertEqual(400, self.client.post("/api/workspace/hosts/bulk-action", json={"action": "explode", "host_ids": [1]}).status_code)
        self.assertEqual(400, self.client.post("/api/workspace/hosts/bulk-action", json={"action": "rescan", "host_ids": []}).status_code)
        self.assertEqual(400, self.client.post("/api/workspace/hosts/bulk-action", json={"action": "rescan", "host_ids": ["x", 0]}).status_code)
        self.assertEqual([], self.runtime.calls)

    def test_batch_tool_run_queues_one_job_per_target_and_reports_failures(self):
        response = self.client.post("/api/workspace/tools/run", json={
            "tool_id": "nikto",
            "parameters": {"depth": 2},
            "targets": [
                {"host_ip": "10.0.0.5", "port": "80"},
                {"host_ip": "10.0.0.5", "port": "80", "protocol": "tcp"},  # duplicate, skipped
                {"host_ip": "10.0.0.6", "port": "8080", "protocol": "TCP"},
                {"host_ip": "10.0.0.9", "port": "443"},  # runtime raises
                {"host_ip": "", "port": "443"},  # invalid target
            ],
        })
        self.assertEqual(202, response.status_code)
        body = response.json
        self.assertEqual(2, body["queued"])
        self.assertEqual(2, len(body["jobs"]))
        self.assertEqual(body["jobs"][0], body["job"])
        self.assertEqual(2, len(body["errors"]))
        tool_calls = [call for call in self.runtime.calls if call[0] == "start_tool_run_job"]
        self.assertEqual(3, len(tool_calls))
        self.assertEqual(("start_tool_run_job", "10.0.0.6", "8080", "tcp", "nikto", 300, {"depth": 2}), tool_calls[1])

    def test_batch_tool_run_with_no_valid_target_is_a_400(self):
        response = self.client.post("/api/workspace/tools/run", json={"tool_id": "nikto", "targets": [{"host_ip": "10.0.0.9", "port": "443"}]})
        self.assertEqual(400, response.status_code)

    def test_single_tool_run_still_requires_host_and_port(self):
        self.assertEqual(400, self.client.post("/api/workspace/tools/run", json={"tool_id": "nikto"}).status_code)
        response = self.client.post("/api/workspace/tools/run", json={"tool_id": "nikto", "host_ip": "10.0.0.5", "port": "80"})
        self.assertEqual(202, response.status_code)
        self.assertEqual(1, response.json["queued"])

    def test_scan_rerun_route_maps_errors(self):
        ok = self.client.post("/api/scans/history/7/rerun", json={})
        self.assertEqual(202, ok.status_code)
        self.assertEqual(5007, ok.json["job"]["id"])
        self.assertEqual(404, self.client.post("/api/scans/history/404/rerun").status_code)
        self.assertEqual(400, self.client.post("/api/scans/history/400/rerun").status_code)


class _RerunRuntime:
    """Runtime stub with a real project database so re-run reads the recorded row."""

    def __init__(self, project):
        self._lock = threading.RLock()
        self.logic = SimpleNamespace(activeProject=project)
        self.calls = []

    def _require_active_project(self):
        return self.logic.activeProject

    def start_nmap_scan_job(self, **kwargs):
        self.calls.append(("nmap", kwargs))
        return {"id": 1}

    def start_nmap_xml_import_job(self, path, run_actions=False):
        self.calls.append(("import", path, run_actions))
        return {"id": 2}

    def start_passive_capture_scan_job(self, *, interface_name, duration_minutes, run_actions=False):
        self.calls.append(("capture", interface_name, duration_minutes, run_actions))
        return {"id": 3}


class RerunScanSubmissionTest(unittest.TestCase):
    def setUp(self):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.scan_history import ensure_scan_submission_table
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory

        self.project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        ensure_scan_submission_table(self.project.database)
        self.runtime = _RerunRuntime(self.project)

    def tearDown(self):
        self.project_manager.closeProject(self.project)

    def _record(self, **overrides):
        from app.scheduler.scan_history import record_scan_submission

        record = {
            "job_id": "1",
            "submission_kind": "nmap_scan",
            "targets": ["10.0.0.0/24"],
            "scan_mode": "easy",
            "discovery": True,
            "staged": False,
            "run_actions": True,
            "nmap_path": "/usr/bin/nmap",
            "nmap_args": "-sV",
            "scan_options": {"top_ports": 100},
        }
        record.update(overrides)
        return record_scan_submission(self.project.database, record)

    def test_rerun_nmap_scan_replays_recorded_parameters(self):
        from app.web.runtime_scans import rerun_scan_submission

        created = self._record()
        job = rerun_scan_submission(self.runtime, created["id"])
        self.assertEqual({"id": 1}, job)
        kind, kwargs = self.runtime.calls[0]
        self.assertEqual("nmap", kind)
        self.assertEqual(["10.0.0.0/24"], kwargs["targets"])
        self.assertTrue(kwargs["discovery"])
        self.assertFalse(kwargs["staged"])
        self.assertTrue(kwargs["run_actions"])
        self.assertEqual("/usr/bin/nmap", kwargs["nmap_path"])
        self.assertEqual("-sV", kwargs["nmap_args"])
        self.assertEqual("easy", kwargs["scan_mode"])
        self.assertEqual({"top_ports": 100}, kwargs["scan_options"])

    def test_rerun_keeps_empty_nmap_path_for_the_planner_to_resolve(self):
        from app.web.runtime_scans import rerun_scan_submission

        created = self._record(nmap_path="")
        rerun_scan_submission(self.runtime, created["id"])
        self.assertEqual("", self.runtime.calls[0][1]["nmap_path"])

    def test_rerun_import_and_capture_kinds(self):
        from app.web.runtime_scans import rerun_scan_submission

        imported = self._record(submission_kind="import_nmap_xml", targets=[], source_path="/tmp/scan.xml", run_actions=False)
        captured = self._record(
            submission_kind="passive_capture_scan", targets=[], scan_mode="passive_capture",
            scan_options={"interface_name": "eth0", "duration_minutes": 15},
        )
        rerun_scan_submission(self.runtime, imported["id"])
        rerun_scan_submission(self.runtime, captured["id"])
        self.assertIn(("import", "/tmp/scan.xml", False), self.runtime.calls)
        self.assertIn(("capture", "eth0", 15, True), self.runtime.calls)

    def test_rerun_rejects_unknown_rows_and_kinds(self):
        from app.web.runtime_scans import rerun_scan_submission

        with self.assertRaises(KeyError):
            rerun_scan_submission(self.runtime, 999999)
        odd = self._record(submission_kind="something_else")
        with self.assertRaises(ValueError):
            rerun_scan_submission(self.runtime, odd["id"])
        empty = self._record(targets=[])
        with self.assertRaises(ValueError):
            rerun_scan_submission(self.runtime, empty["id"])
        self.assertEqual([], self.runtime.calls)


if __name__ == "__main__":
    unittest.main()
