import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.host import hostObj
from db.entities.port import portObj
from db.entities.service import serviceObj


class WebRuntimeWorkspaceBatchingTest(unittest.TestCase):
    def setUp(self):
        repository_factory = RepositoryFactory(getDbLogger())
        self.project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        session = self.project.database.session()
        try:
            self.host_ids = []
            for index in range(3):
                host = hostObj(ip=f"10.0.0.{index + 1}", hostname=f"host{index + 1}", status="up")
                session.add(host)
                session.flush()
                self.host_ids.append(int(host.id))
                for port_number, service_name in (("80", "http"), ("22", "ssh")):
                    service = serviceObj(service_name, str(host.id), product=f"{service_name}-prod")
                    session.add(service)
                    session.flush()
                    session.add(portObj(port_number, "tcp", "open", str(host.id), str(service.id)))
            session.commit()
        finally:
            session.close()
        self.runtime = SimpleNamespace(
            _lock=threading.RLock(),
            logic=SimpleNamespace(activeProject=self.project),
            _require_active_project=lambda: self.project,
        )

    def tearDown(self):
        self.project_manager.closeProject(self.project)

    def test_hosts_batches_port_and_service_lookups(self):
        from app.web import runtime_workspace_read

        repo_container = self.project.repositoryContainer
        with patch.object(repo_container.portRepository, "getPortsByHostId", side_effect=AssertionError("N+1")), \
                patch.object(repo_container.serviceRepository, "getServiceById", side_effect=AssertionError("N+1")):
            rows = runtime_workspace_read.hosts(
                self.runtime,
                build_workspace_host_row_func=lambda _runtime, host, *_args, **kwargs: {
                    "id": int(host.id),
                    "ports": len(kwargs["preloaded_ports"]),
                    "inventory": kwargs["preloaded_service_inventory"],
                    "services": kwargs["preloaded_services"],
                },
            )

        self.assertEqual(sorted(self.host_ids), sorted(row["id"] for row in rows))
        for row in rows:
            self.assertEqual(2, row["ports"])
            self.assertEqual(["http", "ssh"], row["services"])
            self.assertEqual(
                {"http-prod", "ssh-prod"},
                {item["service_product"] for item in row["inventory"]},
            )

    def test_resolve_host_queries_by_id(self):
        from app.web import runtime_workspace_read

        host_repo = self.project.repositoryContainer.hostRepository
        with patch.object(host_repo, "getAllHostObjs", side_effect=AssertionError("full scan")):
            host = runtime_workspace_read.resolve_host(self.runtime, self.host_ids[1])
            missing = runtime_workspace_read.resolve_host(self.runtime, 99999)

        self.assertEqual("10.0.0.2", host.ip)
        self.assertIsNone(missing)


class WebRuntimeProcessOutputPartialTest(unittest.TestCase):
    def setUp(self):
        repository_factory = RepositoryFactory(getDbLogger())
        self.project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)

    def tearDown(self):
        self.project_manager.closeProject(self.project)

    def test_partial_writes_upsert_and_ensure_tables_once(self):
        from sqlalchemy import text

        from app.web import runtime_execution, runtime_process_control

        runtime = SimpleNamespace(_lock=threading.RLock(), logic=SimpleNamespace(activeProject=self.project))
        ensure_calls = []

        def _ensure():
            ensure_calls.append(1)
            runtime_process_control.ensure_process_tables(runtime)

        runtime._ensure_process_tables = _ensure
        with patch.object(self.project.database, "session", wraps=self.project.database.session) as session_spy:
            runtime_execution.write_process_output_partial(runtime, 11, "first")
            first_sessions = session_spy.call_count
            runtime_execution.write_process_output_partial(runtime, 11, "first second")
            second_sessions = session_spy.call_count - first_sessions

        # The second write reuses the cached table check: only the write session is opened.
        self.assertEqual(1, second_sessions)
        self.assertGreater(first_sessions, second_sessions)
        session = self.project.database.session()
        try:
            rows = session.execute(text(
                "SELECT output FROM process_output WHERE processId = 11"
            )).fetchall()
        finally:
            session.close()
        self.assertEqual([("first second",)], [tuple(row) for row in rows])

    def test_partial_flush_interval_backs_off_with_output_size(self):
        from app.web.runtime_execution import _partial_output_flush_interval

        self.assertEqual(0.5, _partial_output_flush_interval(0))
        self.assertEqual(1.0, _partial_output_flush_interval(65536))
        self.assertEqual(5.0, _partial_output_flush_interval(50 * 1024 * 1024))


class FindingsBulkPreloadTest(unittest.TestCase):
    def test_production_findings_path_uses_bulk_target_state_loader(self):
        from app.web import runtime_workspace, runtime_workspace_findings

        project = SimpleNamespace(database=object())
        runtime = SimpleNamespace(
            _lock=threading.RLock(),
            _require_active_project=lambda: project,
            _hosts=lambda limit=500: [{"id": 1, "ip": "10.0.0.1"}, {"id": 2, "ip": "10.0.0.2"}],
        )
        states = {1: {"findings": [{"title": "a", "severity": "high"}]}, 2: {"findings": []}}

        with patch.object(runtime_workspace_findings, "load_target_state_cache", return_value=states) as bulk, \
                patch.object(runtime_workspace_findings, "load_target_state") as per_host:
            # WebRuntime goes through runtime_workspace, which passes the scheduler's get_target_state.
            per_host.side_effect = AssertionError("per-host lookup used")
            with patch.object(runtime_workspace, "get_target_state", runtime_workspace_findings.load_target_state):
                result = runtime_workspace.get_findings(runtime)

        bulk.assert_called_once()
        self.assertEqual(1, result["count"])


if __name__ == "__main__":
    unittest.main()
