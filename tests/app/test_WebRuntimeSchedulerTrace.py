import threading
import unittest
from types import SimpleNamespace

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.execution import ensure_scheduler_execution_table, store_execution_record
from app.scheduler.models import ExecutionRecord, PlanStep
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


def _store(project, index, host_ip, tool_id, stdout_ref=""):
    step = PlanStep.from_legacy_fields(
        tool_id=tool_id,
        label=tool_id,
        command_template="echo [IP]",
        protocol="tcp",
        score=1.0,
        rationale="test",
        mode="deterministic",
        goal_profile="internal_asset_discovery",
        family_id=tool_id,
        target_ref={"host_ip": host_ip, "port": "80", "service": "http", "protocol": "tcp"},
    )
    record = ExecutionRecord.from_plan_step(
        step,
        started_at=f"2026-03-16T10:00:{index % 60:02d}Z",
        finished_at=f"2026-03-16T10:00:{index % 60:02d}Z",
        exit_status="completed",
        stdout_ref=stdout_ref,
    )
    store_execution_record(project.database, record, step=step, host_ip=host_ip, port="80", protocol="tcp")


class WebRuntimeSchedulerTraceTest(unittest.TestCase):
    def setUp(self):
        repository_factory = RepositoryFactory(getDbLogger())
        self.project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        ensure_scheduler_execution_table(self.project.database)
        self.output_requests = []

        def _get_process_output(process_id, offset=0, max_chars=12000):
            self.output_requests.append(int(process_id))
            return {"output": f"head-{process_id}-" + "x" * 50 + "-tail"}

        self.runtime = SimpleNamespace(
            _lock=threading.RLock(),
            _require_active_project=lambda: self.project,
            get_process_output=_get_process_output,
            _read_text_excerpt=lambda path, max_chars=4000: "",
        )

    def tearDown(self):
        self.project_manager.closeProject(self.project)

    def test_filters_are_applied_before_limit_and_process_output_refs_resolve(self):
        from app.web.runtime_scheduler_trace import get_scheduler_execution_traces

        _store(self.project, 0, "10.0.0.1", "whatweb", stdout_ref="process_output:5")
        for index in range(1, 80):
            _store(self.project, index, "10.0.0.2", "nikto")

        traces = get_scheduler_execution_traces(
            self.runtime,
            limit=1,
            host_ip="10.0.0.1",
            include_output=True,
            output_max_chars=10,
        )
        self.assertEqual(1, len(traces))
        self.assertEqual("10.0.0.1", traces[0]["host_ip"])
        self.assertEqual("x" * 5 + "-tail", traces[0]["stdout_excerpt"])
        self.assertEqual("", traces[0]["stderr_excerpt"])
        self.assertEqual([5], self.output_requests)

        by_tool = get_scheduler_execution_traces(self.runtime, limit=5, tool_id="WhatWeb")
        self.assertEqual(["whatweb"], [item["tool_id"] for item in by_tool])

        unfiltered = get_scheduler_execution_traces(self.runtime, limit=3)
        self.assertEqual(3, len(unfiltered))


if __name__ == "__main__":
    unittest.main()
