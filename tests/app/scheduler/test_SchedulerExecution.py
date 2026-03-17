import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.execution import (
    ensure_scheduler_execution_table,
    get_execution_record,
    list_execution_records,
    store_execution_record,
)
from app.scheduler.models import ExecutionRecord, PlanStep
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


class SchedulerExecutionStoreTest(unittest.TestCase):
    def test_store_and_fetch_execution_record_preserves_plan_step_metadata(self):
        shell = DefaultShell()
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(shell, repository_factory, getAppLogger())

        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_execution_table(project.database)

            step = PlanStep.from_legacy_fields(
                tool_id="smb-enum-users.nse",
                label="SMB Enum Users",
                command_template="nmap --script=smb-enum-users [IP] -p [PORT]",
                protocol="tcp",
                score=100.0,
                rationale="Enumerate SMB users on an exposed service.",
                mode="deterministic",
                goal_profile="internal_asset_discovery",
                family_id="smb-enum-users",
                target_ref={
                    "host_ip": "10.0.0.5",
                    "port": "445",
                    "service": "smb",
                    "protocol": "tcp",
                },
            )
            record = ExecutionRecord.from_plan_step(
                step,
                started_at="2026-03-16T10:00:00Z",
                finished_at="2026-03-16T10:00:05Z",
                exit_status="completed",
                stdout_ref="process_output:42",
                artifact_refs=["/tmp/demo-output.nmap", "/tmp/demo-output.xml"],
                approval_id="",
            )

            stored = store_execution_record(
                project.database,
                record,
                step=step,
                host_ip="10.0.0.5",
                port="445",
                protocol="tcp",
                service="smb",
            )
            listing = list_execution_records(project.database, limit=10)
            fetched = get_execution_record(project.database, record.execution_id)

            self.assertEqual(record.execution_id, stored["execution_id"])
            self.assertEqual(1, len(listing))
            self.assertIsNotNone(fetched)
            self.assertEqual(step.step_id, fetched["step_id"])
            self.assertEqual("smb-enum-users.nse", fetched["tool_id"])
            self.assertEqual("deterministic", fetched["scheduler_mode"])
            self.assertEqual("internal_asset_discovery", fetched["goal_profile"])
            self.assertEqual("10.0.0.5", fetched["host_ip"])
            self.assertEqual("445", fetched["port"])
            self.assertEqual("completed", fetched["exit_status"])
            self.assertEqual("process_output:42", fetched["stdout_ref"])
            self.assertEqual(
                ["/tmp/demo-output.nmap", "/tmp/demo-output.xml"],
                fetched["artifact_refs"],
            )
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
