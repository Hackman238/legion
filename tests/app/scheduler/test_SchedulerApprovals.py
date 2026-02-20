import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    list_pending_approvals,
    queue_pending_approval,
    update_pending_approval,
)
from app.shell.DefaultShell import DefaultShell
from app.tools.ToolCoordinator import ToolCoordinator
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory


class SchedulerApprovalsStoreTest(unittest.TestCase):
    def test_queue_and_update_approval_records(self):
        shell = DefaultShell()
        db_log = getDbLogger()
        app_log = getAppLogger()
        repository_factory = RepositoryFactory(db_log)
        project_manager = ProjectManager(shell, repository_factory, app_log)
        nmap_exporter = DefaultNmapExporter(shell, app_log)
        _tool_coordinator = ToolCoordinator(shell, nmap_exporter)

        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_approval_table(project.database)
            approval_id = queue_pending_approval(project.database, {
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "service": "smb",
                "tool_id": "smb-default",
                "label": "SMB Bruteforce",
                "command_template": "hydra [IP]",
                "command_family_id": "fam1",
                "danger_categories": "credential_bruteforce",
                "scheduler_mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "rationale": "high value",
            })
            self.assertGreater(approval_id, 0)

            listing = list_pending_approvals(project.database, limit=20, status="pending")
            self.assertEqual(1, len(listing))
            self.assertEqual("smb-default", listing[0]["tool_id"])

            updated = update_pending_approval(
                project.database,
                approval_id,
                status="approved",
                decision_reason="approved in test",
                execution_job_id="12",
            )
            self.assertIsNotNone(updated)
            self.assertEqual("approved", updated["status"])

            fetched = get_pending_approval(project.database, approval_id)
            self.assertIsNotNone(fetched)
            self.assertEqual("12", fetched["execution_job_id"])
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
