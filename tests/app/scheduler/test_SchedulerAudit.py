import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.audit import (
    ensure_scheduler_audit_table,
    log_scheduler_decision,
    update_scheduler_decision_for_approval,
)
from app.shell.DefaultShell import DefaultShell
from app.tools.ToolCoordinator import ToolCoordinator
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory


class SchedulerAuditStoreTest(unittest.TestCase):
    def test_update_decision_lifecycle_by_approval_id(self):
        shell = DefaultShell()
        db_log = getDbLogger()
        app_log = getAppLogger()
        repository_factory = RepositoryFactory(db_log)
        project_manager = ProjectManager(shell, repository_factory, app_log)
        nmap_exporter = DefaultNmapExporter(shell, app_log)
        _tool_coordinator = ToolCoordinator(shell, nmap_exporter)

        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_audit_table(project.database)
            log_scheduler_decision(project.database, {
                "timestamp": "2026-02-17T00:00:00Z",
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "service": "smb",
                "scheduler_mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "tool_id": "smb-default",
                "label": "SMB Bruteforce",
                "command_family_id": "fam1",
                "danger_categories": "credential_bruteforce",
                "requires_approval": "True",
                "approved": "False",
                "executed": "False",
                "reason": "pending approval #77",
                "rationale": "test",
                "approval_id": "77",
            })

            queued = update_scheduler_decision_for_approval(
                project.database,
                77,
                approved=True,
                executed=False,
                reason="approved & queued",
            )
            self.assertIsNotNone(queued)
            self.assertEqual("True", queued["approved"])
            self.assertEqual("False", queued["executed"])
            self.assertEqual("approved & queued", queued["reason"])

            running = update_scheduler_decision_for_approval(
                project.database,
                77,
                approved=True,
                executed=False,
                reason="approved & running",
            )
            self.assertIsNotNone(running)
            self.assertEqual("approved & running", running["reason"])

            completed = update_scheduler_decision_for_approval(
                project.database,
                77,
                approved=True,
                executed=True,
                reason="approved & completed",
            )
            self.assertIsNotNone(completed)
            self.assertEqual("True", completed["executed"])
            self.assertEqual("approved & completed", completed["reason"])
        finally:
            project_manager.closeProject(project)

    def test_update_decision_lifecycle_legacy_reason_fallback(self):
        shell = DefaultShell()
        db_log = getDbLogger()
        app_log = getAppLogger()
        repository_factory = RepositoryFactory(db_log)
        project_manager = ProjectManager(shell, repository_factory, app_log)
        nmap_exporter = DefaultNmapExporter(shell, app_log)
        _tool_coordinator = ToolCoordinator(shell, nmap_exporter)

        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_audit_table(project.database)
            log_scheduler_decision(project.database, {
                "timestamp": "2026-02-17T00:00:00Z",
                "host_ip": "10.0.0.9",
                "port": "22",
                "protocol": "tcp",
                "service": "ssh",
                "scheduler_mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "tool_id": "ssh-default-router",
                "label": "SSH default router",
                "command_family_id": "fam2",
                "danger_categories": "credential_bruteforce",
                "requires_approval": "True",
                "approved": "False",
                "executed": "False",
                "reason": "pending approval #12",
                "rationale": "legacy row without approval_id",
                "approval_id": "",
            })

            queued = update_scheduler_decision_for_approval(
                project.database,
                12,
                approved=True,
                executed=False,
                reason="approved & queued",
            )
            self.assertIsNotNone(queued)
            self.assertEqual("approved & queued", queued["reason"])
            self.assertEqual("True", queued["approved"])
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
