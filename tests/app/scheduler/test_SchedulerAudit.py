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
                "engagement_preset": "internal_pentest",
                "tool_id": "smb-default",
                "label": "SMB Bruteforce",
                "command_family_id": "fam1",
                "danger_categories": "credential_bruteforce",
                "risk_tags": "credential_bruteforce,account_lockout_risk",
                "requires_approval": "True",
                "policy_decision": "approval_required",
                "policy_reason": "requires approval under internal pentest",
                "risk_summary": "Could lock or throttle real user accounts.",
                "safer_alternative": "Prefer credential validation against known accounts or low-impact enumeration first.",
                "family_policy_state": "",
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
            self.assertEqual("approval_required", queued["policy_decision"])
            self.assertEqual("internal_pentest", queued["engagement_preset"])

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
                "engagement_preset": "internal_recon",
                "tool_id": "ssh-default-router",
                "label": "SSH default router",
                "command_family_id": "fam2",
                "danger_categories": "credential_bruteforce",
                "risk_tags": "credential_bruteforce,account_lockout_risk",
                "requires_approval": "True",
                "policy_decision": "blocked",
                "policy_reason": "blocked under internal recon",
                "risk_summary": "Could lock or throttle real user accounts.",
                "safer_alternative": "Prefer credential validation against known accounts or low-impact enumeration first.",
                "family_policy_state": "",
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



class SchedulerAuditReasonFallbackTest(unittest.TestCase):
    def test_reason_fallback_matches_exact_approval_number(self):
        project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_audit_table(project.database)
            # Legacy rows: no approval_id column value, only the reason text links them.
            base = {key: "" for key in (
                "timestamp", "host_ip", "port", "protocol", "service", "scheduler_mode", "goal_profile",
                "label", "command_family_id", "danger_categories", "requires_approval",
                "approved", "executed", "rationale",
            )}
            for reason in ("pending approval #1 for smb-default", "pending approval #12", "pending approval #1"):
                log_scheduler_decision(project.database, dict(base, tool_id="t", reason=reason, approval_id=""))

            updated_12 = update_scheduler_decision_for_approval(project.database, 12, approved=True)
            self.assertEqual("pending approval #12", updated_12["reason"])

            updated_1 = update_scheduler_decision_for_approval(project.database, 1, approved=True)
            self.assertEqual("pending approval #1", updated_1["reason"])  # newest exact match, not #12

            self.assertIsNone(update_scheduler_decision_for_approval(project.database, 2, approved=True))
        finally:
            project_manager.closeProject(project)


class SchedulerAuditFailureLoggingTest(unittest.TestCase):
    class _BrokenSession:
        def get_bind(self):
            return None

        def execute(self, *_args, **_kwargs):
            raise RuntimeError("database is locked")

        def commit(self):
            pass

        def rollback(self):
            self.rolled_back = True

        def close(self):
            pass

    def _broken_database(self):
        session = self._BrokenSession()
        return type("BrokenDb", (), {"session": staticmethod(lambda: session)})(), session

    def test_failed_decision_log_is_logged_not_raised(self):
        database, session = self._broken_database()
        with self.assertLogs("app.scheduler.audit", level="WARNING") as captured:
            self.assertIsNone(log_scheduler_decision(database, {"tool_id": "nikto", "host_ip": "10.0.0.5"}))
        self.assertTrue(getattr(session, "rolled_back", False))
        self.assertIn("nikto", captured.output[0])
        self.assertIsNotNone(captured.records[0].exc_info)

    def test_failed_approval_update_is_logged_not_raised(self):
        database, _session = self._broken_database()
        with self.assertLogs("app.scheduler.audit", level="WARNING") as captured:
            self.assertIsNone(update_scheduler_decision_for_approval(database, 7, approved=True))
        self.assertIn("approval 7", captured.output[0])
        self.assertIsNotNone(captured.records[0].exc_info)

if __name__ == "__main__":
    unittest.main()
