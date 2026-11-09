import unittest
from unittest.mock import patch

from sqlalchemy import text

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.schema_cache import clear_schema_cache
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


class LegacySchedulerTableMigrationTest(unittest.TestCase):
    def setUp(self):
        clear_schema_cache()
        self.pm = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        self.project = self.pm.createNewProject(projectType="legion", isTemp=True)
        self.addCleanup(self.pm.closeProject, self.project)
        self.addCleanup(clear_schema_cache)

    def _columns(self, table):
        session = self.project.database.session()
        try:
            return {row[1] for row in session.execute(text(f"PRAGMA table_info({table})")).fetchall()}
        finally:
            session.close()

    def _indexes(self, table):
        session = self.project.database.session()
        try:
            return {row[1] for row in session.execute(text(f"PRAGMA index_list({table})")).fetchall()}
        finally:
            session.close()

    def test_decision_log_created_before_approval_id_existed_gains_column_and_index(self):
        from app.scheduler.audit import ensure_scheduler_audit_table
        session = self.project.database.session()
        try:
            session.execute(text(
                "CREATE TABLE scheduler_decision_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, "
                "host_ip TEXT, port TEXT, protocol TEXT, service TEXT, scheduler_mode TEXT, goal_profile TEXT, "
                "tool_id TEXT, label TEXT, command_family_id TEXT, danger_categories TEXT, requires_approval TEXT, "
                "approved TEXT, executed TEXT, reason TEXT, rationale TEXT)"
            ))
            session.commit()
        finally:
            session.close()

        ensure_scheduler_audit_table(self.project.database)

        self.assertIn("approval_id", self._columns("scheduler_decision_log"))
        self.assertIn("ix_scheduler_decision_log_approval_id", self._indexes("scheduler_decision_log"))

    def test_fresh_tables_get_their_indexes(self):
        from app.scheduler.approvals import ensure_scheduler_approval_table
        from app.scheduler.execution import ensure_scheduler_execution_table
        ensure_scheduler_approval_table(self.project.database)
        ensure_scheduler_execution_table(self.project.database)
        self.assertIn("ix_scheduler_pending_approval_host_ip", self._indexes("scheduler_pending_approval"))
        self.assertIn("ix_scheduler_execution_record_approval_id", self._indexes("scheduler_execution_record"))


class TargetStateGraphSyncCacheTest(unittest.TestCase):
    def setUp(self):
        self.pm = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        self.project = self.pm.createNewProject(projectType="legion", isTemp=True)
        self.addCleanup(self.pm.closeProject, self.project)

    def test_unchanged_state_is_synced_to_the_graph_once(self):
        from app.scheduler import state as state_module
        state = {"service_inventory": [{"port": "80", "protocol": "tcp", "state": "open", "service": "http"}]}
        with patch("app.scheduler.graph.sync_target_state_to_evidence_graph", return_value=[]) as sync:
            state_module.upsert_target_state(self.project.database, 1, dict(state))
            state_module.upsert_target_state(self.project.database, 1, dict(state))  # new updated_at, same content
            self.assertEqual(1, sync.call_count)
            state_module.upsert_target_state(
                self.project.database, 1,
                {"service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}]},
            )
            self.assertEqual(2, sync.call_count)
            state_module.invalidate_target_state_graph_cache(self.project.database, host_id=1)
            state_module.upsert_target_state(self.project.database, 1, {})
            self.assertEqual(3, sync.call_count)


if __name__ == "__main__":
    unittest.main()
