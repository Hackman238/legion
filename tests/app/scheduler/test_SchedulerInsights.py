import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.insights import (
    delete_host_ai_state,
    ensure_scheduler_ai_state_table,
    get_host_ai_state,
    upsert_host_ai_state,
)
from app.shell.DefaultShell import DefaultShell
from app.tools.ToolCoordinator import ToolCoordinator
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory


class SchedulerInsightsStoreTest(unittest.TestCase):
    def test_upsert_get_delete_host_ai_state(self):
        shell = DefaultShell()
        db_log = getDbLogger()
        app_log = getAppLogger()
        repository_factory = RepositoryFactory(db_log)
        project_manager = ProjectManager(shell, repository_factory, app_log)
        nmap_exporter = DefaultNmapExporter(shell, app_log)
        _tool_coordinator = ToolCoordinator(shell, nmap_exporter)

        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_ai_state_table(project.database)
            upsert_host_ai_state(project.database, 11, {
                "host_ip": "10.0.0.5",
                "provider": "openai",
                "goal_profile": "internal_asset_discovery",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "hostname": "edge-gateway",
                "hostname_confidence": 90,
                "os_match": "Linux",
                "os_confidence": 82,
                "next_phase": "targeted_checks",
                "technologies": [{"name": "nginx", "version": "1.20", "cpe": "cpe:/a:nginx:nginx:1.20", "evidence": "server header"}],
                "findings": [{"title": "Open admin endpoint", "severity": "medium", "cvss": 5.1, "cve": "", "evidence": "/admin/login.jsp"}],
                "manual_tests": [{"why": "confirm auth", "command": "curl -k https://10.0.0.5/admin/login.jsp", "scope_note": "safe"}],
                "raw": {"actions": []},
            })

            loaded = get_host_ai_state(project.database, 11)
            self.assertIsNotNone(loaded)
            self.assertEqual("openai", loaded["provider"])
            self.assertEqual("edge-gateway", loaded["hostname"])
            self.assertEqual("Linux", loaded["os_match"])
            self.assertEqual("nginx", loaded["technologies"][0]["name"])
            self.assertEqual("Open admin endpoint", loaded["findings"][0]["title"])
            self.assertIn("curl -k", loaded["manual_tests"][0]["command"])

            deleted_count = delete_host_ai_state(project.database, 11)
            self.assertEqual(1, deleted_count)
            self.assertIsNone(get_host_ai_state(project.database, 11))
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
