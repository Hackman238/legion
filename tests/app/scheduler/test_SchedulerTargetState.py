import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.insights import get_host_ai_state, upsert_host_ai_state
from app.scheduler.state import (
    delete_target_state,
    ensure_scheduler_target_state_table,
    get_target_state,
    upsert_target_state,
)
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


class SchedulerTargetStateStoreTest(unittest.TestCase):
    def _create_project(self):
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        return project_manager, project

    def test_upsert_get_delete_target_state_round_trip(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            upsert_target_state(project.database, 11, {
                "host_ip": "10.0.0.5",
                "last_mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "engagement_preset": "internal_recon",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "hostname": "portal.local",
                "hostname_confidence": 96,
                "os_match": "Linux",
                "os_confidence": 80,
                "next_phase": "targeted_checks",
                "technologies": [{"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "banner"}],
                "findings": [{"title": "Admin panel exposed", "severity": "medium", "cvss": 5.0, "cve": "", "evidence": "/admin"}],
                "manual_tests": [{"why": "validate auth", "command": "curl -k https://10.0.0.5/admin", "scope_note": "safe"}],
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https", "service_product": "nginx"}],
                "urls": [
                    {"url": "https://10.0.0.5:443/", "port": "443", "protocol": "tcp", "service": "https"},
                    {"url": "https://10.0.0.5", "port": "", "protocol": "tcp", "service": "https"},
                    {"url": "http://10.0.0.5:8080/", "port": "8080", "protocol": "tcp", "service": "http"},
                ],
                "coverage_gaps": [{"gap_id": "missing_nikto", "description": "missing nikto", "recommended_tool_ids": ["nikto"]}],
                "attempted_actions": [{"tool_id": "nuclei-web", "status": "executed", "attempted_at": "2026-03-17T01:00:00Z", "port": "443", "protocol": "tcp", "service": "https"}],
                "credentials": [{"username": "svc-web", "realm": "local", "type": "password", "evidence": "manual note"}],
                "sessions": [{"session_type": "shell", "username": "svc-web", "host": "10.0.0.5", "port": "443", "protocol": "tcp"}],
                "screenshots": [{"artifact_ref": "/tmp/10.0.0.5-443-screenshot.png", "filename": "10.0.0.5-443-screenshot.png", "port": "443", "protocol": "tcp"}],
                "artifacts": [{"ref": "/tmp/scan.txt", "kind": "artifact", "tool_id": "nuclei-web", "port": "443", "protocol": "tcp"}],
                "raw": {"source": "test"},
            })

            loaded = get_target_state(project.database, 11)
            self.assertIsNotNone(loaded)
            self.assertEqual("internal_recon", loaded["engagement_preset"])
            self.assertEqual("portal.local", loaded["hostname"])
            self.assertEqual("nginx", loaded["technologies"][0]["name"])
            self.assertEqual("Admin panel exposed", loaded["findings"][0]["title"])
            loaded_urls = {str(item.get("url", "")): str(item.get("port", "")) for item in loaded["urls"]}
            self.assertEqual("443", loaded_urls["https://10.0.0.5"])
            self.assertEqual("8080", loaded_urls["http://10.0.0.5:8080"])
            self.assertEqual("missing_nikto", loaded["coverage_gaps"][0]["gap_id"])
            self.assertEqual("nuclei-web", loaded["attempted_actions"][0]["tool_id"])
            self.assertEqual("svc-web", loaded["credentials"][0]["username"])
            self.assertEqual("shell", loaded["sessions"][0]["session_type"])
            self.assertEqual("/tmp/scan.txt", loaded["artifacts"][0]["ref"])

            deleted = delete_target_state(project.database, 11)
            self.assertEqual(1, deleted)
            self.assertIsNone(get_target_state(project.database, 11))
        finally:
            project_manager.closeProject(project)

    def test_legacy_ai_state_migrates_into_target_state_and_legacy_reads_from_target_state(self):
        project_manager, project = self._create_project()
        try:
            upsert_host_ai_state(project.database, 22, {
                "host_ip": "10.0.0.22",
                "provider": "openai",
                "goal_profile": "internal_asset_discovery",
                "last_port": "445",
                "last_protocol": "tcp",
                "last_service": "smb",
                "hostname": "dc01.local",
                "hostname_confidence": 93,
                "os_match": "Windows",
                "os_confidence": 88,
                "next_phase": "safe_followup",
                "technologies": [{"name": "samba", "version": "4.x", "cpe": "cpe:/a:samba:samba:4", "evidence": "service"}],
                "findings": [{"title": "SMB signing not required", "severity": "high", "cvss": 7.5, "cve": "", "evidence": "smb-security-mode"}],
                "manual_tests": [{"why": "validate relay", "command": "ntlmrelayx.py -tf targets.txt", "scope_note": "approval"}],
                "raw": {"actions": [{"tool_id": "smb-enum-users.nse"}]},
            })

            target_state = get_target_state(project.database, 22)
            self.assertIsNotNone(target_state)
            self.assertEqual("ai", target_state["last_mode"])
            self.assertEqual("openai", target_state["provider"])
            self.assertEqual("samba", target_state["technologies"][0]["name"])
            self.assertEqual("SMB signing not required", target_state["findings"][0]["title"])

            legacy_view = get_host_ai_state(project.database, 22)
            self.assertIsNotNone(legacy_view)
            self.assertEqual("dc01.local", legacy_view["hostname"])
            self.assertEqual("safe_followup", legacy_view["next_phase"])
            self.assertEqual("samba", legacy_view["technologies"][0]["name"])
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
