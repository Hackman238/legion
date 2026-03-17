import os
import tempfile
import unittest
from types import SimpleNamespace

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    queue_pending_approval,
    update_pending_approval,
)
from app.scheduler.config import SchedulerConfigManager
from app.scheduler.insights import (
    ensure_scheduler_ai_state_table,
    get_host_ai_state,
    upsert_host_ai_state,
)
from app.scheduler.planner import SchedulerPlanner
from app.shell.DefaultShell import DefaultShell
from app.web import create_app
from db.RepositoryFactory import RepositoryFactory
from db.entities.host import hostObj


class _CompatibilityRuntime:
    def __init__(self):
        self.state = {
            "mode": "deterministic",
            "goal_profile": "internal_asset_discovery",
            "provider": "none",
            "providers": {},
            "dangerous_categories": ["credential_bruteforce"],
            "project_report_delivery": {},
        }
        self.last_updates = None

    def get_scheduler_preferences(self):
        return dict(self.state)

    def apply_scheduler_preferences(self, updates):
        self.last_updates = dict(updates or {})
        self.state.update(self.last_updates)
        return self.get_scheduler_preferences()


class SchedulerCompatibilityBaselineTest(unittest.TestCase):
    def _create_project_manager(self):
        shell = DefaultShell()
        repository_factory = RepositoryFactory(getDbLogger())
        return ProjectManager(shell, repository_factory, getAppLogger())

    def test_deterministic_scheduler_golden_mapping_for_sample_services(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "dangerous_categories": ["credential_bruteforce"],
            })
            planner = SchedulerPlanner(manager)
            settings = SimpleNamespace(
                automatedAttacks=[
                    ["smb-enum-users.nse", "smb", "tcp"],
                    ["smb-default", "smb", "tcp"],
                    ["nuclei-web", "http", "tcp"],
                ],
                portActions=[
                    ["SMB Users", "smb-enum-users.nse", "nmap --script=smb-enum-users [IP] -p [PORT]", "smb"],
                    ["SMB Default", "smb-default", "hydra -s [PORT] -u root -P pass.txt [IP] smb", "smb"],
                    ["Run nuclei web scan", "nuclei-web", "nuclei -u http://[IP]:[PORT] -silent", "http"],
                ],
            )

            smb_actions = planner.plan_actions("smb", "tcp", settings)
            http_actions = planner.plan_actions("http", "tcp", settings)

            golden = [
                {
                    "tool_id": action.tool_id,
                    "label": action.label,
                    "protocol": action.protocol,
                    "goal_profile": action.goal_profile,
                    "danger_categories": list(action.danger_categories),
                    "requires_approval": bool(action.requires_approval),
                }
                for action in smb_actions + http_actions
            ]

            self.assertEqual([
                {
                    "tool_id": "smb-enum-users.nse",
                    "label": "SMB Users",
                    "protocol": "tcp",
                    "goal_profile": "internal_asset_discovery",
                    "danger_categories": [],
                    "requires_approval": False,
                },
                {
                    "tool_id": "smb-default",
                    "label": "SMB Default",
                    "protocol": "tcp",
                    "goal_profile": "internal_asset_discovery",
                    "danger_categories": ["credential_bruteforce"],
                    "requires_approval": True,
                },
                {
                    "tool_id": "nuclei-web",
                    "label": "Run nuclei web scan",
                    "protocol": "tcp",
                    "goal_profile": "internal_asset_discovery",
                    "danger_categories": [],
                    "requires_approval": False,
                },
            ], golden)

    def test_approval_queue_round_trip_preserves_scheduler_fields(self):
        project_manager = self._create_project_manager()
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_approval_table(project.database)
            approval_id = queue_pending_approval(project.database, {
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "service": "smb",
                "tool_id": "smb-default",
                "label": "SMB Default",
                "command_template": "hydra [IP]",
                "command_family_id": "compat-fam-1",
                "danger_categories": "credential_bruteforce",
                "scheduler_mode": "ai",
                "goal_profile": "internal_asset_discovery",
                "rationale": "baseline compatibility",
            })
            stored = get_pending_approval(project.database, approval_id)
            self.assertEqual("smb-default", stored["tool_id"])
            self.assertEqual("credential_bruteforce", stored["danger_categories"])

            updated = update_pending_approval(
                project.database,
                approval_id,
                status="approved",
                decision_reason="compat-approved",
                execution_job_id="44",
            )
            self.assertEqual("approved", updated["status"])
            self.assertEqual("44", updated["execution_job_id"])
        finally:
            project_manager.closeProject(project)

    def test_host_ai_state_round_trip_preserves_structured_payload(self):
        project_manager = self._create_project_manager()
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_ai_state_table(project.database)
            upsert_host_ai_state(project.database, 22, {
                "host_ip": "10.0.0.22",
                "provider": "openai",
                "goal_profile": "internal_asset_discovery",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "hostname": "portal.internal",
                "hostname_confidence": 95,
                "os_match": "Linux",
                "os_confidence": 88,
                "next_phase": "targeted_checks",
                "technologies": [{"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "server header"}],
                "findings": [{"title": "Login panel exposed", "severity": "medium", "cvss": 5.0, "cve": "", "evidence": "/login"}],
                "manual_tests": [{"why": "validate auth controls", "command": "curl -k https://10.0.0.22/login", "scope_note": "safe"}],
                "raw": {"actions": [{"tool_id": "nuclei-web"}]},
            })

            loaded = get_host_ai_state(project.database, 22)
            self.assertEqual("portal.internal", loaded["hostname"])
            self.assertEqual("nginx", loaded["technologies"][0]["name"])
            self.assertEqual("Login panel exposed", loaded["findings"][0]["title"])
            self.assertEqual("nuclei-web", loaded["raw"]["actions"][0]["tool_id"])
        finally:
            project_manager.closeProject(project)

    def test_project_save_and_reopen_round_trip_preserves_host_records(self):
        project_manager = self._create_project_manager()
        with tempfile.TemporaryDirectory() as tmpdir:
            project = project_manager.createNewProject(projectType="legion", isTemp=True)
            try:
                session = project.database.session()
                session.add(hostObj(ip="10.20.30.40", ipv4="10.20.30.40", hostname="compat-host"))
                session.commit()
                session.close()

                destination = os.path.join(tmpdir, "compat-project")
                saved_project = project_manager.saveProjectAs(project, destination, replace=1, projectType="legion")
                hosts = saved_project.repositoryContainer.hostRepository.getAllHostObjs()

                self.assertTrue(os.path.isfile(f"{destination}.legion"))
                self.assertEqual(1, len(hosts))
                self.assertEqual("10.20.30.40", hosts[0].ip)
            finally:
                if "saved_project" in locals():
                    project_manager.setStoreWordListsOnExit(saved_project, False)
                    project_manager.closeProject(saved_project)

    def test_web_scheduler_preferences_api_round_trip_preserves_contract(self):
        runtime = _CompatibilityRuntime()
        app = create_app(runtime)
        client = app.test_client()

        current = client.get("/api/scheduler/preferences")
        self.assertEqual(200, current.status_code)
        self.assertEqual("deterministic", current.json["mode"])

        updated = client.post("/api/scheduler/preferences", json={
            "mode": "ai",
            "goal_profile": "external_pentest",
            "ignored_field": "should-not-pass-through",
        })
        self.assertEqual(200, updated.status_code)
        self.assertEqual("ai", updated.json["mode"])
        self.assertEqual("external_pentest", updated.json["goal_profile"])
        self.assertEqual({
            "mode": "ai",
            "goal_profile": "external_pentest",
        }, runtime.last_updates)


if __name__ == "__main__":
    unittest.main()
