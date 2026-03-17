import os
import tempfile
import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.policy import (
    ensure_scheduler_engagement_policy_table,
    get_project_engagement_policy,
    normalize_engagement_policy,
    upsert_project_engagement_policy,
)
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


class SchedulerPolicyTest(unittest.TestCase):
    def test_normalize_policy_maps_legacy_goal_profile_to_internal_recon(self):
        policy = normalize_engagement_policy({}, fallback_goal_profile="internal_asset_discovery")
        self.assertEqual("internal_recon", policy.preset)
        self.assertEqual("internal_asset_discovery", policy.legacy_goal_profile)
        self.assertFalse(policy.allow_exploitation)

    def test_project_policy_round_trip_preserves_normalized_fields(self):
        shell = DefaultShell()
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(shell, repository_factory, getAppLogger())

        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            ensure_scheduler_engagement_policy_table(project.database)
            stored = upsert_project_engagement_policy(
                project.database,
                {
                    "preset": "external_recon",
                    "scope": "external",
                    "intent": "recon",
                    "allow_exploitation": False,
                    "allow_lateral_movement": False,
                    "credential_attack_mode": "blocked",
                    "lockout_risk_mode": "blocked",
                    "stability_risk_mode": "approval",
                    "detection_risk_mode": "low",
                    "approval_mode": "risky",
                    "runner_preference": "local",
                    "noise_budget": "low",
                },
                updated_at="2026-03-17T00:00:00Z",
            )
            loaded = get_project_engagement_policy(project.database)

            self.assertEqual("external_recon", stored["preset"])
            self.assertIsNotNone(loaded)
            self.assertEqual("external_recon", loaded["preset"])
            self.assertEqual("external", loaded["scope"])
            self.assertEqual("recon", loaded["intent"])
            self.assertEqual("external_pentest", loaded["derived_from_goal_profile"])
        finally:
            project_manager.closeProject(project)

    def test_project_policy_persists_across_save_and_reopen(self):
        shell = DefaultShell()
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(shell, repository_factory, getAppLogger())

        with tempfile.TemporaryDirectory() as tmpdir:
            project = project_manager.createNewProject(projectType="legion", isTemp=True)
            try:
                ensure_scheduler_engagement_policy_table(project.database)
                upsert_project_engagement_policy(
                    project.database,
                    {
                        "preset": "internal_pentest",
                        "scope": "internal",
                        "intent": "pentest",
                        "allow_exploitation": True,
                        "allow_lateral_movement": True,
                        "credential_attack_mode": "approval",
                        "lockout_risk_mode": "approval",
                        "stability_risk_mode": "approval",
                        "detection_risk_mode": "medium",
                        "approval_mode": "risky",
                        "runner_preference": "local",
                        "noise_budget": "medium",
                    },
                    updated_at="2026-03-17T00:00:00Z",
                )

                destination = os.path.join(tmpdir, "policy-project")
                saved_project = project_manager.saveProjectAs(project, destination, replace=1, projectType="legion")
                loaded = get_project_engagement_policy(saved_project.database)

                self.assertIsNotNone(loaded)
                self.assertEqual("internal_pentest", loaded["preset"])
                self.assertEqual("pentest", loaded["intent"])
            finally:
                if "saved_project" in locals():
                    project_manager.closeProject(saved_project)


if __name__ == "__main__":
    unittest.main()
