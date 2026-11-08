import json
import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from app.web import create_app
from app.web.runtime import WebRuntime
from app.logic import Logic
from app.tools.ToolCoordinator import ToolCoordinator
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory


class FamilyPolicyRouteTest(unittest.TestCase):
    def setUp(self):
        shell = DefaultShell()
        project_manager = ProjectManager(shell, RepositoryFactory(getDbLogger()), getAppLogger())
        logic = Logic(shell, project_manager, ToolCoordinator(shell, DefaultNmapExporter(shell, getAppLogger())))
        logic.createNewTemporaryProject()
        self.runtime = WebRuntime(logic)
        self.addCleanup(lambda: project_manager.closeProject(logic.activeProject))
        app = create_app(self.runtime)
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.addCleanup(lambda: self.runtime.scheduler_config.clear_family_policy("family:test-smb-brute"))

    def test_preferences_list_families_and_route_sets_and_clears_them(self):
        response = self.client.post("/api/scheduler/family-policy", json={
            "family_id": "family:test-smb-brute", "state": "suppressed", "tool_id": "smb-brute.nse", "label": "SMB brute",
        })
        self.assertEqual(200, response.status_code, response.data)
        body = json.loads(response.data)
        self.assertEqual("suppressed", body["state"])
        self.assertIn("family:test-smb-brute", {item["family_id"] for item in body["families"]})

        prefs = json.loads(self.client.get("/api/scheduler/preferences").data)
        families = {item["family_id"]: item for item in prefs["preapproved_command_families"]}
        self.assertEqual("suppressed", families["family:test-smb-brute"]["policy_state"])
        self.assertEqual("SMB brute", families["family:test-smb-brute"]["label"])

        cleared = json.loads(self.client.post("/api/scheduler/family-policy", json={"family_id": "family:test-smb-brute", "state": "clear"}).data)
        self.assertEqual("", cleared["state"])
        self.assertNotIn("family:test-smb-brute", {item["family_id"] for item in cleared["families"]})

        self.assertEqual(400, self.client.post("/api/scheduler/family-policy", json={"family_id": "x", "state": "bogus"}).status_code)
        self.assertEqual(400, self.client.post("/api/scheduler/family-policy", json={"state": "allowed"}).status_code)


if __name__ == "__main__":
    unittest.main()
