import csv
import io
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
from db.entities.cve import cve
from db.entities.host import hostObj


class FullWorkspaceExportTest(unittest.TestCase):
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
        session = logic.activeProject.database.session()
        try:
            for index in range(60):  # more than the 40-row snapshot cap, and one host that is down
                status = "down" if index == 0 else "up"
                session.add(hostObj(ip=f"10.9.{index // 250}.{index % 250 + 1}", ipv4=f"10.9.0.{index + 1}", status=status, hostname=f"h{index}"))
            session.flush()
            first = session.query(hostObj).filter_by(hostname="h1").first()
            session.add(cve("CVE-2024-0001", "https://example.test/cve", "openssh", first.id, severity="9.8",
                            source="vulners", version="9.6", exploitId=123, exploit="OpenSSH exploit",
                            exploitUrl="https://www.exploit-db.com/exploits/123"))
            session.commit()
        finally:
            session.close()

    def test_json_export_is_uncapped_and_includes_down_hosts(self):
        response = self.client.get("/api/export/json")
        self.assertEqual(200, response.status_code)
        payload = json.loads(response.data)
        self.assertEqual(60, len(payload["hosts"]))
        self.assertIn("down", {host["status"] for host in payload["hosts"]})
        self.assertEqual(1, len(payload["cves"]))
        self.assertEqual("https://www.exploit-db.com/exploits/123", payload["cves"][0]["exploit_url"])
        for table in ("services", "ports", "processes", "jobs", "scan_history", "scheduler_decisions", "credentials"):
            self.assertIn(table, payload)

    def test_table_csv_export(self):
        response = self.client.get("/api/export/table/cves.csv")
        self.assertEqual(200, response.status_code)
        rows = list(csv.reader(io.StringIO(response.data.decode("utf-8"))))
        self.assertIn("exploit_url", rows[0])
        self.assertEqual(2, len(rows))
        self.assertEqual(404, self.client.get("/api/export/table/nope.csv").status_code)
        self.assertEqual(400, self.client.get("/api/export/table/hosts.xml").status_code)
        tables = json.loads(self.client.get("/api/export/tables").data)["tables"]
        self.assertIn("findings", tables)

    def test_full_csv_has_a_section_per_table(self):
        response = self.client.get("/api/export/csv")
        text = response.data.decode("utf-8")
        for section in ("project", "hosts", "cves", "scheduler_approvals"):
            self.assertIn(f"\r\n{section}\r\n", "\r\n" + text)


if __name__ == "__main__":
    unittest.main()
