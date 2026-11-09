import unittest

from sqlalchemy import text


class EvidenceGraphHostDeleteTest(unittest.TestCase):
    """Deleting a host prunes every node keyed to it, URL nodes included (they are keyed url:<host_id>:<url>)."""

    def test_delete_host_removes_its_url_nodes(self):
        from app.ProjectManager import ProjectManager
        from app.importers.nmap_runner import import_nmap_xml_into_project
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.graph import delete_host_from_evidence_graph, rebuild_evidence_graph
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory

        project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        try:
            import_nmap_xml_into_project(project=project, xml_path="tests/parsers/nmap-fixtures/valid-nmap-report.xml")
            host = project.repositoryContainer.hostRepository.getAllHostObjs()[0]
            rebuild_evidence_graph(project.database)

            def keys():
                session = project.database.session()
                try:
                    return [str(row[0]) for row in session.execute(text("SELECT node_key FROM graph_node")).fetchall()]
                finally:
                    session.close()

            before = keys()
            self.assertTrue(any(key.startswith(f"url:{host.id}:") for key in before), before)
            self.assertTrue(any(key.startswith(f"port:{host.id}:") for key in before), before)

            removed = delete_host_from_evidence_graph(project.database, host_id=int(host.id), host_ip=str(host.ip))
            self.assertGreater(removed, 0)
            after = keys()
            self.assertFalse(any(key.startswith(f"url:{host.id}:") for key in after), after)
            self.assertFalse(any(key.startswith(f"port:{host.id}:") for key in after), after)
            self.assertNotIn(f"host:{host.ip}", after)
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
