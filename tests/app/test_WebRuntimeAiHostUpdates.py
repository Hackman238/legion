import threading
import unittest
from types import SimpleNamespace

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.host import hostObj
from db.entities.port import portObj
from db.entities.service import serviceObj


class EnrichHostFromObservedResultsTest(unittest.TestCase):
    def setUp(self):
        self.project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        self.addCleanup(self.project_manager.closeProject, self.project)

    def test_inferred_os_replaces_the_nan_default_accuracy(self):
        from app.web.runtime_scheduler_ai_host_updates import enrich_host_from_observed_results

        session = self.project.database.session()
        try:
            host = hostObj(ip="10.0.0.9", hostname="srv09")   # osAccuracy defaults to 'NaN'
            session.add(host)
            session.flush()
            service = serviceObj("ssh", host.id, "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.6")
            session.add(service)
            session.flush()
            session.add(portObj("22", "tcp", "open", host.id, service.id))
            session.commit()
            self.assertEqual("NaN", host.osAccuracy)
        finally:
            session.close()

        runtime = SimpleNamespace(
            _lock=threading.RLock(),
            logic=SimpleNamespace(activeProject=self.project),
            _truncate_scheduler_text=lambda value, limit: str(value or "")[:limit],
        )
        enrich_host_from_observed_results(runtime, host_ip="10.0.0.9", port="22", protocol="tcp")

        session = self.project.database.session()
        try:
            row = session.query(hostObj).filter_by(ip="10.0.0.9").one()
            self.assertEqual("Linux", row.osMatch)
            self.assertEqual("80", row.osAccuracy)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
