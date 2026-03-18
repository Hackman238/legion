import unittest


class ScanHistoryStoreTest(unittest.TestCase):
    def test_record_update_and_list_scan_submissions(self):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.scan_history import (
            ensure_scan_submission_table,
            list_scan_submissions,
            record_scan_submission,
            update_scan_submission,
        )
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory

        project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            ensure_scan_submission_table(project.database)
            created = record_scan_submission(project.database, {
                "job_id": "77",
                "submission_kind": "nmap_scan",
                "status": "submitted",
                "target_summary": "10.0.0.0/24",
                "scope_summary": "subnets: 10.0.0.0/24",
                "targets": ["10.0.0.0/24"],
                "scan_mode": "easy",
                "discovery": True,
                "staged": False,
                "run_actions": False,
                "nmap_path": "nmap",
                "nmap_args": "-sV",
                "scan_options": {"top_ports": 1000},
            })

            self.assertGreater(int(created.get("id", 0) or 0), 0)

            updated = update_scan_submission(
                project.database,
                job_id=77,
                status="completed",
                result_summary="imported 8 hosts",
            )
            self.assertIsNotNone(updated)
            self.assertEqual("completed", updated["status"])
            self.assertEqual("imported 8 hosts", updated["result_summary"])

            listing = list_scan_submissions(project.database, limit=10)
            self.assertEqual(1, len(listing))
            self.assertEqual("nmap_scan", listing[0]["submission_kind"])
            self.assertEqual(["10.0.0.0/24"], listing[0]["targets"])
            self.assertEqual(1000, listing[0]["scan_options"]["top_ports"])
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
