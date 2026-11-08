import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _runtime(source, saved, running_jobs):
    runtime = SimpleNamespace(
        _lock=threading.RLock(),
        _save_in_progress=False,
        _active_processes={},
        jobs=SimpleNamespace(list_jobs=lambda limit=200: list(running_jobs)),
        logic=SimpleNamespace(activeProject=source),
        _ensure_scheduler_table=lambda: None,
        _ensure_scheduler_approval_store=lambda: None,
        _ensure_process_tables=lambda: None,
    )
    runtime.logic.projectManager = MagicMock()
    runtime.logic.retireDatabase = MagicMock()
    runtime.logic.projectManager.saveProjectAs.return_value = saved
    return runtime


class WebSaveAsSourceDatabaseTest(unittest.TestCase):
    def _save(self, running_jobs):
        from app.web import runtime_projects

        source, saved = MagicMock(), MagicMock()
        runtime = _runtime(source, saved, running_jobs)
        with patch.object(runtime_projects, "count_running_or_waiting_processes", return_value=0), \
                patch.object(runtime_projects, "get_project_details", return_value={}):
            runtime_projects.save_project_as_impl(runtime, "/tmp/copy.legion", replace=True)
        self.assertIs(saved, runtime.logic.activeProject)
        return source, runtime

    def test_source_database_disposed_when_only_the_save_job_runs(self):
        source, runtime = self._save([{"type": "project-save-as", "status": "running"}])
        source.database.dispose.assert_called_once_with()
        runtime.logic.retireDatabase.assert_not_called()

    def test_source_database_kept_while_another_job_may_still_use_it(self):
        source, runtime = self._save([
            {"type": "project-save-as", "status": "running"},
            {"type": "host-screenshot-refresh", "status": "running"},
        ])
        source.database.dispose.assert_not_called()
        runtime.logic.retireDatabase.assert_called_once_with(source.database)  # released when jobs go idle


class WebSaveAsRetireRaceTest(unittest.TestCase):
    def test_job_finishing_between_count_and_retire_still_releases_the_source_database(self):
        from app.logic import Logic
        from app.web import runtime_projects

        source, saved = MagicMock(), MagicMock()
        other_job = {"type": "host-screenshot-refresh", "status": "running"}
        list_calls = []

        def _list_jobs(limit=200):
            list_calls.append(dict(other_job))
            jobs = [dict(other_job)]
            # The other job completes right after the save path counted it as running: its own "completed"
            # idle check ran before the database was retired, so nothing else would release it.
            if len(list_calls) >= 2:
                other_job["status"] = "completed"
            return jobs

        runtime = _runtime(source, saved, [])
        runtime.jobs = SimpleNamespace(list_jobs=_list_jobs)
        logic = Logic(MagicMock(), MagicMock(), MagicMock())
        logic.activeProject = source
        logic.projectManager = MagicMock()
        logic.projectManager.saveProjectAs.return_value = saved
        runtime.logic = logic
        with patch.object(runtime_projects, "count_running_or_waiting_processes", return_value=0), \
                patch.object(runtime_projects, "get_project_details", return_value={}):
            runtime_projects.save_project_as_impl(runtime, "/tmp/copy.legion", replace=True)

        self.assertIs(saved, logic.activeProject)
        source.database.dispose.assert_called_once_with()
        self.assertFalse(logic.hasRetiredDatabases())


class WebRetiredDatabaseReleaseTest(unittest.TestCase):
    def _runtime(self, jobs):
        from app.logic import Logic

        logic = Logic(MagicMock(), MagicMock(), MagicMock())
        database = MagicMock()
        logic.retireDatabase(database)
        runtime = SimpleNamespace(
            logic=logic,
            jobs=SimpleNamespace(list_jobs=lambda limit=200: list(jobs)),
            _emit_ui_invalidation=lambda *args, **kwargs: None,
        )
        return runtime, database

    def test_released_when_the_last_running_job_finishes(self):
        from app.web import runtime_jobs

        jobs = [{"type": "host-screenshot-refresh", "status": "running"}]
        runtime, database = self._runtime(jobs)
        with patch.object(runtime_jobs, "emit_ui_invalidation"):
            runtime_jobs.handle_job_change(runtime, {"type": "tool-run", "status": "completed"}, "completed")
            database.dispose.assert_not_called()            # another job still runs
            jobs[0]["status"] = "completed"
            runtime_jobs.handle_job_change(runtime, dict(jobs[0]), "completed")
        database.dispose.assert_called_once_with()
        self.assertFalse(runtime.logic.hasRetiredDatabases())


if __name__ == "__main__":
    unittest.main()
