import threading
import time
import unittest
from unittest import mock


class WebRuntimeCredentialCaptureTest(unittest.TestCase):
    def setUp(self):
        from app.web.jobs import WebJobManager
        from app.web.runtime import WebRuntime

        self.jobs = WebJobManager(worker_count=1)
        self.release_blocker = threading.Event()
        self.blocker_started = threading.Event()

        def _blocker():
            self.blocker_started.set()
            self.release_blocker.wait(10)
            return {}

        # Occupy the only worker so capture jobs stay queued (no process row exists for them yet).
        self.jobs.start("blocker", _blocker)
        self.assertTrue(self.blocker_started.wait(5))

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime.jobs = self.jobs
        runtime._get_workspace_setting_locked = lambda _key, default=None: default
        runtime._emit_ui_invalidation = lambda *_args, **_kwargs: None
        runtime.kill_process = mock.Mock(return_value={"killed": True, "had_live_handle": True})
        self.runtime = runtime
        self.latest_session = {}
        patcher = mock.patch(
            "app.web.runtime_credential_capture.latest_credential_capture_session_locked",
            side_effect=lambda _runtime, tool: dict(self.latest_session.get(tool, {})),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for job in self.jobs.list_jobs(limit=200):
            if job.get("type") == "credential-capture-session":
                self.jobs.cancel_job(int(job["id"]))
        self.release_blocker.set()

    def test_queued_capture_job_blocks_a_second_start_and_can_be_stopped(self):
        from app.web.runtime import WebRuntime

        first = WebRuntime.start_credential_capture_session_job(self.runtime, "responder")
        self.assertEqual("queued", first["status"])

        with self.assertRaisesRegex(ValueError, "already running"):
            WebRuntime.start_credential_capture_session_job(self.runtime, "responder")
        # Another capture tool is independent.
        other = WebRuntime.start_credential_capture_session_job(self.runtime, "ntlmrelayx")
        self.assertEqual("queued", other["status"])

        stopped = WebRuntime.stop_credential_capture_session(self.runtime, "responder")

        self.assertTrue(stopped["stopped"])
        self.assertEqual(int(first["id"]), stopped["job_id"])
        self.assertEqual("cancelled", self.jobs.get_job(int(first["id"]))["status"])
        self.runtime.kill_process.assert_not_called()
        # Once stopped, the tool can be started again.
        restarted = WebRuntime.start_credential_capture_session_job(self.runtime, "responder")
        self.assertNotEqual(first["id"], restarted["id"])

    def test_concurrent_starts_queue_only_one_job(self):
        from app.web.runtime import WebRuntime

        real_start = self.jobs.start

        def slow_start(*args, **kwargs):
            time.sleep(0.2)  # widen the window between the duplicate check and the job existing
            return real_start(*args, **kwargs)

        self.jobs.start = slow_start
        outcomes = []

        def _start():
            try:
                outcomes.append(WebRuntime.start_credential_capture_session_job(self.runtime, "responder"))
            except ValueError as exc:
                outcomes.append(exc)

        threads = [threading.Thread(target=_start) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)

        started = [item for item in outcomes if isinstance(item, dict)]
        rejected = [item for item in outcomes if isinstance(item, ValueError)]
        self.assertEqual(1, len(started))
        self.assertEqual(1, len(rejected))
        capture_jobs = [
            job for job in self.jobs.list_jobs(limit=200)
            if job.get("type") == "credential-capture-session" and job.get("status") == "queued"
        ]
        self.assertEqual(1, len(capture_jobs))

    def test_stop_kills_running_capture_process(self):
        from app.web.runtime import WebRuntime

        self.latest_session["responder"] = {"process_id": 7, "running": True, "status": "Running"}

        stopped = WebRuntime.stop_credential_capture_session(self.runtime, "responder")

        self.assertTrue(stopped["stopped"])
        self.assertEqual(7, stopped["process_id"])
        self.runtime.kill_process.assert_called_once_with(7)

    def test_stop_reports_not_running_without_process_or_job(self):
        from app.web.runtime import WebRuntime

        self.latest_session["responder"] = {"process_id": 7, "running": False, "status": "Finished"}

        stopped = WebRuntime.stop_credential_capture_session(self.runtime, "responder")

        self.assertFalse(stopped["stopped"])
        self.assertEqual("not running", stopped["reason"])
        self.runtime.kill_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
