import time
import threading
import unittest


class WebJobManagerTest(unittest.TestCase):
    def _wait_for_state(self, manager, job_id, states, timeout=1.5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = manager.get_job(job_id)
            if job and job.get("status") in states:
                return job
            time.sleep(0.02)
        return manager.get_job(job_id)

    def test_job_completes_with_result(self):
        from app.web.jobs import WebJobManager

        manager = WebJobManager(max_jobs=20)
        job = manager.start("unit-test", lambda: {"ok": True})
        finished = self._wait_for_state(manager, job["id"], {"completed"})

        self.assertIsNotNone(finished)
        self.assertEqual("completed", finished["status"])
        self.assertEqual(True, finished["result"].get("ok"))

    def test_job_records_failure(self):
        from app.web.jobs import WebJobManager

        def _boom():
            raise RuntimeError("boom")

        manager = WebJobManager(max_jobs=20)
        job = manager.start("unit-test", _boom)
        finished = self._wait_for_state(manager, job["id"], {"failed"})

        self.assertIsNotNone(finished)
        self.assertEqual("failed", finished["status"])
        self.assertIn("boom", finished["error"])

    def test_queue_front_runs_before_waiting_jobs(self):
        from app.web.jobs import WebJobManager

        manager = WebJobManager(max_jobs=20)
        release_first = threading.Event()
        first_started = threading.Event()
        run_order = []

        def _first():
            first_started.set()
            release_first.wait(timeout=1.5)
            run_order.append("first")
            return {"ok": True}

        def _second():
            run_order.append("second")
            return {"ok": True}

        def _save():
            run_order.append("save")
            return {"ok": True}

        first = manager.start("nmap-scan", _first)
        self._wait_for_state(manager, first["id"], {"running"})
        self.assertTrue(first_started.is_set())

        second = manager.start("tool-run", _second)
        save = manager.start("project-save-as", _save, queue_front=True)

        release_first.set()
        self._wait_for_state(manager, save["id"], {"completed"})
        self._wait_for_state(manager, second["id"], {"completed"})

        self.assertEqual(["first", "save", "second"], run_order)

    def test_exclusive_job_waits_for_running_jobs_and_runs_before_later_jobs(self):
        from app.web.jobs import WebJobManager

        manager = WebJobManager(max_jobs=20, worker_count=3)
        release_gate = threading.Event()
        run_order = []

        def _first():
            release_gate.wait(timeout=1.5)
            run_order.append("first")
            return {"ok": True}

        def _second():
            release_gate.wait(timeout=1.5)
            run_order.append("second")
            return {"ok": True}

        def _save():
            run_order.append("save")
            return {"ok": True}

        def _third():
            run_order.append("third")
            return {"ok": True}

        first = manager.start("nmap-scan", _first)
        second = manager.start("tool-run", _second)
        self._wait_for_state(manager, first["id"], {"running"})
        self._wait_for_state(manager, second["id"], {"running"})

        save = manager.start("project-save-as", _save, queue_front=True, exclusive=True)
        third = manager.start("tool-run", _third)

        release_gate.set()
        self._wait_for_state(manager, save["id"], {"completed"})
        self._wait_for_state(manager, third["id"], {"completed"})

        self.assertIn("save", run_order)
        self.assertIn("third", run_order)
        self.assertLess(run_order.index("save"), run_order.index("third"))

    def test_cancel_queued_job_marks_cancelled(self):
        from app.web.jobs import WebJobManager

        manager = WebJobManager(max_jobs=20, worker_count=1)
        release_gate = threading.Event()
        run_order = []

        def _first():
            release_gate.wait(timeout=1.5)
            run_order.append("first")
            return {"ok": True}

        def _second():
            run_order.append("second")
            return {"ok": True}

        first = manager.start("nmap-scan", _first)
        self._wait_for_state(manager, first["id"], {"running"})
        second = manager.start("tool-run", _second)

        cancelled = manager.cancel_job(second["id"], reason="cancelled in test")
        self.assertIsNotNone(cancelled)
        self.assertEqual("cancelled", cancelled["status"])

        release_gate.set()
        self._wait_for_state(manager, first["id"], {"completed"})
        final_second = manager.get_job(second["id"])
        self.assertEqual("cancelled", final_second["status"])
        self.assertEqual(["first"], run_order)

    def test_cancel_running_job_marks_job_cancelled(self):
        from app.web.jobs import WebJobManager

        manager = WebJobManager(max_jobs=20, worker_count=1)
        job_ref = {"id": 0}

        def _runner():
            deadline = time.time() + 1.5
            while time.time() < deadline:
                if manager.is_cancel_requested(job_ref["id"]):
                    return {"cancelled": True}
                time.sleep(0.02)
            return {"timed_out": True}

        job = manager.start("long-running", _runner)
        job_ref["id"] = int(job["id"])
        self._wait_for_state(manager, job["id"], {"running"})

        manager.cancel_job(job["id"], reason="cancelled in test")
        finished = self._wait_for_state(manager, job["id"], {"cancelled"})
        self.assertIsNotNone(finished)
        self.assertEqual("cancelled", finished["status"])
        self.assertTrue(finished.get("cancel_requested"))


if __name__ == "__main__":
    unittest.main()
