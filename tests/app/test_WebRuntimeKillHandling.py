import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class _DummyProcessRepo:
    def __init__(self):
        self.killed = []
        self.outputs = {}

    def storeProcess(self, _stub):
        return 1

    def storeProcessRunningStatus(self, _process_id, _pid):
        return None

    def storeProcessRunningElapsedTime(self, _process_id, _elapsed):
        return None

    def storeProcessProgress(self, _process_id, percent=None, estimated_remaining=None):
        _ = percent, estimated_remaining
        return None

    def storeProcessCrashStatus(self, _process_id):
        return None

    def storeProcessKillStatus(self, process_id):
        self.killed.append(str(process_id))
        return None

    def storeProcessOutput(self, process_id, output):
        self.outputs[str(process_id)] = str(output)
        return None


class _SlowStdout:
    def readline(self):
        time.sleep(5.0)
        return ""

    def close(self):
        return None


class _ExitedProc:
    def __init__(self):
        self.pid = 32100
        self.returncode = 0
        self.stdout = _SlowStdout()

    def poll(self):
        return 0

    def wait(self, timeout=None):
        _ = timeout
        return 0

    def terminate(self):
        return None

    def kill(self):
        return None


class _RunningProc:
    def __init__(self):
        self.pid = 65400
        self.stdout = _SlowStdout()
        self._killed = False

    def poll(self):
        return None if not self._killed else 0

    def wait(self, timeout=None):
        _ = timeout
        raise TimeoutError("still running")

    def terminate(self):
        return None

    def kill(self):
        self._killed = True
        return None


class WebRuntimeKillHandlingTest(unittest.TestCase):
    def _make_runtime(self, repo):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._process_runtime_lock = threading.Lock()
        runtime._active_processes = {}
        runtime._kill_requests = set()
        runtime._ensure_process_tables = lambda: None
        runtime._is_nmap_command = lambda *_args, **_kwargs: False
        runtime._update_nmap_process_progress = lambda *_args, **_kwargs: None
        runtime._write_process_output_partial = lambda *_args, **_kwargs: None
        runtime._require_active_project = lambda: SimpleNamespace(
            repositoryContainer=SimpleNamespace(processRepository=repo)
        )
        return runtime

    def test_run_command_forces_completion_when_reader_does_not_close(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)

        with patch("app.web.runtime._PROCESS_READER_EXIT_GRACE_SECONDS", 0.0):
            with patch("app.web.runtime.subprocess.Popen", return_value=_ExitedProc()):
                executed, reason, process_id = WebRuntime._run_command_with_tracking(
                    runtime,
                    tool_name="test-tool",
                    tab_title="Test",
                    host_ip="127.0.0.1",
                    port="80",
                    protocol="tcp",
                    command="echo test",
                    outputfile="/tmp/out",
                    timeout=30,
                )

        self.assertTrue(executed)
        self.assertEqual("completed", reason)
        self.assertEqual(1, process_id)
        self.assertIn("[notice] output stream did not close after process exit", repo.outputs["1"])

    def test_kill_process_marks_process_and_requests_force_signal(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)
        proc = _RunningProc()
        runtime._active_processes[42] = proc

        calls = []

        def signal_spy(target_proc, force=False):
            calls.append((target_proc, bool(force)))
            if force:
                target_proc.kill()

        runtime._signal_process_tree = signal_spy

        result = WebRuntime.kill_process(runtime, 42)

        self.assertTrue(result["killed"])
        self.assertTrue(result["had_live_handle"])
        self.assertIn("42", repo.killed)
        self.assertEqual(2, len(calls))
        self.assertFalse(calls[0][1])
        self.assertTrue(calls[1][1])


if __name__ == "__main__":
    unittest.main()
