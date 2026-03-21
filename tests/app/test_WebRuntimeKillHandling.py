import collections
import collections.abc
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

_REAL_SLEEP = time.sleep


for _name in ("Mapping", "MutableMapping", "Sequence"):
    if not hasattr(collections, _name):
        setattr(collections, _name, getattr(collections.abc, _name))


class _DummyProcessRepo:
    def __init__(self):
        self.killed = []
        self.crashed = []
        self.problems = []
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
        self.crashed.append(str(_process_id))
        return None

    def storeProcessProblemStatus(self, _process_id):
        self.problems.append(str(_process_id))
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


class _ImmediateStdout:
    def readline(self):
        return ""

    def close(self):
        return None


class _ExitCodeProc:
    def __init__(self, returncode):
        self.pid = 42000 + abs(int(returncode))
        self.returncode = int(returncode)
        self.stdout = _ImmediateStdout()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        _ = timeout
        return self.returncode

    def terminate(self):
        return None

    def kill(self):
        return None


class _FakeClock:
    def __init__(self, start=100.0):
        self._now = float(start)
        self._lock = threading.Lock()

    def monotonic(self):
        with self._lock:
            return self._now

    def sleep(self, seconds):
        with self._lock:
            self._now += float(seconds)
        _REAL_SLEEP(0.001)


class _ScheduledStdout:
    def __init__(self, clock, entries):
        self._clock = clock
        self._entries = list(entries or [])
        self._index = 0
        self._closed = False

    def readline(self):
        if self._closed or self._index >= len(self._entries):
            return ""

        emit_at, line = self._entries[self._index]
        while not self._closed:
            if self._clock.monotonic() >= float(emit_at):
                self._index += 1
                return str(line)
            _REAL_SLEEP(0.001)
        return ""

    def close(self):
        self._closed = True
        return None


class _ClockDrivenProc:
    def __init__(self, clock, stdout, exit_at=None, pid=65001, returncode=0):
        self.pid = int(pid)
        self.stdout = stdout
        self._clock = clock
        self._exit_at = float(exit_at) if exit_at is not None else None
        self._natural_returncode = int(returncode)
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if self._exit_at is not None and self._clock.monotonic() >= self._exit_at:
            self.returncode = self._natural_returncode
            return self.returncode
        return None

    def wait(self, timeout=None):
        _ = timeout
        status = self.poll()
        if status is None:
            raise TimeoutError("still running")
        return status

    def terminate(self):
        self.returncode = -15
        return None

    def kill(self):
        self.returncode = -9
        return None


class WebRuntimeKillHandlingTest(unittest.TestCase):
    def _make_runtime(self, repo):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        runtime._process_runtime_lock = threading.Lock()
        runtime._active_processes = {}
        runtime._kill_requests = set()
        runtime._job_process_ids = {}
        runtime._process_job_id = {}
        runtime._ensure_process_tables = lambda: None
        runtime._emit_ui_invalidation = lambda *_args, **_kwargs: None
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

    def test_nonzero_exit_is_marked_problem(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)

        with patch("app.web.runtime.subprocess.Popen", return_value=_ExitCodeProc(2)):
            executed, reason, process_id = WebRuntime._run_command_with_tracking(
                runtime,
                tool_name="test-tool",
                tab_title="Test",
                host_ip="127.0.0.1",
                port="80",
                protocol="tcp",
                command="badcmd --bogus",
                outputfile="/tmp/out",
                timeout=30,
            )

        self.assertFalse(executed)
        self.assertEqual("failed: exit 2", reason)
        self.assertEqual(1, process_id)
        self.assertEqual(["1"], repo.problems)
        self.assertEqual([], repo.crashed)

    def test_allowed_nonzero_exit_is_treated_as_completed(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)

        with patch("app.web.runtime.subprocess.Popen", return_value=_ExitCodeProc(1)):
            executed, reason, process_id = WebRuntime._run_command_with_tracking(
                runtime,
                tool_name="nikto",
                tab_title="Nikto",
                host_ip="127.0.0.1",
                port="443",
                protocol="tcp",
                command="nikto -h https://127.0.0.1/",
                outputfile="/tmp/out",
                timeout=30,
            )

        self.assertTrue(executed)
        self.assertEqual("completed (allowed exit 1)", reason)
        self.assertEqual(1, process_id)
        self.assertEqual([], repo.problems)
        self.assertEqual([], repo.crashed)

    def test_signal_exit_after_threshold_is_marked_crashed(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)
        monotonic_values = iter([100.0, 106.2, 106.2])

        with patch("app.web.runtime.subprocess.Popen", return_value=_ExitCodeProc(139)):
            with patch("app.web.runtime.time.monotonic", side_effect=lambda: next(monotonic_values)):
                with patch("app.web.runtime.time.sleep", return_value=None):
                    executed, reason, process_id = WebRuntime._run_command_with_tracking(
                        runtime,
                        tool_name="test-tool",
                        tab_title="Test",
                        host_ip="127.0.0.1",
                        port="80",
                        protocol="tcp",
                        command="segfaulting-tool",
                        outputfile="/tmp/out",
                        timeout=30,
                    )

        self.assertFalse(executed)
        self.assertEqual("failed: exit 139", reason)
        self.assertEqual(1, process_id)
        self.assertEqual(["1"], repo.crashed)
        self.assertEqual([], repo.problems)

    def test_timeout_is_based_on_output_inactivity(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)
        runtime._signal_process_tree = lambda proc, force=False: proc.kill() if force else proc.terminate()
        clock = _FakeClock(start=100.0)
        proc = _ClockDrivenProc(
            clock,
            stdout=_ScheduledStdout(clock, [(102.0, "still alive\n")]),
            exit_at=None,
            pid=65010,
        )

        with patch("app.web.runtime.subprocess.Popen", return_value=proc):
            with patch("app.web.runtime.time.monotonic", side_effect=clock.monotonic):
                with patch("app.web.runtime.time.sleep", side_effect=clock.sleep):
                    executed, reason, process_id = WebRuntime._run_command_with_tracking(
                        runtime,
                        tool_name="test-tool",
                        tab_title="Test",
                        host_ip="127.0.0.1",
                        port="80",
                        protocol="tcp",
                        command="long-running-tool",
                        outputfile="/tmp/out",
                        timeout=5,
                    )

        self.assertFalse(executed)
        self.assertEqual("failed: timeout after 5s without output", reason)
        self.assertEqual(1, process_id)
        self.assertEqual(["1"], repo.problems)
        self.assertIn("still alive", repo.outputs["1"])
        self.assertIn("[timeout after 5s without output]", repo.outputs["1"])

    def test_output_delta_extends_timeout_budget(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)
        runtime._signal_process_tree = lambda proc, force=False: proc.kill() if force else proc.terminate()
        clock = _FakeClock(start=100.0)
        proc = _ClockDrivenProc(
            clock,
            stdout=_ScheduledStdout(clock, [(104.0, "progress heartbeat\n")]),
            exit_at=108.0,
            pid=65011,
        )

        with patch("app.web.runtime._PROCESS_READER_EXIT_GRACE_SECONDS", 0.0):
            with patch("app.web.runtime.subprocess.Popen", return_value=proc):
                with patch("app.web.runtime.time.monotonic", side_effect=clock.monotonic):
                    with patch("app.web.runtime.time.sleep", side_effect=clock.sleep):
                        executed, reason, process_id = WebRuntime._run_command_with_tracking(
                            runtime,
                            tool_name="test-tool",
                            tab_title="Test",
                            host_ip="127.0.0.1",
                            port="80",
                            protocol="tcp",
                            command="chatty-long-run",
                            outputfile="/tmp/out",
                            timeout=5,
                        )

        self.assertTrue(executed)
        self.assertEqual("completed", reason)
        self.assertEqual(1, process_id)
        self.assertEqual([], repo.problems)
        self.assertEqual([], repo.crashed)
        self.assertIn("progress heartbeat", repo.outputs["1"])

    def test_quiet_long_running_timeout_uses_cpu_io_inactivity(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)
        runtime._signal_process_tree = lambda proc, force=False: proc.kill() if force else proc.terminate()
        runtime._resolve_process_timeout_policy = lambda *_args, **_kwargs: {
            "quiet_long_running": True,
            "inactivity_timeout_seconds": 5,
            "hard_timeout_seconds": 0,
        }
        runtime._sample_process_tree_activity = lambda _proc: (0.0, 0)
        clock = _FakeClock(start=100.0)
        proc = _ClockDrivenProc(
            clock,
            stdout=_ScheduledStdout(clock, []),
            exit_at=None,
            pid=65012,
        )

        with patch("app.web.runtime.subprocess.Popen", return_value=proc):
            with patch("app.web.runtime.time.monotonic", side_effect=clock.monotonic):
                with patch("app.web.runtime.time.sleep", side_effect=clock.sleep):
                    executed, reason, process_id = WebRuntime._run_command_with_tracking(
                        runtime,
                        tool_name="nikto",
                        tab_title="Test",
                        host_ip="127.0.0.1",
                        port="443",
                        protocol="tcp",
                        command="nikto -h https://127.0.0.1/",
                        outputfile="/tmp/out",
                        timeout=5,
                    )

        self.assertFalse(executed)
        self.assertEqual("failed: timeout after 5s without CPU/IO activity", reason)
        self.assertEqual(1, process_id)
        self.assertEqual(["1"], repo.problems)
        self.assertIn("[timeout after 5s without CPU/IO activity]", repo.outputs["1"])

    def test_cpu_io_activity_extends_quiet_long_running_budget(self):
        from app.web.runtime import WebRuntime

        repo = _DummyProcessRepo()
        runtime = self._make_runtime(repo)
        runtime._signal_process_tree = lambda proc, force=False: proc.kill() if force else proc.terminate()
        runtime._resolve_process_timeout_policy = lambda *_args, **_kwargs: {
            "quiet_long_running": True,
            "inactivity_timeout_seconds": 5,
            "hard_timeout_seconds": 0,
        }
        clock = _FakeClock(start=100.0)
        proc = _ClockDrivenProc(
            clock,
            stdout=_ScheduledStdout(clock, []),
            exit_at=108.0,
            pid=65013,
        )

        def activity_sample(_proc):
            if clock.monotonic() >= 104.0:
                return 1.0, 128
            return 0.0, 0

        runtime._sample_process_tree_activity = activity_sample

        with patch("app.web.runtime.subprocess.Popen", return_value=proc):
            with patch("app.web.runtime.time.monotonic", side_effect=clock.monotonic):
                with patch("app.web.runtime.time.sleep", side_effect=clock.sleep):
                    executed, reason, process_id = WebRuntime._run_command_with_tracking(
                        runtime,
                        tool_name="nikto",
                        tab_title="Test",
                        host_ip="127.0.0.1",
                        port="443",
                        protocol="tcp",
                        command="nikto -h https://127.0.0.1/",
                        outputfile="/tmp/out",
                        timeout=5,
                    )

        self.assertTrue(executed)
        self.assertEqual("completed", reason)
        self.assertEqual(1, process_id)
        self.assertEqual([], repo.problems)
        self.assertEqual([], repo.crashed)


if __name__ == "__main__":
    unittest.main()
