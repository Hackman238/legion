from __future__ import annotations

import os
import queue
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.paths import tool_working_directory
from app.settings import AppSettings
from app.timing import getTimestamp
from app.tooling import build_tool_execution_env
from db.entities.l1script import l1ScriptObj

_PROCESS_READER_EXIT_GRACE_SECONDS = 2.0
_PROCESS_CRASH_MIN_RUNTIME_SECONDS = 5.0
_PARTIAL_OUTPUT_FLUSH_MIN_SECONDS = 0.5
_PARTIAL_OUTPUT_FLUSH_MAX_SECONDS = 5.0


def _is_signal_exit(code: int) -> bool:
    # Negative: Popen saw the signal directly; 128+N: a wrapping shell reported a signalled child.
    return code < 0 or 128 <= code <= 192


def _partial_output_flush_interval(output_length: int) -> float:
    # Each partial flush rewrites the whole accumulated output, so back off as it grows:
    # 0.5s up to 64 KiB, then +0.5s per additional 64 KiB, capped at 5s.
    extra_steps = max(0, int(output_length or 0)) // 65536
    return min(_PARTIAL_OUTPUT_FLUSH_MAX_SECONDS, _PARTIAL_OUTPUT_FLUSH_MIN_SECONDS * (1 + extra_steps))


class _TrackedProcessStub:
    def __init__(
            self,
            *,
            name: str,
            tab_title: str,
            host_ip: str,
            port: str,
            protocol: str,
            command: str,
            start_time: str,
            outputfile: str,
    ):
        self.name = str(name)
        self.tabTitle = str(tab_title)
        self.hostIp = str(host_ip)
        self.port = str(port)
        self.protocol = str(protocol)
        self.command = str(command)
        self.startTime = str(start_time)
        self.outputfile = str(outputfile)
        self.id = None

    def processId(self):
        return 0


def run_command_with_tracking(
        runtime,
        *,
        tool_name: str,
        tab_title: str,
        host_ip: str,
        port: str,
        protocol: str,
        command: str,
        outputfile: str,
        timeout: int,
        job_id: int = 0,
        return_metadata: bool = False,
        on_process_created=None,
) -> Any:
    """Run a tool command with process-table tracking.

    on_process_created(process_id), if given, is called as soon as the process row exists, so callers
    without a job id can still find (and kill) the process while it runs.
    """
    with runtime._lock:
        project = runtime._require_active_project()
        runtime._ensure_process_tables()
        process_repo = project.repositoryContainer.processRepository

    start_time = getTimestamp(True)
    stub = _TrackedProcessStub(
        name=str(tool_name),
        tab_title=str(tab_title),
        host_ip=str(host_ip),
        port=str(port),
        protocol=str(protocol),
        command=str(command),
        start_time=start_time,
        outputfile=str(outputfile),
    )

    try:
        process_id = int(process_repo.storeProcess(stub) or 0)
    except Exception:
        with runtime._lock:
            runtime._ensure_process_tables()
        process_id = int(process_repo.storeProcess(stub) or 0)

    if process_id > 0 and callable(on_process_created):
        try:
            on_process_created(int(process_id))
        except Exception:
            pass

    if process_id <= 0:
        failed_result = (False, "error: failed to create process record", 0)
        if not return_metadata:
            return failed_result
        return failed_result + ({
            "started_at": start_time,
            "finished_at": getTimestamp(True),
            "stdout_ref": "",
            "stderr_ref": "",
            "artifact_refs": [],
        },)

    resolved_job_id = int(job_id or 0)
    if resolved_job_id > 0:
        runtime._register_job_process(resolved_job_id, int(process_id))
        if runtime.jobs.is_cancel_requested(resolved_job_id):
            process_repo.storeProcessCancelStatus(str(process_id))
            process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
            process_repo.storeProcessOutput(str(process_id), "[cancelled before start]")
            runtime._unregister_job_process(int(process_id))
            cancelled_result = (False, "killed", int(process_id))
            if not return_metadata:
                return cancelled_result
            return cancelled_result + ({
                "started_at": start_time,
                "finished_at": getTimestamp(True),
                "stdout_ref": f"process_output:{int(process_id)}",
                "stderr_ref": "",
                "artifact_refs": runtime._collect_command_artifacts(outputfile),
            },)
    runtime._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)

    proc: Optional[subprocess.Popen] = None
    output_parts: List[str] = []
    output_queue: queue.Queue = queue.Queue()
    reader_done = threading.Event()
    started_at = time.monotonic()
    timeout_policy = runtime._resolve_process_timeout_policy(tool_name, timeout)
    quiet_long_running = bool(timeout_policy.get("quiet_long_running", False))
    try:
        inactivity_timeout_seconds = max(0, int(timeout_policy.get("inactivity_timeout_seconds", 300)))
    except (TypeError, ValueError):
        inactivity_timeout_seconds = 300
    # 0 disables the inactivity timeout (long-running listeners); the hard timeout still applies when set.
    hard_timeout_seconds = max(0, int(timeout_policy.get("hard_timeout_seconds", 0) or 0))
    progress_state = {
        "adapter": runtime._process_progress_adapter_for_command(str(tool_name), str(command)),
        "percent": None,
        "remaining": None,
        "message": "",
        "source": "",
        "updated_at": 0.0,
    }
    timed_out = False
    timeout_reason = ""
    killed = False
    flush_due_at = started_at
    elapsed_due_at = started_at
    last_output_at = started_at
    last_activity_at = started_at
    activity_sample_due_at = started_at
    last_process_activity = None
    process_exited_at = None

    def _store_failure_status(status_name: str):
        if str(status_name) == "Crashed":
            process_repo.storeProcessCrashStatus(str(process_id))
        else:
            process_repo.storeProcessProblemStatus(str(process_id))

    def _classify_nonzero_exit(returncode_value: int, runtime_seconds: float) -> str:
        try:
            code = int(returncode_value)
        except (TypeError, ValueError):
            return "Problem"

        if _is_signal_exit(code) and float(runtime_seconds) >= float(_PROCESS_CRASH_MIN_RUNTIME_SECONDS):
            return "Crashed"
        return "Problem"

    def _was_killed_externally(returncode_value) -> bool:
        # kill_process (HTTP thread) may signal and reap the process itself, so the loop above never
        # sees it running with a kill request: recognise that kill from the request or the stored status.
        # The exit code is deliberately not consulted: a tool that handles SIGTERM may exit 0 or 1, and a
        # kill request is only ever recorded for a process that was still running when the user asked.
        _ = returncode_value
        with runtime._process_runtime_lock:
            if int(process_id) in runtime._kill_requests:
                return True
        try:
            return bool(process_repo.isKilledProcess(str(process_id)))
        except Exception:
            return False

    def _reader(pipe):
        try:
            if pipe is None:
                return
            for line in iter(pipe.readline, ""):
                output_queue.put(str(line))
        except Exception as exc:
            output_queue.put(f"\n[reader-error] {exc}\n")
        finally:
            try:
                if pipe is not None:
                    pipe.close()
            except Exception:
                pass
            reader_done.set()

    def _build_result(executed: bool, reason: str, process_identifier: int):
        result = (bool(executed), str(reason), int(process_identifier or 0))
        if not return_metadata:
            return result
        return result + ({
            "started_at": start_time,
            "finished_at": getTimestamp(True),
            "stdout_ref": f"process_output:{int(process_identifier)}" if int(process_identifier or 0) > 0 else "",
            "stderr_ref": "",
            "artifact_refs": runtime._collect_command_artifacts(outputfile),
        },)

    def _persist_special_output(output_text: str):
        normalized_tool = str(tool_name or "").strip().lower()
        if normalized_tool not in {"responder", "ntlmrelayx", "ntlmrelay"}:
            return
        try:
            runtime._persist_credential_capture_output(
                tool_name=str(tool_name or ""),
                output_text=str(output_text or ""),
                default_source=str(host_ip or ""),
            )
        except Exception:
            pass

    try:
        # The process may have been killed while it was still "Waiting" (no live handle yet).
        if process_repo.isKilledProcess(str(process_id)):
            process_repo.storeProcessOutput(str(process_id), "[killed before start]")
            return _build_result(False, "killed", int(process_id))
        proc = subprocess.Popen(
            command,
            shell=True,
            cwd=tool_working_directory(command),  # the install directory when ./scripts or ./wordlists is named
            # Never hand the tool Legion's own stdin: ProjectDiscovery tools (katana, httpx) treat a piped stdin
            # as another target source and wait for EOF forever, which looks like a hung scan with no output.
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            # Tools emit arbitrary bytes; a strict decode error would kill the reader (and the tool, via SIGPIPE).
            errors="replace",
            bufsize=1,
            start_new_session=(os.name != "nt"),
            env=build_tool_execution_env(),
        )
        with runtime._process_runtime_lock:
            runtime._active_processes[int(process_id)] = proc
            runtime._kill_requests.discard(int(process_id))
        # Registered above, so a kill from now on finds the live handle. A kill that landed between the
        # pre-start check and registration only marked the row Killed: honour it instead of overwriting it.
        if process_repo.isKilledProcess(str(process_id)):
            with runtime._process_runtime_lock:
                runtime._kill_requests.add(int(process_id))
        else:
            process_repo.storeProcessRunningStatus(str(process_id), str(proc.pid))
        if quiet_long_running:
            last_process_activity = runtime._sample_process_tree_activity(proc)

        reader_thread = threading.Thread(target=_reader, args=(proc.stdout,), daemon=True)
        reader_thread.start()

        while True:
            changed = False
            while True:
                try:
                    chunk = output_queue.get_nowait()
                except queue.Empty:
                    break
                output_parts.append(str(chunk))
                changed = True
                if progress_state.get("adapter"):
                    runtime._update_process_progress(
                        process_repo,
                        process_id=int(process_id),
                        tool_name=str(tool_name),
                        command=str(command),
                        text_chunk=str(chunk),
                        runtime_seconds=max(0.0, time.monotonic() - started_at),
                        state=progress_state,
                    )

            now = time.monotonic()
            if changed:
                last_output_at = now
                last_activity_at = now
            if changed and now >= flush_due_at:
                partial_output = "".join(output_parts)
                output_parts[:] = [partial_output]
                runtime._write_process_output_partial(int(process_id), partial_output)
                flush_due_at = now + _partial_output_flush_interval(len(partial_output))

            if quiet_long_running and now >= activity_sample_due_at and proc.poll() is None:
                current_activity = runtime._sample_process_tree_activity(proc)
                if runtime._process_tree_activity_changed(last_process_activity, current_activity):
                    last_activity_at = now
                if current_activity is not None:
                    last_process_activity = current_activity
                activity_sample_due_at = now + 1.0

            if now >= elapsed_due_at:
                elapsed_seconds = int(now - started_at)
                try:
                    process_repo.storeProcessRunningElapsedTime(str(process_id), elapsed_seconds)
                except Exception:
                    pass
                if progress_state.get("adapter") == "tshark":
                    runtime._update_process_progress(
                        process_repo,
                        process_id=int(process_id),
                        tool_name=str(tool_name),
                        command=str(command),
                        text_chunk="",
                        runtime_seconds=float(elapsed_seconds),
                        state=progress_state,
                    )
                elapsed_due_at = now + 1.0

            with runtime._process_runtime_lock:
                kill_requested = int(process_id) in runtime._kill_requests
            if kill_requested and proc.poll() is None:
                killed = True
                runtime._signal_process_tree(proc, force=False)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    runtime._signal_process_tree(proc, force=True)

            if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id) and proc.poll() is None:
                killed = True
                runtime._signal_process_tree(proc, force=False)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    runtime._signal_process_tree(proc, force=True)

            if proc.poll() is None:
                if hard_timeout_seconds > 0 and (now - started_at) > int(hard_timeout_seconds):
                    timed_out = True
                    timeout_reason = f"timeout after {int(hard_timeout_seconds)}s total runtime"
                    runtime._signal_process_tree(proc, force=True)
                elif inactivity_timeout_seconds <= 0:
                    pass
                elif quiet_long_running and (now - last_activity_at) > int(inactivity_timeout_seconds):
                    timed_out = True
                    timeout_reason = f"timeout after {int(inactivity_timeout_seconds)}s without CPU/IO activity"
                    runtime._signal_process_tree(proc, force=True)
                elif (not quiet_long_running) and (now - last_output_at) > int(inactivity_timeout_seconds):
                    timed_out = True
                    timeout_reason = f"timeout after {int(inactivity_timeout_seconds)}s without output"
                    runtime._signal_process_tree(proc, force=True)

            if proc.poll() is not None:
                if process_exited_at is None:
                    process_exited_at = now
                if reader_done.is_set() and output_queue.empty():
                    break
                if (now - process_exited_at) >= float(_PROCESS_READER_EXIT_GRACE_SECONDS):
                    try:
                        if proc.stdout is not None:
                            proc.stdout.close()
                    except Exception:
                        pass
                    while True:
                        try:
                            chunk = output_queue.get_nowait()
                        except queue.Empty:
                            break
                        output_parts.append(str(chunk))
                    output_parts.append(
                        "\n[notice] output stream did not close after process exit; forced completion\n"
                    )
                    break

            time.sleep(0.1)

        while True:
            try:
                chunk = output_queue.get_nowait()
            except queue.Empty:
                break
            output_parts.append(str(chunk))

        combined_output = "".join(output_parts)
        runtime_seconds = max(0.0, float((process_exited_at or time.monotonic()) - started_at))
        allowed_exit_codes = AppSettings.allowed_nonzero_exit_codes(str(tool_name or ""))
        if not timed_out and not killed and _was_killed_externally(proc.returncode):
            killed = True
        if timed_out:
            combined_output += f"\n[{timeout_reason}]"
            process_repo.storeProcessProblemStatus(str(process_id))
            process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
            process_repo.storeProcessOutput(str(process_id), combined_output)
            _persist_special_output(combined_output)
            return _build_result(False, f"failed: {timeout_reason}", int(process_id))

        if killed:
            process_repo.storeProcessKillStatus(str(process_id))
            process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
            process_repo.storeProcessOutput(str(process_id), combined_output)
            _persist_special_output(combined_output)
            return _build_result(False, "killed", int(process_id))

        if int(proc.returncode or 0) in allowed_exit_codes:
            try:
                process_repo.storeProcessProgress(
                    str(process_id),
                    percent="100",
                    estimated_remaining=None,
                )
            except Exception:
                pass
            process_repo.storeProcessOutput(str(process_id), combined_output)
            _persist_special_output(combined_output)
            return _build_result(True, f"completed (allowed exit {int(proc.returncode or 0)})", int(process_id))

        if int(proc.returncode or 0) != 0:
            _store_failure_status(_classify_nonzero_exit(proc.returncode, runtime_seconds))
            process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
            process_repo.storeProcessOutput(str(process_id), combined_output)
            _persist_special_output(combined_output)
            return _build_result(False, f"failed: exit {proc.returncode}", int(process_id))

        try:
            process_repo.storeProcessProgress(
                str(process_id),
                percent="100",
                estimated_remaining=None,
            )
        except Exception:
            pass

        process_repo.storeProcessOutput(str(process_id), combined_output)
        _persist_special_output(combined_output)
        return _build_result(True, "completed", int(process_id))
    except Exception as exc:
        process_repo.storeProcessProblemStatus(str(process_id))
        try:
            process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
        except Exception:
            pass
        process_repo.storeProcessOutput(str(process_id), f"[error] {exc}\n{''.join(output_parts)}")
        return _build_result(False, f"error: {exc}", int(process_id))
    finally:
        with runtime._process_runtime_lock:
            runtime._active_processes.pop(int(process_id), None)
            runtime._kill_requests.discard(int(process_id))
        runtime._unregister_job_process(int(process_id))
        runtime._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)


def write_process_output_partial(runtime, process_id: int, output_text: str):
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return
        runtime._ensure_process_tables()
        session = project.database.session()
        try:
            params = {"process_id": int(process_id), "output": str(output_text)}
            updated = session.execute(text(
                "UPDATE process_output SET output = :output WHERE processId = :process_id"
            ), params)
            if not int(getattr(updated, "rowcount", 0) or 0):
                session.execute(text(
                    "INSERT INTO process_output (processId, output) VALUES (:process_id, :output)"
                ), params)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()


def save_script_result_if_missing(runtime, host_ip: str, port: str, protocol: str, tool_id: str, process_id: int):
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return

        host = project.repositoryContainer.hostRepository.getHostByIP(str(host_ip))
        if not host:
            return

        port_obj = project.repositoryContainer.portRepository.getPortByHostIdAndPort(
            host.id,
            str(port),
            str(protocol or "tcp").lower(),
        )
        if not port_obj:
            return

        script_repo = project.repositoryContainer.scriptRepository
        for existing in script_repo.getScriptsByPortId(port_obj.id):
            if str(getattr(existing, "scriptId", "")) == str(tool_id):
                return

        output_text = str(runtime.get_process_output_text(int(process_id)) or "")

        session = project.database.session()
        try:
            row = l1ScriptObj(str(tool_id), output_text, str(port_obj.id), str(host.id))
            session.add(row)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()
