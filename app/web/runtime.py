import datetime
import json
import os
import queue
import re
import shlex
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests
from sqlalchemy import text

from app.cli_utils import import_targets_from_textfile, is_wsl, to_windows_path
from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.hostsfile import add_temporary_host_alias
from app.httputil.isHttps import isHttps
from app.importers.NmapImporter import NmapImporter
from app.nmap_enrichment import (
    infer_hostname_from_nmap_data,
    infer_os_from_service_inventory,
    infer_os_from_nmap_scripts,
    is_unknown_hostname,
    is_unknown_os_match,
)
from app.paths import get_legion_autosave_dir
from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    list_pending_approvals,
    queue_pending_approval,
    update_pending_approval,
)
from app.scheduler.audit import (
    ensure_scheduler_audit_table,
    log_scheduler_decision,
    update_scheduler_decision_for_approval,
)
from app.scheduler.insights import (
    delete_host_ai_state,
    ensure_scheduler_ai_state_table,
    get_host_ai_state,
    upsert_host_ai_state,
)
from app.scheduler.config import SchedulerConfigManager
from app.scheduler.planner import ScheduledAction, SchedulerPlanner
from app.scheduler.providers import get_provider_logs, test_provider_connection
from app.scheduler.risk import classify_command_danger
from app.settings import AppSettings, Settings
from app.timing import getTimestamp
from app.web.jobs import WebJobManager
from db.entities.cve import cve
from db.entities.host import hostObj
from db.entities.l1script import l1ScriptObj


class _WebProcessStub:
    def __init__(
            self,
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


_NMAP_PROGRESS_PERCENT_RE = re.compile(r"About\s+([0-9]+(?:\.[0-9]+)?)%\s+done", flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_PAREN_RE = re.compile(r"\(([^)]*?)\s+remaining\)", flags=re.IGNORECASE)
_NMAP_PROGRESS_PERCENT_ATTR_RE = re.compile(r'percent=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_ATTR_RE = re.compile(r'remaining=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_CPE22_TOKEN_RE = re.compile(r"\bcpe:/[aho]:[a-z0-9._:-]+\b", flags=re.IGNORECASE)
_CPE23_TOKEN_RE = re.compile(r"\bcpe:2\.3:[aho]:[a-z0-9._:-]+\b", flags=re.IGNORECASE)
_CVE_TOKEN_RE = re.compile(r"\bcve-\d{4}-\d+\b", flags=re.IGNORECASE)
_TECH_VERSION_RE = re.compile(r"\b(\d+(?:[._-][0-9a-z]+){0,4})\b", flags=re.IGNORECASE)
_IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_TECH_CPE_HINTS = (
    (("jetty",), "Jetty", "cpe:/a:eclipse:jetty"),
    (("traccar",), "Traccar", "cpe:/a:traccar:traccar"),
    (("pi-hole", "pihole", "pi.hole"), "Pi-hole", ""),
    (("openssh",), "OpenSSH", "cpe:/a:openbsd:openssh"),
    (("nginx",), "nginx", "cpe:/a:nginx:nginx"),
    (("apache http server", "apache httpd"), "Apache HTTP Server", "cpe:/a:apache:http_server"),
    (("apache",), "Apache HTTP Server", "cpe:/a:apache:http_server"),
    (("microsoft-iis", "microsoft iis", " iis "), "Microsoft IIS", "cpe:/a:microsoft:iis"),
    (("node.js", "nodejs", "node js"), "Node.js", "cpe:/a:nodejs:node.js"),
    (("php",), "PHP", "cpe:/a:php:php"),
)
_WEAK_TECH_NAME_TOKENS = {
    "domain",
    "webdav",
    "commplex-link",
    "rfe",
    "filemaker",
    "avt-profile-1",
    "airport-admin",
    "surfpass",
    "jtnetd-server",
    "mmcc",
    "ida-agent",
    "rlm-admin",
    "sip",
    "sip-tls",
    "onscreen",
    "biotic",
    "admd",
    "admdog",
    "admeng",
    "barracuda-bbs",
    "targus-getdata",
    "3exmp",
    "xmpp-client",
    "hp-server",
    "hp-status",
}
_TECH_STRONG_EVIDENCE_MARKERS = (
    "ssh banner",
    "service ",
    "whatweb",
    "http-title",
    "ssl-cert",
    "nuclei",
    "nmap",
    "fingerprint",
    "output cpe",
    "server header",
)
_GENERIC_TECH_NAME_TOKENS = {
    "unknown",
    "generic",
    "service",
    "tcpwrapped",
    "http",
    "https",
    "ssl",
    "ssh",
    "smtp",
    "imap",
    "pop3",
    "domain",
    "msrpc",
    "rpc",
    "vmrdp",
    "rdp",
    "vnc",
}
_SCHEDULER_ONLY_LABELS = {
    "screenshooter": "Capture web screenshot",
}
_DEFAULT_AI_FEEDBACK_CONFIG = {
    "enabled": True,
    "max_rounds_per_target": 4,
    "max_actions_per_round": 4,
    "recent_output_chars": 900,
}
_DIG_DEEPER_MAX_RUNTIME_SECONDS = 900
_DIG_DEEPER_MAX_TOTAL_ACTIONS = 24
_DIG_DEEPER_TASK_TIMEOUT_SECONDS = 180
_PROCESS_READER_EXIT_GRACE_SECONDS = 2.0
_AI_HOST_UPDATE_MIN_CONFIDENCE = 70.0


class WebRuntime:
    def __init__(self, logic):
        self.logic = logic
        self.scheduler_config = SchedulerConfigManager()
        self.scheduler_planner = SchedulerPlanner(self.scheduler_config)
        self.settings_file = AppSettings()
        self.settings = Settings(self.settings_file)
        scheduler_preferences = self.scheduler_config.load()
        job_workers = self._job_worker_count(scheduler_preferences)
        job_max = self._scheduler_max_jobs(scheduler_preferences)
        self.jobs = WebJobManager(max_jobs=job_max, worker_count=job_workers)
        self._lock = threading.RLock()
        self._process_runtime_lock = threading.Lock()
        self._active_processes: Dict[int, subprocess.Popen] = {}
        self._kill_requests: set[int] = set()
        self._job_process_ids: Dict[int, set] = {}
        self._process_job_id: Dict[int, int] = {}
        self._save_in_progress = False
        self._autosave_lock = threading.Lock()
        self._autosave_next_due_monotonic = 0.0
        self._autosave_last_job_id = 0
        self._autosave_last_saved_at = ""
        self._autosave_last_path = ""
        self._autosave_last_error = ""

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self._maybe_schedule_autosave_locked()
            tools_page = self.get_workspace_tools_page(limit=300, offset=0)
            return {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "project": self._project_metadata(),
                "summary": self._summary(),
                "hosts": self._hosts(limit=100),
                "processes": self._processes(limit=75),
                "services": self.get_workspace_services(limit=40),
                "tools": tools_page.get("tools", []),
                "tools_meta": {
                    "offset": int(tools_page.get("offset", 0) or 0),
                    "limit": int(tools_page.get("limit", 0) or 0),
                    "total": int(tools_page.get("total", 0) or 0),
                    "has_more": bool(tools_page.get("has_more", False)),
                    "next_offset": tools_page.get("next_offset"),
                },
                "scheduler": self._scheduler_preferences(),
                "scheduler_decisions": self.get_scheduler_decisions(limit=80),
                "scheduler_approvals": self.get_scheduler_approvals(limit=40, status="pending"),
                "jobs": self.jobs.list_jobs(limit=20),
            }

    def get_scheduler_preferences(self) -> Dict[str, Any]:
        with self._lock:
            return self._scheduler_preferences()

    def apply_scheduler_preferences(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            normalized = dict(updates or {})
            saved = self.scheduler_config.update_preferences(normalized)
        requested_workers = self._job_worker_count(saved)
        requested_max_jobs = self._scheduler_max_jobs(saved)
        try:
            self.jobs.ensure_worker_count(requested_workers)
        except Exception:
            pass
        try:
            self.jobs.ensure_max_jobs(requested_max_jobs)
        except Exception:
            pass
        return self.get_scheduler_preferences()

    def test_scheduler_provider(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            merged = self.scheduler_config.merge_preferences(updates or {})
        return test_provider_connection(merged)

    def get_scheduler_provider_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            _ = self._require_active_project()
        return get_provider_logs(limit=limit)

    def get_scheduler_decisions(self, limit: int = 80) -> List[Dict[str, Any]]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return []

            ensure_scheduler_audit_table(project.database)
            session = project.database.session()
            try:
                result = session.execute(text(
                    "SELECT id, timestamp, host_ip, port, protocol, service, scheduler_mode, goal_profile, "
                    "tool_id, label, command_family_id, danger_categories, requires_approval, approved, "
                    "executed, reason, rationale, approval_id "
                    "FROM scheduler_decision_log ORDER BY id DESC LIMIT :limit"
                ), {"limit": int(limit)})
                rows = result.fetchall()
                keys = result.keys()
                return [dict(zip(keys, row)) for row in rows]
            except Exception:
                return []
            finally:
                session.close()

    def get_scheduler_approvals(self, limit: int = 200, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_approval_table(project.database)
            return list_pending_approvals(project.database, limit=limit, status=status)

    def approve_scheduler_approval(self, approval_id: int, approve_family: bool = False, run_now: bool = True):
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_approval_table(project.database)
            item = get_pending_approval(project.database, int(approval_id))
            if item is None:
                raise KeyError(f"Unknown approval id: {approval_id}")
            if str(item.get("status", "")).strip().lower() not in {"pending", "approved"}:
                return {"approval": item, "job": None}

            if approve_family:
                self.scheduler_config.approve_family(
                    str(item.get("command_family_id", "")),
                    {
                        "tool_id": str(item.get("tool_id", "")),
                        "label": str(item.get("label", "")),
                        "danger_categories": self._split_csv(str(item.get("danger_categories", ""))),
                    }
                )

            updated = update_pending_approval(
                project.database,
                int(approval_id),
                status="approved",
                decision_reason="approved via web",
            )
            update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=True,
                executed=False,
                reason="approved",
            )

        if not run_now:
            return {"approval": updated, "job": None}

        job = self._start_job(
            "scheduler-approval-execute",
            lambda job_id: self._execute_approved_scheduler_item(int(approval_id), job_id=job_id),
            payload={"approval_id": int(approval_id), "approve_family": bool(approve_family)},
        )
        with self._lock:
            project = self._require_active_project()
            final_state = update_pending_approval(
                project.database,
                int(approval_id),
                status="approved",
                decision_reason="approved & queued",
                execution_job_id=str(job.get("id", "")),
            )
            update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=True,
                executed=False,
                reason="approved & queued",
            )
        return {"approval": final_state, "job": job}

    def reject_scheduler_approval(self, approval_id: int, reason: str = "rejected via web"):
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_approval_table(project.database)
            item = get_pending_approval(project.database, int(approval_id))
            if item is None:
                raise KeyError(f"Unknown approval id: {approval_id}")
            updated = update_pending_approval(
                project.database,
                int(approval_id),
                status="rejected",
                decision_reason=str(reason or "rejected via web"),
            )
            return updated

    def get_project_details(self) -> Dict[str, Any]:
        with self._lock:
            metadata = self._project_metadata()
            metadata["is_temporary"] = self._is_temp_project()
            return metadata

    def _start_job(
            self,
            job_type: str,
            runner_with_job_id,
            *,
            payload: Optional[Dict[str, Any]] = None,
            queue_front: bool = False,
            exclusive: bool = False,
    ) -> Dict[str, Any]:
        if not callable(runner_with_job_id):
            raise ValueError("runner_with_job_id must be callable.")

        job_ref = {"id": 0}

        def _wrapped_runner():
            return runner_with_job_id(int(job_ref.get("id", 0) or 0)) or {}

        job = self.jobs.start(
            str(job_type),
            _wrapped_runner,
            payload=dict(payload or {}),
            queue_front=bool(queue_front),
            exclusive=bool(exclusive),
        )
        job_ref["id"] = int(job.get("id", 0) or 0)
        return job

    def _register_job_process(self, job_id: int, process_id: int):
        resolved_job_id = int(job_id or 0)
        resolved_process_id = int(process_id or 0)
        if resolved_job_id <= 0 or resolved_process_id <= 0:
            return
        if not hasattr(self, "_job_process_ids"):
            self._job_process_ids = {}
        if not hasattr(self, "_process_job_id"):
            self._process_job_id = {}
        with self._process_runtime_lock:
            process_ids = self._job_process_ids.setdefault(resolved_job_id, set())
            process_ids.add(resolved_process_id)
            self._process_job_id[resolved_process_id] = resolved_job_id

    def _unregister_job_process(self, process_id: int):
        resolved_process_id = int(process_id or 0)
        if resolved_process_id <= 0:
            return
        if not hasattr(self, "_job_process_ids") or not hasattr(self, "_process_job_id"):
            return
        with self._process_runtime_lock:
            owner_job_id = self._process_job_id.pop(resolved_process_id, None)
            if owner_job_id is None:
                return
            process_ids = self._job_process_ids.get(int(owner_job_id))
            if not process_ids:
                return
            process_ids.discard(resolved_process_id)
            if not process_ids:
                self._job_process_ids.pop(int(owner_job_id), None)

    def _job_active_process_ids(self, job_id: int) -> List[int]:
        resolved_job_id = int(job_id or 0)
        if resolved_job_id <= 0:
            return []
        if not hasattr(self, "_job_process_ids"):
            return []
        with self._process_runtime_lock:
            process_ids = list(self._job_process_ids.get(resolved_job_id, set()))
        return sorted({int(item) for item in process_ids if int(item) > 0})

    def create_new_temporary_project(self) -> Dict[str, Any]:
        with self._lock:
            if self._save_in_progress:
                raise RuntimeError("Project save is in progress. Try again when it finishes.")
            active_jobs = self._count_running_scan_jobs(include_queued=True)
            if active_jobs > 0 or len(self._active_processes) > 0:
                raise RuntimeError(
                    "Cannot create a new project while jobs/scans are active. "
                    "Stop running jobs first."
                )
            self._close_active_project()
            self.logic.createNewTemporaryProject()
            self._ensure_scheduler_table()
            self._ensure_scheduler_approval_store()
            self._ensure_process_tables()
            return self.get_project_details()

    def open_project(self, path: str) -> Dict[str, Any]:
        project_path = self._normalize_project_path(path)
        if not os.path.isfile(project_path):
            raise FileNotFoundError(f"Project file not found: {project_path}")

        with self._lock:
            if self._save_in_progress:
                raise RuntimeError("Project save is in progress. Try again when it finishes.")
            active_jobs = self._count_running_scan_jobs(include_queued=True)
            if active_jobs > 0 or len(self._active_processes) > 0:
                raise RuntimeError(
                    "Cannot open a project while jobs/scans are active. "
                    "Stop running jobs first."
                )
            self._close_active_project()
            self.logic.openExistingProject(project_path, projectType="legion")
            self._ensure_scheduler_table()
            self._ensure_scheduler_approval_store()
            self._ensure_process_tables()
            return self.get_project_details()

    def start_save_project_as_job(self, path: str, replace: bool = True) -> Dict[str, Any]:
        project_path = self._normalize_project_path(path)
        return self._start_job(
            "project-save-as",
            lambda _job_id: self._save_project_as(project_path, bool(replace)),
            payload={"path": project_path, "replace": bool(replace)},
            queue_front=True,
            exclusive=True,
        )

    def save_project_as(self, path: str, replace: bool = True) -> Dict[str, Any]:
        # Backward-compatible synchronous entrypoint.
        project_path = self._normalize_project_path(path)
        return self._save_project_as(project_path, bool(replace))

    def build_project_bundle_zip(self) -> Tuple[str, str]:
        with self._lock:
            project = self._require_active_project()
            props = project.properties
            project_file = str(getattr(props, "projectName", "") or "")
            output_folder = str(getattr(props, "outputFolder", "") or "")
            running_folder = str(getattr(props, "runningFolder", "") or "")

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        bundle_name = f"legion-session-{timestamp}.zip"
        root_name = f"legion-session-{timestamp}"
        tmp = tempfile.NamedTemporaryFile(prefix="legion-session-", suffix=".zip", delete=False)
        bundle_path = tmp.name
        tmp.close()

        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            manifest = {
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "project_file": project_file,
                "output_folder": output_folder,
                "running_folder": running_folder,
            }
            archive.writestr(
                f"{root_name}/manifest.json",
                json.dumps(manifest, indent=2, sort_keys=True),
            )
            self._zip_add_file_if_exists(
                archive,
                project_file,
                f"{root_name}/session/{os.path.basename(project_file or 'session.legion')}",
            )
            self._zip_add_dir_if_exists(archive, output_folder, f"{root_name}/tool-output")
            self._zip_add_dir_if_exists(archive, running_folder, f"{root_name}/running")

        return bundle_path, bundle_name

    def start_restore_project_zip_job(self, path: str) -> Dict[str, Any]:
        zip_path = self._normalize_existing_file(path)
        return self._start_job(
            "project-restore-zip",
            lambda _job_id: self._restore_project_bundle_zip_job(zip_path, cleanup_source=True),
            payload={"path": zip_path},
            queue_front=True,
            exclusive=True,
        )

    def restore_project_bundle_zip(self, path: str) -> Dict[str, Any]:
        zip_path = self._normalize_existing_file(path)
        return self._restore_project_bundle_zip_job(zip_path, cleanup_source=False)

    def _restore_project_bundle_zip_job(self, zip_path: str, cleanup_source: bool) -> Dict[str, Any]:
        normalized = self._normalize_existing_file(zip_path)
        try:
            return self._restore_project_bundle_zip(normalized)
        finally:
            if cleanup_source:
                try:
                    if os.path.isfile(normalized):
                        os.remove(normalized)
                except Exception:
                    pass

    def _restore_project_bundle_zip(self, zip_path: str) -> Dict[str, Any]:
        normalized = self._normalize_existing_file(zip_path)
        if not zipfile.is_zipfile(normalized):
            raise ValueError(f"Invalid ZIP file: {normalized}")

        with zipfile.ZipFile(normalized, "r") as archive:
            manifest_name, root_prefix, manifest = self._read_bundle_manifest(archive)
            _ = manifest_name

            session_member = self._locate_bundle_session_member(
                archive,
                root_prefix=root_prefix,
                manifest=manifest,
            )
            if not session_member:
                raise ValueError("Bundle does not contain a session .legion file.")

            project_file_name = self._safe_bundle_filename(
                os.path.basename(str(session_member or "").strip()),
                fallback="restored.legion",
            )
            if not project_file_name.lower().endswith(".legion"):
                project_file_name = f"{project_file_name}.legion"
            project_stem = os.path.splitext(project_file_name)[0]

            restore_root = tempfile.mkdtemp(prefix="legion-restore-")
            project_path = os.path.join(restore_root, project_file_name)
            output_folder = os.path.join(restore_root, f"{project_stem}-tool-output")
            running_folder = os.path.join(restore_root, f"{project_stem}-running")

            os.makedirs(output_folder, exist_ok=True)
            os.makedirs(running_folder, exist_ok=True)

            self._extract_zip_member_to_file(archive, session_member, project_path)
            self._extract_zip_prefix_to_dir(
                archive,
                prefix=self._bundle_prefix(root_prefix, "tool-output"),
                destination_dir=output_folder,
            )
            self._extract_zip_prefix_to_dir(
                archive,
                prefix=self._bundle_prefix(root_prefix, "running"),
                destination_dir=running_folder,
            )

        with self._lock:
            if self._save_in_progress:
                raise RuntimeError("Project save is in progress. Try again when it finishes.")
            self._close_active_project()
            self.logic.openExistingProject(project_path, projectType="legion")
            self._ensure_scheduler_table()
            self._ensure_scheduler_approval_store()
            self._ensure_process_tables()
            details = self.get_project_details()

        return {
            "project": details,
            "restored": {
                "restore_root": restore_root,
                "project_path": project_path,
                "output_folder": output_folder,
                "running_folder": running_folder,
                "manifest_project_file": str(manifest.get("project_file", "") or ""),
            },
        }

    def _save_project_as(self, project_path: str, replace: bool = True) -> Dict[str, Any]:
        source_project = None
        with self._lock:
            if self._save_in_progress:
                raise RuntimeError("Project save is already in progress.")
            source_project = self._require_active_project()
            running_count = self._count_running_or_waiting_processes(source_project)
            active_subprocess_count = len(self._active_processes)
            active_jobs = self._count_running_scan_jobs(include_queued=False)
            if running_count > 0 or active_subprocess_count > 0 or active_jobs > 0:
                raise RuntimeError(
                    "Cannot save while scans/tools are still active "
                    f"(process-table={running_count}, subprocesses={active_subprocess_count}, jobs={active_jobs}). "
                    "Wait for completion or stop active scans first."
                )
            self._save_in_progress = True

        try:
            saved_project = self.logic.projectManager.saveProjectAs(
                source_project,
                project_path,
                replace=1 if replace else 0,
                projectType="legion",
            )
            if not saved_project:
                raise RuntimeError("Save operation did not complete.")

            with self._lock:
                self.logic.activeProject = saved_project
                self._ensure_scheduler_table()
                self._ensure_scheduler_approval_store()
                self._ensure_process_tables()
                details = self.get_project_details()
            return {"project": details}
        finally:
            with self._lock:
                self._save_in_progress = False

    def _count_running_scan_jobs(self, include_queued: bool = True) -> int:
        running_types = {
            "nmap-scan",
            "import-nmap-xml",
            "scheduler-run",
            "scheduler-approval-execute",
            "scheduler-dig-deeper",
            "tool-run",
            "import-targets",
            "process-retry",
        }
        jobs = self.jobs.list_jobs(limit=200)
        count = 0
        for job in jobs:
            status = str(job.get("status", "") or "").strip().lower()
            valid_statuses = {"running"}
            if include_queued:
                valid_statuses.add("queued")
            if status not in valid_statuses:
                continue
            job_type = str(job.get("type", "") or "").strip()
            if job_type in running_types:
                count += 1
        return count

    def _has_running_autosave_job(self) -> bool:
        jobs = self.jobs.list_jobs(limit=80)
        for job in jobs:
            if str(job.get("type", "") or "") != "project-autosave":
                continue
            status = str(job.get("status", "") or "").strip().lower()
            if status in {"queued", "running"}:
                return True
        return False

    def _get_autosave_interval_seconds(self) -> int:
        raw = getattr(self.settings, "general_notes_autosave_minutes", "2")
        try:
            minutes = float(str(raw).strip())
        except (TypeError, ValueError):
            minutes = 2.0
        if minutes <= 0:
            return 0
        return max(30, int(minutes * 60))

    def _resolve_autosave_target_path(self, project) -> str:
        project_name = str(getattr(project.properties, "projectName", "") or "").strip()
        if not project_name:
            return ""

        base_name = os.path.basename(project_name)
        stem, ext = os.path.splitext(base_name)
        if not ext:
            ext = ".legion"
        autosave_name = f"{stem}.autosave{ext}"

        if bool(getattr(project.properties, "isTemporary", False)):
            autosave_dir = get_legion_autosave_dir()
            os.makedirs(autosave_dir, exist_ok=True)
            return os.path.join(autosave_dir, autosave_name)

        folder = os.path.dirname(project_name) or os.getcwd()
        return os.path.join(folder, autosave_name)

    def _run_project_autosave(self, target_path: str) -> Dict[str, Any]:
        if not target_path:
            return {"saved": False, "reason": "autosave target path missing"}

        with self._autosave_lock:
            with self._lock:
                if self._save_in_progress:
                    return {"saved": False, "reason": "save already in progress"}
                project = getattr(self.logic, "activeProject", None)
                if not project:
                    return {"saved": False, "reason": "no active project"}
                if self._count_running_or_waiting_processes(project) > 0 or len(self._active_processes) > 0:
                    return {"saved": False, "reason": "active scans/tools running"}
                self._save_in_progress = True

            try:
                project.database.verify_integrity()
                project.database.backup_to(str(target_path))
                saved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                with self._lock:
                    self._autosave_last_saved_at = saved_at
                    self._autosave_last_path = str(target_path)
                    self._autosave_last_error = ""
                return {
                    "saved": True,
                    "saved_at": saved_at,
                    "path": str(target_path),
                }
            except Exception as exc:
                with self._lock:
                    self._autosave_last_error = str(exc)
                return {
                    "saved": False,
                    "reason": str(exc),
                    "path": str(target_path),
                }
            finally:
                with self._lock:
                    self._save_in_progress = False

    def _maybe_schedule_autosave_locked(self):
        project = getattr(self.logic, "activeProject", None)
        if not project:
            self._autosave_next_due_monotonic = 0.0
            return

        interval_seconds = self._get_autosave_interval_seconds()
        if interval_seconds <= 0:
            self._autosave_next_due_monotonic = 0.0
            return

        now = time.monotonic()
        if self._autosave_next_due_monotonic <= 0.0:
            self._autosave_next_due_monotonic = now + float(interval_seconds)
            return
        if now < self._autosave_next_due_monotonic:
            return
        if self._save_in_progress or self._has_running_autosave_job():
            self._autosave_next_due_monotonic = now + 20.0
            return
        if self._count_running_scan_jobs() > 0:
            self._autosave_next_due_monotonic = now + 30.0
            return
        if self._count_running_or_waiting_processes(project) > 0 or len(self._active_processes) > 0:
            self._autosave_next_due_monotonic = now + 30.0
            return

        target_path = self._resolve_autosave_target_path(project)
        if not target_path:
            self._autosave_next_due_monotonic = now + float(interval_seconds)
            return

        job = self._start_job(
            "project-autosave",
            lambda _job_id: self._run_project_autosave(target_path),
            payload={"path": str(target_path)},
            exclusive=True,
        )
        self._autosave_last_job_id = int(job.get("id", 0) or 0)
        self._autosave_next_due_monotonic = now + float(interval_seconds)

    def start_targets_import_job(self, path: str) -> Dict[str, Any]:
        file_path = self._normalize_existing_file(path)
        return self._start_job(
            "import-targets",
            lambda _job_id: self._import_targets_from_file(file_path),
            payload={"path": file_path},
        )

    def start_nmap_xml_import_job(self, path: str, run_actions: bool = False) -> Dict[str, Any]:
        xml_path = self._normalize_existing_file(path)
        return self._start_job(
            "import-nmap-xml",
            lambda _job_id: self._import_nmap_xml(xml_path, bool(run_actions)),
            payload={"path": xml_path, "run_actions": bool(run_actions)},
        )

    def start_nmap_scan_job(
            self,
            targets,
            discovery: bool = True,
            staged: bool = False,
            run_actions: bool = False,
            nmap_path: str = "nmap",
            nmap_args: str = "",
            scan_mode: str = "legacy",
            scan_options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized_targets = self._normalize_targets(targets)
        resolved_nmap_path = str(nmap_path or "nmap").strip() or "nmap"
        resolved_nmap_args = str(nmap_args or "").strip()
        resolved_scan_mode = str(scan_mode or "legacy").strip().lower() or "legacy"
        resolved_scan_options = dict(scan_options or {})
        payload = {
            "targets": normalized_targets,
            "discovery": bool(discovery),
            "staged": bool(staged),
            "run_actions": bool(run_actions),
            "nmap_path": resolved_nmap_path,
            "nmap_args": resolved_nmap_args,
            "scan_mode": resolved_scan_mode,
            "scan_options": resolved_scan_options,
        }
        return self._start_job(
            "nmap-scan",
            lambda job_id: self._run_nmap_scan_and_import(
                normalized_targets,
                discovery=bool(discovery),
                staged=bool(staged),
                run_actions=bool(run_actions),
                nmap_path=resolved_nmap_path,
                nmap_args=resolved_nmap_args,
                scan_mode=resolved_scan_mode,
                scan_options=resolved_scan_options,
                job_id=int(job_id or 0),
            ),
            payload=payload,
        )

    def start_scheduler_run_job(self) -> Dict[str, Any]:
        return self._start_job(
            "scheduler-run",
            lambda job_id: self._run_scheduler_actions_web(job_id=int(job_id or 0)),
            payload={},
        )

    def start_host_rescan_job(self, host_id: int) -> Dict[str, Any]:
        with self._lock:
            host = self._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")

        default_scan_options = {
            "discovery": True,
            "skip_dns": True,
            "timing": "T3",
            "top_ports": 1000,
            "service_detection": True,
            "default_scripts": True,
            "os_detection": False,
            "aggressive": False,
            "full_ports": False,
            "vuln_scripts": False,
            "host_discovery_only": False,
            "arp_ping": False,
        }
        return self.start_nmap_scan_job(
            targets=[host_ip],
            discovery=True,
            staged=False,
            run_actions=False,
            nmap_path="nmap",
            nmap_args="",
            scan_mode="easy",
            scan_options=default_scan_options,
        )

    def start_host_dig_deeper_job(self, host_id: int) -> Dict[str, Any]:
        with self._lock:
            host = self._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")

            prefs = self.scheduler_config.load()
            scheduler_mode = str(prefs.get("mode", "deterministic") or "deterministic").strip().lower()
            if scheduler_mode != "ai":
                raise ValueError("Dig Deeper requires scheduler mode 'ai'.")

            provider_name = str(prefs.get("provider", "none") or "none").strip().lower()
            providers = prefs.get("providers", {}) if isinstance(prefs.get("providers", {}), dict) else {}
            provider_cfg = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
            provider_enabled = bool(provider_cfg.get("enabled", False)) if isinstance(provider_cfg, dict) else False
            if provider_name == "none" or not provider_enabled:
                raise ValueError("Dig Deeper requires an enabled AI provider.")

            existing = self._find_active_job(job_type="scheduler-dig-deeper", host_id=int(host_id))
            if existing is not None:
                existing_copy = dict(existing)
                existing_copy["existing"] = True
                return existing_copy

        return self._start_job(
            "scheduler-dig-deeper",
            lambda job_id: self._run_scheduler_actions_web(
                host_ids={int(host_id)},
                dig_deeper=True,
                job_id=int(job_id or 0),
            ),
            payload={"host_id": int(host_id), "host_ip": host_ip, "dig_deeper": True},
        )

    def _find_active_job(self, *, job_type: str, host_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        for job in self.jobs.list_jobs(limit=200):
            if str(job.get("type", "")).strip() != str(job_type or "").strip():
                continue
            status = str(job.get("status", "")).strip().lower()
            if status not in {"queued", "running"}:
                continue
            if host_id is None:
                return job
            payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
            try:
                payload_host_id = int(payload.get("host_id", 0) or 0)
            except (TypeError, ValueError):
                payload_host_id = 0
            if payload_host_id == int(host_id):
                return job
        return None

    def start_tool_run_job(
            self,
            host_ip: str,
            port: str,
            protocol: str,
            tool_id: str,
            command_override: str = "",
            timeout: int = 300,
    ) -> Dict[str, Any]:
        resolved_host_ip = str(host_ip or "").strip()
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        resolved_tool_id = str(tool_id or "").strip()
        if not resolved_host_ip or not resolved_port or not resolved_tool_id:
            raise ValueError("host_ip, port and tool_id are required.")

        payload = {
            "host_ip": resolved_host_ip,
            "port": resolved_port,
            "protocol": resolved_protocol,
            "tool_id": resolved_tool_id,
            "timeout": int(timeout),
        }
        if command_override:
            payload["command_override"] = str(command_override)

        return self._start_job(
            "tool-run",
            lambda job_id: self._run_manual_tool(
                host_ip=resolved_host_ip,
                port=resolved_port,
                protocol=resolved_protocol,
                tool_id=resolved_tool_id,
                command_override=str(command_override or ""),
                timeout=int(timeout),
                job_id=int(job_id or 0),
            ),
            payload=payload,
        )

    def get_workspace_hosts(self, limit: int = 400) -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            repo_container = project.repositoryContainer
            host_repo = repo_container.hostRepository
            port_repo = repo_container.portRepository
            hosts = host_repo.getAllHostObjs()[:max(1, min(int(limit), 2000))]
            rows = []
            for host in hosts:
                ports = port_repo.getPortsByHostId(host.id)
                open_ports = [p for p in ports if str(getattr(p, "state", "")) in {"open", "open|filtered"}]
                rows.append({
                    "id": int(host.id),
                    "ip": str(getattr(host, "ip", "") or ""),
                    "hostname": str(getattr(host, "hostname", "") or ""),
                    "status": str(getattr(host, "status", "") or ""),
                    "os": str(getattr(host, "osMatch", "") or ""),
                    "open_ports": len(open_ports),
                    "total_ports": len(ports),
                })
            return rows

    def get_workspace_services(self, limit: int = 300) -> List[Dict[str, Any]]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return []
            session = project.database.session()
            try:
                result = session.execute(text(
                    "SELECT COALESCE(services.name, 'unknown') AS service, "
                    "COUNT(*) AS port_count, "
                    "COUNT(DISTINCT hosts.ip) AS host_count, "
                    "GROUP_CONCAT(DISTINCT ports.protocol) AS protocols "
                    "FROM portObj AS ports "
                    "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                    "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId "
                    "WHERE ports.state IN ('open', 'open|filtered') "
                    "GROUP BY COALESCE(services.name, 'unknown') "
                    "ORDER BY host_count DESC, port_count DESC, service ASC "
                    "LIMIT :limit"
                ), {"limit": max(1, min(int(limit), 2000))})
                rows = result.fetchall()
                keys = result.keys()
                data = [dict(zip(keys, row)) for row in rows]
                for row in data:
                    protocols = str(row.get("protocols", "") or "")
                    row["protocols"] = [item for item in protocols.split(",") if item]
                return data
            finally:
                session.close()

    def _workspace_tools_rows(self, service: str = "") -> List[Dict[str, Any]]:
        with self._lock:
            settings = self._get_settings()
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return []

            normalized_service = str(service or "").strip().rstrip("?").lower()
            run_stats = self._tool_run_stats(project)
            dangerous_categories = self.scheduler_config.get_dangerous_categories()
            rows = []
            seen_tool_ids = set()

            def _service_matches_scope(service_scope: List[str]) -> bool:
                if not normalized_service:
                    return True
                if not service_scope:
                    return True
                lowered = {item.lower() for item in service_scope}
                return "*" in lowered or normalized_service in lowered

            for action in settings.portActions:
                label = str(action[0])
                tool_id = str(action[1])
                command_template = str(action[2])
                service_scope = self._split_csv(str(action[3] if len(action) > 3 else ""))

                if not _service_matches_scope(service_scope):
                    continue

                stats = run_stats.get(tool_id, {})
                rows.append({
                    "label": label,
                    "tool_id": tool_id,
                    "command_template": command_template,
                    "service_scope": service_scope,
                    "danger_categories": classify_command_danger(command_template, dangerous_categories),
                    "run_count": int(stats.get("run_count", 0) or 0),
                    "last_status": str(stats.get("last_status", "") or ""),
                    "last_start": str(stats.get("last_start", "") or ""),
                    "runnable": True,
                })
                seen_tool_ids.add(tool_id)

            # Show scheduler-only tool ids (for example screenshooter) in the Tools table
            # so the catalog reflects what the scheduler can run.
            for automated in settings.automatedAttacks:
                tool_id = str(automated[0] if len(automated) > 0 else "").strip()
                if not tool_id or tool_id in seen_tool_ids:
                    continue
                service_scope = self._split_csv(str(automated[1] if len(automated) > 1 else ""))
                if not _service_matches_scope(service_scope):
                    continue

                stats = run_stats.get(tool_id, {})
                rows.append({
                    "label": _SCHEDULER_ONLY_LABELS.get(tool_id, tool_id),
                    "tool_id": tool_id,
                    "command_template": "",
                    "service_scope": service_scope,
                    "danger_categories": [],
                    "run_count": int(stats.get("run_count", 0) or 0),
                    "last_status": str(stats.get("last_status", "") or ""),
                    "last_start": str(stats.get("last_start", "") or ""),
                    "runnable": False,
                })
                seen_tool_ids.add(tool_id)

            rows.sort(key=lambda item: item["label"].lower())
            return rows

    def get_workspace_tools_page(
            self,
            service: str = "",
            limit: int = 300,
            offset: int = 0,
    ) -> Dict[str, Any]:
        rows = self._workspace_tools_rows(service=service)
        total = len(rows)
        try:
            resolved_limit = int(limit)
        except (TypeError, ValueError):
            resolved_limit = 300
        try:
            resolved_offset = int(offset)
        except (TypeError, ValueError):
            resolved_offset = 0

        resolved_limit = max(1, min(resolved_limit, 500))
        resolved_offset = max(0, min(resolved_offset, total))
        page_rows = rows[resolved_offset:resolved_offset + resolved_limit]
        next_offset = resolved_offset + len(page_rows)
        has_more = next_offset < total
        return {
            "tools": page_rows,
            "offset": resolved_offset,
            "limit": resolved_limit,
            "total": total,
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
        }

    def get_workspace_tools(self, service: str = "", limit: int = 300, offset: int = 0) -> List[Dict[str, Any]]:
        return self.get_workspace_tools_page(service=service, limit=limit, offset=offset).get("tools", [])

    def get_host_workspace(self, host_id: int) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")

            repo_container = project.repositoryContainer
            port_repo = repo_container.portRepository
            service_repo = repo_container.serviceRepository
            script_repo = repo_container.scriptRepository
            note_repo = repo_container.noteRepository

            note_obj = note_repo.getNoteByHostId(host.id)
            note_text = str(getattr(note_obj, "text", "") or "")

            ports_data = []
            for port in port_repo.getPortsByHostId(host.id):
                service_obj = None
                if getattr(port, "serviceId", None):
                    service_obj = service_repo.getServiceById(getattr(port, "serviceId", None))

                scripts = []
                for script in script_repo.getScriptsByPortId(port.id):
                    scripts.append({
                        "id": int(getattr(script, "id", 0) or 0),
                        "script_id": str(getattr(script, "scriptId", "") or ""),
                        "output": str(getattr(script, "output", "") or ""),
                    })

                ports_data.append({
                    "id": int(getattr(port, "id", 0) or 0),
                    "port": str(getattr(port, "portId", "") or ""),
                    "protocol": str(getattr(port, "protocol", "") or ""),
                    "state": str(getattr(port, "state", "") or ""),
                    "service": {
                        "id": int(getattr(service_obj, "id", 0) or 0) if service_obj else 0,
                        "name": str(getattr(service_obj, "name", "") or "") if service_obj else "",
                        "product": str(getattr(service_obj, "product", "") or "") if service_obj else "",
                        "version": str(getattr(service_obj, "version", "") or "") if service_obj else "",
                        "extrainfo": str(getattr(service_obj, "extrainfo", "") or "") if service_obj else "",
                    },
                    "scripts": scripts,
                })

            cves = self._load_cves_for_host(project, int(host.id))
            screenshots = self._list_screenshots_for_host(project, str(getattr(host, "ip", "") or ""))
            ai_analysis = self._load_host_ai_analysis(project, int(host.id), str(getattr(host, "ip", "") or ""))

            return {
                "host": {
                    "id": int(host.id),
                    "ip": str(getattr(host, "ip", "") or ""),
                    "hostname": str(getattr(host, "hostname", "") or ""),
                    "status": str(getattr(host, "status", "") or ""),
                    "os": str(getattr(host, "osMatch", "") or ""),
                },
                "note": note_text,
                "ports": ports_data,
                "cves": cves,
                "screenshots": screenshots,
                "ai_analysis": ai_analysis,
            }

    def get_host_ai_report(self, host_id: int) -> Dict[str, Any]:
        details = self.get_host_workspace(int(host_id))
        host = details.get("host", {}) if isinstance(details.get("host", {}), dict) else {}
        ports = details.get("ports", []) if isinstance(details.get("ports", []), list) else []
        cves = details.get("cves", []) if isinstance(details.get("cves", []), list) else []
        screenshots = details.get("screenshots", []) if isinstance(details.get("screenshots", []), list) else []
        ai_analysis = details.get("ai_analysis", {}) if isinstance(details.get("ai_analysis", {}), dict) else {}

        port_rows = []
        for item in ports:
            if not isinstance(item, dict):
                continue
            service = item.get("service", {}) if isinstance(item.get("service", {}), dict) else {}
            scripts = item.get("scripts", []) if isinstance(item.get("scripts", []), list) else []
            script_rows = []
            banner = ""
            for script in scripts:
                if not isinstance(script, dict):
                    continue
                script_id = str(script.get("script_id", "")).strip()
                output_excerpt = self._truncate_scheduler_text(script.get("output", ""), 280)
                script_rows.append({
                    "script_id": script_id,
                    "output_excerpt": output_excerpt,
                })
                if not banner:
                    candidate = self._scheduler_banner_from_evidence(script_id, output_excerpt)
                    if candidate:
                        banner = candidate
            if not banner:
                banner = self._scheduler_service_banner_fallback(
                    service_name=str(service.get("name", "") or ""),
                    product=str(service.get("product", "") or ""),
                    version=str(service.get("version", "") or ""),
                    extrainfo=str(service.get("extrainfo", "") or ""),
                )

            port_rows.append({
                "port": str(item.get("port", "") or ""),
                "protocol": str(item.get("protocol", "") or ""),
                "state": str(item.get("state", "") or ""),
                "service": str(service.get("name", "") or ""),
                "service_product": str(service.get("product", "") or ""),
                "service_version": str(service.get("version", "") or ""),
                "service_extrainfo": str(service.get("extrainfo", "") or ""),
                "banner": banner,
                "scripts": script_rows,
            })

        return {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "report_version": 1,
            "host": {
                "id": int(host.get("id", 0) or 0),
                "ip": str(host.get("ip", "") or ""),
                "hostname": str(host.get("hostname", "") or ""),
                "status": str(host.get("status", "") or ""),
                "os": str(host.get("os", "") or ""),
            },
            "note": str(details.get("note", "") or ""),
            "ports": port_rows,
            "cves": cves,
            "screenshots": screenshots,
            "ai_analysis": ai_analysis,
        }

    @staticmethod
    def _safe_report_token(value: Any, fallback: str = "host") -> str:
        token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
        token = token.strip("-._")
        if not token:
            token = str(fallback or "host")
        return token[:96]

    def render_host_ai_report_markdown(self, report: Dict[str, Any]) -> str:
        payload = report if isinstance(report, dict) else {}
        host = payload.get("host", {}) if isinstance(payload.get("host", {}), dict) else {}
        ai = payload.get("ai_analysis", {}) if isinstance(payload.get("ai_analysis", {}), dict) else {}
        host_updates = ai.get("host_updates", {}) if isinstance(ai.get("host_updates", {}), dict) else {}
        technologies = ai.get("technologies", []) if isinstance(ai.get("technologies", []), list) else []
        findings = ai.get("findings", []) if isinstance(ai.get("findings", []), list) else []
        manual_tests = ai.get("manual_tests", []) if isinstance(ai.get("manual_tests", []), list) else []
        ports = payload.get("ports", []) if isinstance(payload.get("ports", []), list) else []
        cves = payload.get("cves", []) if isinstance(payload.get("cves", []), list) else []

        lines = [
            "# Legion Host AI Report",
            "",
            f"- Generated: {payload.get('generated_at', '')}",
            f"- Host ID: {host.get('id', '')}",
            f"- Host IP: {host.get('ip', '')}",
            f"- Hostname: {host.get('hostname', '')}",
            f"- Status: {host.get('status', '')}",
            f"- OS: {host.get('os', '')}",
            "",
            "## AI Analysis",
            "",
            f"- Provider: {ai.get('provider', '')}",
            f"- Goal Profile: {ai.get('goal_profile', '')}",
            f"- Updated: {ai.get('updated_at', '')}",
            f"- Next Phase: {ai.get('next_phase', '')}",
            f"- Hostname Suggestion: {host_updates.get('hostname', '')} ({host_updates.get('hostname_confidence', 0)}%)",
            f"- OS Suggestion: {host_updates.get('os', '')} ({host_updates.get('os_confidence', 0)}%)",
            "",
            "## Technologies",
            "",
        ]

        if technologies:
            for item in technologies:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- {item.get('name', '')} {item.get('version', '')} | CPE: {item.get('cpe', '')} | Evidence: {item.get('evidence', '')}"
                )
        else:
            lines.append("- none")

        lines.extend(["", "## Findings", ""])
        if findings:
            for item in findings:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- [{item.get('severity', 'info')}] {item.get('title', '')} | CVE: {item.get('cve', '')} | CVSS: {item.get('cvss', '')} | Evidence: {item.get('evidence', '')}"
                )
        else:
            lines.append("- none")

        lines.extend(["", "## Manual Tests", ""])
        if manual_tests:
            for item in manual_tests:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- Why: {item.get('why', '')} | Command: `{item.get('command', '')}` | Scope: {item.get('scope_note', '')}"
                )
        else:
            lines.append("- none")

        lines.extend(["", "## Open Services", ""])
        if ports:
            for item in ports:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- {item.get('port', '')}/{item.get('protocol', '')} {item.get('service', '')} {item.get('service_product', '')} {item.get('service_version', '')}".strip()
                )
        else:
            lines.append("- none")

        lines.extend(["", "## CVEs", ""])
        if cves:
            for item in cves:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- {item.get('name', '')} | Severity: {item.get('severity', '')} | Product: {item.get('product', '')}"
                )
        else:
            lines.append("- none")

        return "\n".join(lines).strip() + "\n"

    def build_host_ai_reports_zip(self) -> Tuple[str, str]:
        with self._lock:
            project = self._require_active_project()
            host_repo = project.repositoryContainer.hostRepository
            hosts = host_repo.getAllHostObjs()

        if not hosts:
            raise ValueError("No hosts available in workspace to export AI reports.")

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        bundle_name = f"legion-host-ai-reports-{timestamp}.zip"
        root_name = f"legion-host-ai-reports-{timestamp}"
        tmp = tempfile.NamedTemporaryFile(prefix="legion-host-ai-reports-", suffix=".zip", delete=False)
        bundle_path = tmp.name
        tmp.close()

        manifest = {
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "report_version": 1,
            "host_count": len(hosts),
            "hosts": [],
        }

        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for host in hosts:
                host_id = int(getattr(host, "id", 0) or 0)
                host_ip = str(getattr(host, "ip", "") or "")
                host_name = str(getattr(host, "hostname", "") or "")
                if host_id <= 0:
                    continue

                report = self.get_host_ai_report(host_id)
                report_host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
                host_token = self._safe_report_token(
                    str(report_host.get("hostname", "")).strip()
                    or str(report_host.get("ip", "")).strip()
                    or f"host-{host_id}",
                    fallback=f"host-{host_id}",
                )
                safe_stem = f"{host_token}-{host_id}"
                json_member = f"{root_name}/hosts/{safe_stem}.json"
                md_member = f"{root_name}/hosts/{safe_stem}.md"
                archive.writestr(json_member, json.dumps(report, indent=2, default=str))
                archive.writestr(md_member, self.render_host_ai_report_markdown(report))

                manifest["hosts"].append({
                    "host_id": host_id,
                    "ip": host_ip,
                    "hostname": host_name,
                    "json": f"hosts/{safe_stem}.json",
                    "markdown": f"hosts/{safe_stem}.md",
                })

            archive.writestr(
                f"{root_name}/manifest.json",
                json.dumps(manifest, indent=2, sort_keys=True),
            )

        return bundle_path, bundle_name

    def get_project_ai_report(self) -> Dict[str, Any]:
        with self._lock:
            self._require_active_project()
            project_meta = dict(self._project_metadata())
            summary = dict(self._summary())
            host_rows = list(self._hosts(limit=5000))

        host_reports: List[Dict[str, Any]] = []
        for row in host_rows:
            host_id = int(row.get("id", 0) or 0)
            if host_id <= 0:
                continue
            try:
                host_reports.append(self.get_host_ai_report(host_id))
            except Exception:
                continue

        return {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "report_version": 1,
            "project": project_meta,
            "summary": summary,
            "host_count": len(host_reports),
            "hosts": host_reports,
        }

    def render_project_ai_report_markdown(self, report: Dict[str, Any]) -> str:
        payload = report if isinstance(report, dict) else {}
        project = payload.get("project", {}) if isinstance(payload.get("project", {}), dict) else {}
        summary = payload.get("summary", {}) if isinstance(payload.get("summary", {}), dict) else {}
        hosts = payload.get("hosts", []) if isinstance(payload.get("hosts", []), list) else []

        lines = [
            "# Legion Project AI Report",
            "",
            f"- Generated: {payload.get('generated_at', '')}",
            f"- Report Version: {payload.get('report_version', '')}",
            f"- Project: {project.get('name', '')}",
            f"- Temporary: {bool(project.get('is_temporary', False))}",
            f"- Output Folder: {project.get('output_folder', '')}",
            f"- Running Folder: {project.get('running_folder', '')}",
            "",
            "## Summary",
            "",
            f"- Hosts: {summary.get('hosts', 0)}",
            f"- Open Ports: {summary.get('open_ports', 0)}",
            f"- Services: {summary.get('services', 0)}",
            f"- CVEs: {summary.get('cves', 0)}",
            f"- Running Jobs: {summary.get('running_processes', 0)}",
            f"- Finished Jobs: {summary.get('finished_processes', 0)}",
            "",
            "## Hosts",
            "",
        ]

        if not hosts:
            lines.append("- none")
            return "\n".join(lines).strip() + "\n"

        for item in hosts:
            if not isinstance(item, dict):
                continue
            host = item.get("host", {}) if isinstance(item.get("host", {}), dict) else {}
            ai = item.get("ai_analysis", {}) if isinstance(item.get("ai_analysis", {}), dict) else {}
            technologies = ai.get("technologies", []) if isinstance(ai.get("technologies", []), list) else []
            findings = ai.get("findings", []) if isinstance(ai.get("findings", []), list) else []
            manual_tests = ai.get("manual_tests", []) if isinstance(ai.get("manual_tests", []), list) else []
            ports = item.get("ports", []) if isinstance(item.get("ports", []), list) else []
            cves = item.get("cves", []) if isinstance(item.get("cves", []), list) else []
            host_ip = str(host.get("ip", "") or "")
            host_name = str(host.get("hostname", "") or "")
            host_heading = host_ip
            if host_name:
                host_heading = f"{host_ip} ({host_name})".strip()
            lines.extend([
                f"### {host_heading}",
                "",
                f"- Host ID: {host.get('id', '')}",
                f"- Status: {host.get('status', '')}",
                f"- OS: {host.get('os', '')}",
                f"- Open Services: {len(ports)}",
                f"- CVEs: {len(cves)}",
                f"- Provider: {ai.get('provider', '')}",
                f"- Goal Profile: {ai.get('goal_profile', '')}",
                f"- Updated: {ai.get('updated_at', '')}",
                f"- Next Phase: {ai.get('next_phase', '')}",
                "",
                "#### Technologies",
            ])
            if technologies:
                for tech in technologies:
                    if not isinstance(tech, dict):
                        continue
                    lines.append(
                        f"- {tech.get('name', '')} {tech.get('version', '')} | CPE: {tech.get('cpe', '')} | Evidence: {tech.get('evidence', '')}"
                    )
            else:
                lines.append("- none")
            lines.extend(["", "#### Findings"])
            if findings:
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    lines.append(
                        f"- [{finding.get('severity', 'info')}] {finding.get('title', '')} | CVE: {finding.get('cve', '')} | CVSS: {finding.get('cvss', '')}"
                    )
            else:
                lines.append("- none")
            lines.extend(["", "#### Manual Tests"])
            if manual_tests:
                for test in manual_tests:
                    if not isinstance(test, dict):
                        continue
                    lines.append(
                        f"- Why: {test.get('why', '')} | Command: `{test.get('command', '')}` | Scope: {test.get('scope_note', '')}"
                    )
            else:
                lines.append("- none")
            lines.append("")

        return "\n".join(lines).strip() + "\n"

    def push_project_ai_report(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            config = self.scheduler_config.load()
            base_delivery = self._project_report_delivery_config(config)

        merged_delivery = dict(base_delivery)
        merged_delivery["headers"] = dict(base_delivery.get("headers", {}))
        merged_delivery["mtls"] = dict(base_delivery.get("mtls", {}))
        if isinstance(overrides, dict):
            for key, value in overrides.items():
                if key == "headers" and isinstance(value, dict):
                    merged_delivery["headers"] = {
                        str(k or "").strip(): str(v or "")
                        for k, v in value.items()
                        if str(k or "").strip()
                    }
                elif key == "mtls" and isinstance(value, dict):
                    next_mtls = dict(merged_delivery.get("mtls", {}))
                    next_mtls.update(value)
                    merged_delivery["mtls"] = next_mtls
                else:
                    merged_delivery[key] = value
        delivery = self._project_report_delivery_config({"project_report_delivery": merged_delivery})

        endpoint = str(delivery.get("endpoint", "") or "").strip()
        if not endpoint:
            raise ValueError("Project report delivery endpoint is required.")

        report = self.get_project_ai_report()
        report_format = str(delivery.get("format", "json") or "json").strip().lower()
        if report_format == "md":
            body = self.render_project_ai_report_markdown(report)
            content_type = "text/markdown; charset=utf-8"
        else:
            report_format = "json"
            body = json.dumps(report, indent=2, default=str)
            content_type = "application/json"

        headers = self._normalize_project_report_headers(delivery.get("headers", {}))
        has_content_type = any(str(name).strip().lower() == "content-type" for name in headers.keys())
        if not has_content_type:
            headers["Content-Type"] = content_type

        timeout_seconds = int(delivery.get("timeout_seconds", 30) or 30)
        timeout_seconds = max(5, min(timeout_seconds, 300))

        mtls = delivery.get("mtls", {}) if isinstance(delivery.get("mtls", {}), dict) else {}
        cert_value = None
        verify_value: Any = True
        if bool(mtls.get("enabled", False)):
            cert_path = str(mtls.get("client_cert_path", "") or "").strip()
            key_path = str(mtls.get("client_key_path", "") or "").strip()
            ca_path = str(mtls.get("ca_cert_path", "") or "").strip()

            if not cert_path:
                raise ValueError("mTLS is enabled but client cert path is empty.")
            if not os.path.isfile(cert_path):
                raise ValueError(f"mTLS client cert not found: {cert_path}")
            if key_path and not os.path.isfile(key_path):
                raise ValueError(f"mTLS client key not found: {key_path}")
            if ca_path and not os.path.isfile(ca_path):
                raise ValueError(f"mTLS CA cert not found: {ca_path}")

            cert_value = (cert_path, key_path) if key_path else cert_path
            if ca_path:
                verify_value = ca_path

        method = str(delivery.get("method", "POST") or "POST").strip().upper()
        if method not in {"POST", "PUT", "PATCH"}:
            method = "POST"

        try:
            response = requests.request(
                method=method,
                url=endpoint,
                headers=headers,
                data=body.encode("utf-8"),
                timeout=timeout_seconds,
                cert=cert_value,
                verify=verify_value,
            )
            response_text = str(getattr(response, "text", "") or "")
            excerpt = response_text[:4000].rstrip()
            ok = 200 <= int(response.status_code) < 300
            return {
                "ok": bool(ok),
                "provider_name": str(delivery.get("provider_name", "") or ""),
                "endpoint": endpoint,
                "method": method,
                "format": report_format,
                "status_code": int(response.status_code),
                "response_body_excerpt": excerpt,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider_name": str(delivery.get("provider_name", "") or ""),
                "endpoint": endpoint,
                "method": method,
                "format": report_format,
                "error": str(exc),
            }

    @staticmethod
    def _normalize_project_report_headers(headers: Any) -> Dict[str, str]:
        source = headers
        if isinstance(source, str):
            try:
                source = json.loads(source)
            except Exception:
                source = {}
        if not isinstance(source, dict):
            return {}
        normalized = {}
        for name, value in source.items():
            key = str(name or "").strip()
            if not key:
                continue
            normalized[key] = str(value or "")
        return normalized

    def update_host_note(self, host_id: int, text_value: str) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")

            ok = project.repositoryContainer.noteRepository.storeNotes(host.id, str(text_value or ""))
            return {
                "host_id": int(host.id),
                "saved": bool(ok),
            }

    def delete_host_workspace(self, host_id: int) -> Dict[str, Any]:
        target_host_id = int(host_id)
        target_host_ip = ""

        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(target_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            target_host_ip = str(getattr(host, "ip", "") or "").strip()

            self._ensure_process_tables()
            self._ensure_scheduler_table()
            self._ensure_scheduler_approval_store()

            session = project.database.session()
            try:
                running_process_ids = []
                if target_host_ip:
                    result = session.execute(text(
                        "SELECT id FROM process "
                        "WHERE COALESCE(hostIp, '') = :host_ip "
                        "AND COALESCE(status, '') IN ('Running', 'Waiting')"
                    ), {"host_ip": target_host_ip})
                    running_process_ids = [
                        int(item[0]) for item in result.fetchall()
                        if item and item[0] is not None
                    ]
            finally:
                session.close()

        for process_id in running_process_ids:
            try:
                self.kill_process(int(process_id))
            except Exception:
                pass

        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(target_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            target_host_ip = str(getattr(host, "ip", "") or "").strip()
            host_id_text = str(int(getattr(host, "id", target_host_id) or target_host_id))

            session = project.database.session()
            deleted_counts = {
                "scripts": 0,
                "cves": 0,
                "notes": 0,
                "ports": 0,
                "hosts": 0,
                "process_output": 0,
                "processes": 0,
                "approvals": 0,
                "decisions": 0,
                "ai_analysis": 0,
            }

            try:
                script_delete = session.execute(text(
                    "DELETE FROM l1ScriptObj "
                    "WHERE CAST(hostId AS TEXT) = :host_id "
                    "OR CAST(portId AS TEXT) IN ("
                    "SELECT CAST(id AS TEXT) FROM portObj WHERE CAST(hostId AS TEXT) = :host_id"
                    ")"
                ), {"host_id": host_id_text})
                deleted_counts["scripts"] = max(0, int(script_delete.rowcount or 0))

                cve_delete = session.execute(text(
                    "DELETE FROM cve WHERE CAST(hostId AS TEXT) = :host_id"
                ), {"host_id": host_id_text})
                deleted_counts["cves"] = max(0, int(cve_delete.rowcount or 0))

                note_delete = session.execute(text(
                    "DELETE FROM note WHERE CAST(hostId AS TEXT) = :host_id"
                ), {"host_id": host_id_text})
                deleted_counts["notes"] = max(0, int(note_delete.rowcount or 0))

                port_delete = session.execute(text(
                    "DELETE FROM portObj WHERE CAST(hostId AS TEXT) = :host_id"
                ), {"host_id": host_id_text})
                deleted_counts["ports"] = max(0, int(port_delete.rowcount or 0))

                host_delete = session.execute(text(
                    "DELETE FROM hostObj WHERE id = :host_id_int"
                ), {"host_id_int": int(host_id_text)})
                deleted_counts["hosts"] = max(0, int(host_delete.rowcount or 0))

                if target_host_ip:
                    process_output_delete = session.execute(text(
                        "DELETE FROM process_output "
                        "WHERE processId IN (SELECT id FROM process WHERE COALESCE(hostIp, '') = :host_ip)"
                    ), {"host_ip": target_host_ip})
                    deleted_counts["process_output"] = max(0, int(process_output_delete.rowcount or 0))

                    process_delete = session.execute(text(
                        "DELETE FROM process WHERE COALESCE(hostIp, '') = :host_ip"
                    ), {"host_ip": target_host_ip})
                    deleted_counts["processes"] = max(0, int(process_delete.rowcount or 0))

                    approval_delete = session.execute(text(
                        "DELETE FROM scheduler_pending_approval WHERE COALESCE(host_ip, '') = :host_ip"
                    ), {"host_ip": target_host_ip})
                    deleted_counts["approvals"] = max(0, int(approval_delete.rowcount or 0))

                    decision_delete = session.execute(text(
                        "DELETE FROM scheduler_decision_log WHERE COALESCE(host_ip, '') = :host_ip"
                    ), {"host_ip": target_host_ip})
                    deleted_counts["decisions"] = max(0, int(decision_delete.rowcount or 0))

                session.execute(text(
                    "DELETE FROM serviceObj "
                    "WHERE CAST(id AS TEXT) NOT IN ("
                    "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj "
                    "WHERE COALESCE(serviceId, '') <> ''"
                    ")"
                ))

                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

            deleted_counts["ai_analysis"] = int(delete_host_ai_state(project.database, int(host_id_text)) or 0)

            deleted_screenshots = 0
            screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
            if os.path.isdir(screenshot_dir) and target_host_ip:
                prefix = f"{target_host_ip}-"
                for filename in os.listdir(screenshot_dir):
                    if not filename.startswith(prefix) or not filename.lower().endswith(".png"):
                        continue
                    try:
                        os.remove(os.path.join(screenshot_dir, filename))
                        deleted_screenshots += 1
                    except Exception:
                        continue

            return {
                "deleted": True,
                "host_id": int(target_host_id),
                "host_ip": target_host_ip,
                "counts": {
                    **deleted_counts,
                    "screenshots": int(deleted_screenshots),
                },
            }

    def create_script_entry(
            self,
            host_id: int,
            port: str,
            protocol: str,
            script_id: str,
            output: str,
    ) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")

            port_obj = project.repositoryContainer.portRepository.getPortByHostIdAndPort(
                host.id,
                str(port),
                str(protocol or "tcp").lower(),
            )
            if port_obj is None:
                raise KeyError(f"Unknown port {port}/{protocol} for host {host.id}")

            session = project.database.session()
            try:
                script_row = l1ScriptObj(str(script_id), str(output or ""), str(port_obj.id), str(host.id))
                session.add(script_row)
                session.commit()
                return {
                    "id": int(script_row.id),
                    "script_id": str(script_row.scriptId),
                    "port_id": int(port_obj.id),
                }
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def delete_script_entry(self, script_db_id: int) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            session = project.database.session()
            try:
                row = session.query(l1ScriptObj).filter_by(id=int(script_db_id)).first()
                if row is None:
                    raise KeyError(f"Unknown script id: {script_db_id}")
                session.delete(row)
                session.commit()
                return {"deleted": True, "id": int(script_db_id)}
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def create_cve_entry(
            self,
            host_id: int,
            name: str,
            url: str = "",
            severity: str = "",
            source: str = "",
            product: str = "",
            version: str = "",
            exploit_id: int = 0,
            exploit: str = "",
            exploit_url: str = "",
    ) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")

            session = project.database.session()
            try:
                existing = session.query(cve).filter_by(hostId=str(host.id), name=str(name)).first()
                if existing:
                    return {
                        "id": int(existing.id),
                        "name": str(existing.name),
                        "host_id": int(host.id),
                        "created": False,
                    }

                row = cve(
                    str(name),
                    str(url or ""),
                    str(product or ""),
                    str(host.id),
                    severity=str(severity or ""),
                    source=str(source or ""),
                    version=str(version or ""),
                    exploitId=int(exploit_id or 0),
                    exploit=str(exploit or ""),
                    exploitUrl=str(exploit_url or ""),
                )
                session.add(row)
                session.commit()
                return {
                    "id": int(row.id),
                    "name": str(row.name),
                    "host_id": int(host.id),
                    "created": True,
                }
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def delete_cve_entry(self, cve_id: int) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            session = project.database.session()
            try:
                row = session.query(cve).filter_by(id=int(cve_id)).first()
                if row is None:
                    raise KeyError(f"Unknown cve id: {cve_id}")
                session.delete(row)
                session.commit()
                return {"deleted": True, "id": int(cve_id)}
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def start_process_retry_job(self, process_id: int, timeout: int = 300) -> Dict[str, Any]:
        target_id = int(process_id)
        timeout_value = max(1, int(timeout or 300))
        return self._start_job(
            "process-retry",
            lambda job_id: self.retry_process(target_id, timeout=timeout_value, job_id=int(job_id or 0)),
            payload={"process_id": target_id, "timeout": timeout_value},
        )

    def retry_process(self, process_id: int, timeout: int = 300, job_id: int = 0) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            self._ensure_process_tables()
            process_repo = project.repositoryContainer.processRepository
            details = process_repo.getProcessById(int(process_id))
            if not details:
                raise KeyError(f"Unknown process id: {process_id}")

            command = str(details.get("command", "") or "")
            if not command:
                raise ValueError(f"Process {process_id} has no command to retry.")

            host_ip = str(details.get("hostIp", "") or "")
            port = str(details.get("port", "") or "")
            protocol = str(details.get("protocol", "") or "tcp")
            tool_name = str(details.get("name", "") or "process")
            tab_title = str(details.get("tabTitle", "") or tool_name)
            outputfile = str(details.get("outputfile", "") or "")
            if not outputfile:
                outputfile = os.path.join(
                    project.properties.runningFolder,
                    f"{getTimestamp()}-{tool_name}-{host_ip}-{port}",
                )
                outputfile = os.path.normpath(outputfile).replace("\\", "/")

        executed, reason, new_process_id = self._run_command_with_tracking(
            tool_name=tool_name,
            tab_title=tab_title,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            command=command,
            outputfile=outputfile,
            timeout=int(timeout),
            job_id=int(job_id or 0),
        )
        return {
            "source_process_id": int(process_id),
            "process_id": int(new_process_id),
            "executed": bool(executed),
            "reason": str(reason),
            "command": command,
        }

    @staticmethod
    def _signal_process_tree(proc: Optional[subprocess.Popen], *, force: bool = False):
        if proc is None:
            return
        try:
            if proc.poll() is not None:
                return
        except Exception:
            return

        used_group_signal = False
        if os.name != "nt" and hasattr(os, "killpg"):
            try:
                pgid = os.getpgid(int(proc.pid))
                if pgid > 0:
                    sig = signal.SIGKILL if force else signal.SIGTERM
                    os.killpg(pgid, sig)
                    used_group_signal = True
            except Exception:
                used_group_signal = False

        if not used_group_signal:
            try:
                if force:
                    proc.kill()
                else:
                    proc.terminate()
            except Exception:
                pass

    def kill_process(self, process_id: int) -> Dict[str, Any]:
        process_key = int(process_id)
        with self._process_runtime_lock:
            self._kill_requests.add(process_key)
            proc = self._active_processes.get(process_key)

        had_live_handle = proc is not None
        if proc is not None and proc.poll() is None:
            self._signal_process_tree(proc, force=False)
            try:
                proc.wait(timeout=2)
            except Exception:
                self._signal_process_tree(proc, force=True)
        else:
            with self._lock:
                project = self._require_active_project()
                process_repo = project.repositoryContainer.processRepository
                pid = process_repo.getPIDByProcessId(str(process_key))
            try:
                if pid not in (None, "", "-1"):
                    os.kill(int(pid), signal.SIGTERM)
            except Exception:
                pass

        with self._lock:
            project = self._require_active_project()
            process_repo = project.repositoryContainer.processRepository
            process_repo.storeProcessKillStatus(str(process_key))

        return {
            "killed": True,
            "process_id": process_key,
            "had_live_handle": had_live_handle,
        }

    def clear_processes(self, reset_all: bool = False) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            process_repo = project.repositoryContainer.processRepository
            process_repo.toggleProcessDisplayStatus(resetAll=bool(reset_all))
        return {"cleared": True, "reset_all": bool(reset_all)}

    def close_process(self, process_id: int) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            process_repo = project.repositoryContainer.processRepository
            status = str(process_repo.getStatusByProcessId(str(int(process_id))) or "")
            session = project.database.session()
            try:
                session.execute(text(
                    "UPDATE process SET display = 'False', closed = 'True' WHERE id = :id"
                ), {"id": int(process_id)})
                session.commit()
            except Exception:
                session.rollback()
            finally:
                session.close()
            if status in {"Running", "Waiting"}:
                process_repo.storeProcessCancelStatus(str(int(process_id)))
        return {"closed": True, "process_id": int(process_id)}

    def get_process_output(self, process_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
        offset_value = max(0, int(offset or 0))
        max_len = max(256, min(int(max_chars or 12000), 50000))
        with self._lock:
            project = self._require_active_project()
            session = project.database.session()
            try:
                result = session.execute(text(
                    "SELECT p.id, p.name, p.hostIp, p.port, p.protocol, p.command, p.status, p.startTime, p.endTime, "
                    "COALESCE(o.output, '') AS output "
                    "FROM process AS p "
                    "LEFT JOIN process_output AS o ON o.processId = p.id "
                    "WHERE p.id = :id LIMIT 1"
                ), {"id": int(process_id)})
                row = result.fetchone()
                if row is None:
                    raise KeyError(f"Unknown process id: {process_id}")
                keys = result.keys()
                data = dict(zip(keys, row))
            finally:
                session.close()

        full_output = str(data.get("output", "") or "")
        output_length = len(full_output)
        chunk = ""
        if offset_value < output_length:
            chunk = full_output[offset_value:offset_value + max_len]
        next_offset = offset_value + len(chunk)
        status = str(data.get("status", "") or "")
        completed = status not in {"Running", "Waiting"}
        data["output_chunk"] = chunk
        data["output_length"] = output_length
        data["offset"] = offset_value
        data["next_offset"] = next_offset
        data["completed"] = completed
        return data

    def get_script_output(self, script_db_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
        offset_value = max(0, int(offset or 0))
        max_len = max(256, min(int(max_chars or 12000), 50000))
        with self._lock:
            project = self._require_active_project()
            session = project.database.session()
            try:
                script_result = session.execute(text(
                    "SELECT s.id AS script_db_id, "
                    "COALESCE(s.scriptId, '') AS script_id, "
                    "COALESCE(s.output, '') AS script_output, "
                    "COALESCE(p.portId, '') AS port, "
                    "LOWER(COALESCE(p.protocol, 'tcp')) AS protocol, "
                    "COALESCE(h.ip, '') AS host_ip "
                    "FROM l1ScriptObj AS s "
                    "LEFT JOIN portObj AS p ON p.id = s.portId "
                    "LEFT JOIN hostObj AS h ON h.id = s.hostId "
                    "WHERE s.id = :id LIMIT 1"
                ), {"id": int(script_db_id)})
                script_row = script_result.fetchone()
                if script_row is None:
                    raise KeyError(f"Unknown script id: {script_db_id}")
                script_data = dict(zip(script_result.keys(), script_row))

                process_result = session.execute(text(
                    "SELECT p.id AS process_id, "
                    "COALESCE(p.command, '') AS command, "
                    "COALESCE(p.outputfile, '') AS outputfile, "
                    "COALESCE(p.status, '') AS status, "
                    "COALESCE(o.output, '') AS output "
                    "FROM process AS p "
                    "LEFT JOIN process_output AS o ON o.processId = p.id "
                    "WHERE p.name = :tool_id "
                    "AND COALESCE(p.hostIp, '') = :host_ip "
                    "AND COALESCE(p.port, '') = :port "
                    "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                    "ORDER BY p.id DESC LIMIT 1"
                ), {
                    "tool_id": str(script_data.get("script_id", "") or ""),
                    "host_ip": str(script_data.get("host_ip", "") or ""),
                    "port": str(script_data.get("port", "") or ""),
                    "protocol": str(script_data.get("protocol", "tcp") or "tcp"),
                })
                process_row = process_result.fetchone()
                process_data = dict(zip(process_result.keys(), process_row)) if process_row else {}
            finally:
                session.close()

        has_process = bool(process_data.get("process_id"))
        output_text = str(process_data.get("output", "") or "") if has_process else str(script_data.get("script_output", "") or "")
        output_length = len(output_text)
        chunk = ""
        if offset_value < output_length:
            chunk = output_text[offset_value:offset_value + max_len]
        next_offset = offset_value + len(chunk)
        status = str(process_data.get("status", "") or "")
        completed = status not in {"Running", "Waiting"} if has_process else True

        return {
            "script_db_id": int(script_data.get("script_db_id", 0) or 0),
            "script_id": str(script_data.get("script_id", "") or ""),
            "host_ip": str(script_data.get("host_ip", "") or ""),
            "port": str(script_data.get("port", "") or ""),
            "protocol": str(script_data.get("protocol", "tcp") or "tcp"),
            "source": "process" if has_process else "script-row",
            "process_id": int(process_data.get("process_id", 0) or 0),
            "outputfile": str(process_data.get("outputfile", "") or ""),
            "command": str(process_data.get("command", "") or ""),
            "status": status if has_process else "Saved",
            "output": output_text,
            "output_chunk": chunk,
            "output_length": output_length,
            "offset": offset_value,
            "next_offset": next_offset,
            "completed": completed,
        }

    def get_screenshot_file(self, filename: str) -> str:
        safe_name = os.path.basename(str(filename or "").strip())
        if safe_name != str(filename or "").strip():
            raise ValueError("Invalid screenshot filename.")
        if not safe_name.lower().endswith(".png"):
            raise ValueError("Only PNG screenshots are supported.")

        with self._lock:
            project = self._require_active_project()
            screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
            path = os.path.join(screenshot_dir, safe_name)
            if not os.path.isfile(path):
                raise FileNotFoundError(path)
            return path

    def list_jobs(self, limit: int = 80) -> List[Dict[str, Any]]:
        return self.jobs.list_jobs(limit=limit)

    def get_job(self, job_id: int) -> Dict[str, Any]:
        job = self.jobs.get_job(job_id)
        if job is None:
            raise KeyError(f"Unknown job id: {job_id}")
        return job

    def stop_job(self, job_id: int) -> Dict[str, Any]:
        target_job_id = int(job_id)
        job = self.jobs.get_job(target_job_id)
        if job is None:
            raise KeyError(f"Unknown job id: {job_id}")

        status = str(job.get("status", "") or "").strip().lower()
        if status not in {"queued", "running"}:
            return {
                "stopped": False,
                "job": job,
                "killed_process_ids": [],
                "message": "Job is not running or queued.",
            }

        updated = self.jobs.cancel_job(target_job_id, reason="stopped by user")
        if updated is None:
            raise KeyError(f"Unknown job id: {job_id}")

        killed_process_ids = []
        for process_id in self._job_active_process_ids(target_job_id):
            try:
                self.kill_process(int(process_id))
                killed_process_ids.append(int(process_id))
            except Exception:
                continue

        final_job = self.jobs.get_job(target_job_id) or updated
        return {
            "stopped": True,
            "job": final_job,
            "killed_process_ids": killed_process_ids,
        }

    def _import_targets_from_file(self, file_path: str) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            session = project.database.session()
            host_repo = project.repositoryContainer.hostRepository
            try:
                added = import_targets_from_textfile(session, host_repo, file_path)
            finally:
                session.close()
            return {
                "path": file_path,
                "added": int(added or 0),
            }

    def _import_nmap_xml(self, xml_path: str, run_actions: bool = False) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            host_repo = project.repositoryContainer.hostRepository
            importer = NmapImporter(None, host_repo)
            importer.setDB(project.database)
            importer.setHostRepository(host_repo)
            importer.setFilename(xml_path)
            importer.setOutput("")
            importer.run()

            try:
                self.logic.copyNmapXMLToOutputFolder(xml_path)
            except Exception:
                pass

            self._ensure_scheduler_table()
            self._ensure_scheduler_approval_store()

        scheduler_result = None
        if run_actions:
            scheduler_result = self._run_scheduler_actions_web()

        return {
            "xml_path": xml_path,
            "run_actions": bool(run_actions),
            "scheduler_result": scheduler_result,
        }

    def _run_nmap_scan_and_import(
            self,
            targets: List[str],
            discovery: bool,
            staged: bool,
            run_actions: bool,
            nmap_path: str,
            nmap_args: str,
            scan_mode: str = "legacy",
            scan_options: Optional[Dict[str, Any]] = None,
            job_id: int = 0,
    ) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            running_folder = project.properties.runningFolder
            host_count_before = len(project.repositoryContainer.hostRepository.getAllHostObjs())
            output_prefix = os.path.join(
                running_folder,
                f"web-nmap-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",
            )

        scan_plan = self._build_nmap_scan_plan(
            targets=targets,
            discovery=bool(discovery),
            staged=bool(staged),
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            output_prefix=output_prefix,
            scan_mode=scan_mode,
            scan_options=dict(scan_options or {}),
        )

        target_label = self._compact_targets(targets)
        stage_results: List[Dict[str, Any]] = []
        for stage in scan_plan["stages"]:
            if int(job_id or 0) > 0 and self.jobs.is_cancel_requested(int(job_id)):
                raise RuntimeError("cancelled")
            executed, reason, process_id = self._run_command_with_tracking(
                tool_name=stage["tool_name"],
                tab_title=stage["tab_title"],
                host_ip=target_label,
                port="",
                protocol="",
                command=stage["command"],
                outputfile=stage["output_prefix"],
                timeout=int(stage.get("timeout", 3600)),
                job_id=int(job_id or 0),
            )
            stage_results.append({
                "name": stage["tool_name"],
                "command": stage["command"],
                "executed": bool(executed),
                "reason": reason,
                "process_id": int(process_id or 0),
                "output_prefix": stage["output_prefix"],
                "xml_path": stage["xml_path"],
            })
            if not executed:
                raise RuntimeError(
                    f"Nmap stage '{stage['tool_name']}' failed ({reason}). "
                    f"Command: {stage['command']}"
                )

        xml_path = scan_plan["xml_path"]
        if not xml_path or not os.path.isfile(xml_path):
            raise RuntimeError(f"Nmap scan completed but XML output was not found: {xml_path}")

        import_result = self._import_nmap_xml(xml_path, run_actions=run_actions)
        with self._lock:
            project = self._require_active_project()
            host_count_after = len(project.repositoryContainer.hostRepository.getAllHostObjs())
        imported_hosts = max(0, int(host_count_after) - int(host_count_before))
        warnings: List[str] = []
        if imported_hosts == 0:
            if bool(discovery):
                warnings.append(
                    "Nmap completed but no hosts were imported. "
                    "The target may be dropping discovery probes; try disabling host discovery (-Pn)."
                )
            else:
                warnings.append(
                    "Nmap completed but no hosts were imported. "
                    "Verify target reachability and scan privileges."
                )

        return {
            "targets": targets,
            "discovery": bool(discovery),
            "staged": bool(staged),
            "run_actions": bool(run_actions),
            "nmap_path": nmap_path,
            "nmap_args": str(nmap_args or ""),
            "scan_mode": str(scan_mode or "legacy"),
            "scan_options": dict(scan_options or {}),
            "commands": [stage["command"] for stage in scan_plan["stages"]],
            "stages": stage_results,
            "xml_path": xml_path,
            "imported_hosts": imported_hosts,
            "warnings": warnings,
            **import_result,
        }

    def _run_manual_tool(
            self,
            host_ip: str,
            port: str,
            protocol: str,
            tool_id: str,
            command_override: str,
            timeout: int,
            job_id: int = 0,
    ):
        with self._lock:
            self._require_active_project()
            settings = self._get_settings()
            action = self._find_port_action(settings, tool_id)
            if action is None:
                raise KeyError(f"Unknown tool id: {tool_id}")

            label = str(action[0])
            template = str(command_override or action[2])
            command, outputfile = self._build_command(template, host_ip, port, protocol, tool_id)

        executed, reason, process_id = self._run_command_with_tracking(
            tool_name=tool_id,
            tab_title=f"{tool_id} ({port}/{protocol})",
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            command=command,
            outputfile=outputfile,
            timeout=int(timeout),
            job_id=int(job_id or 0),
        )

        return {
            "tool_id": tool_id,
            "label": label,
            "host_ip": host_ip,
            "port": str(port),
            "protocol": str(protocol),
            "command": command,
            "outputfile": outputfile,
            "executed": bool(executed),
            "reason": reason,
            "process_id": process_id,
        }

    def _run_scheduler_actions_web(
            self,
            *,
            host_ids: Optional[set] = None,
            dig_deeper: bool = False,
            job_id: int = 0,
    ) -> Dict[str, Any]:
        summary = {
            "considered": 0,
            "approval_queued": 0,
            "executed": 0,
            "skipped": 0,
            "host_scope_count": 0,
            "dig_deeper": bool(dig_deeper),
        }
        resolved_job_id = int(job_id or 0)
        started_at = time.monotonic()
        max_runtime_seconds = _DIG_DEEPER_MAX_RUNTIME_SECONDS if bool(dig_deeper) else 0
        max_total_actions = _DIG_DEEPER_MAX_TOTAL_ACTIONS if bool(dig_deeper) else 0
        task_timeout_seconds = _DIG_DEEPER_TASK_TIMEOUT_SECONDS if bool(dig_deeper) else 300

        normalized_host_ids = {
            int(item) for item in list(host_ids or set())
            if str(item).strip()
        }

        with self._lock:
            project = self._require_active_project()
            settings = self._get_settings()
            host_repo = project.repositoryContainer.hostRepository
            port_repo = project.repositoryContainer.portRepository
            service_repo = project.repositoryContainer.serviceRepository
            scheduler_prefs = self.scheduler_config.load()
            scheduler_mode = str(scheduler_prefs.get("mode", "deterministic") or "deterministic").strip().lower()
            goal_profile = str(scheduler_prefs.get("goal_profile", "internal_asset_discovery") or "internal_asset_discovery")
            scheduler_concurrency = self._scheduler_max_concurrency(scheduler_prefs)
            ai_feedback_cfg = self._scheduler_feedback_config(scheduler_prefs)
            hosts = host_repo.getAllHostObjs()
            if normalized_host_ids:
                hosts = [
                    host for host in hosts
                    if int(getattr(host, "id", 0) or 0) in normalized_host_ids
                ]

        summary["host_scope_count"] = len(hosts)

        for host in hosts:
            if resolved_job_id > 0 and self.jobs.is_cancel_requested(resolved_job_id):
                summary["cancelled"] = True
                summary["cancel_reason"] = "cancelled by user"
                return summary
            host_id = int(getattr(host, "id", 0) or 0)
            host_ip = str(getattr(host, "ip", "") or "")
            ports = port_repo.getPortsByHostId(host.id)
            for port_obj in ports:
                if resolved_job_id > 0 and self.jobs.is_cancel_requested(resolved_job_id):
                    summary["cancelled"] = True
                    summary["cancel_reason"] = "cancelled by user"
                    return summary
                state = str(getattr(port_obj, "state", "") or "")
                if state not in {"open", "open|filtered"}:
                    continue
                port = str(getattr(port_obj, "portId", "") or "")
                protocol = str(getattr(port_obj, "protocol", "tcp") or "tcp").lower()
                service_name = ""
                service_id = getattr(port_obj, "serviceId", None)
                if service_id:
                    service_obj = service_repo.getServiceById(service_id)
                    if service_obj:
                        service_name = str(getattr(service_obj, "name", "") or "")
                service_name = service_name.rstrip("?")

                use_feedback_loop = scheduler_mode == "ai" and bool(ai_feedback_cfg.get("enabled", True))
                max_rounds = int(ai_feedback_cfg.get("max_rounds_per_target", 4)) if use_feedback_loop else 1
                max_rounds = max(1, min(max_rounds, 12))
                max_actions_per_round = int(ai_feedback_cfg.get("max_actions_per_round", 2)) if use_feedback_loop else 4
                max_actions_per_round = max(1, min(max_actions_per_round, 8))
                recent_output_chars = int(ai_feedback_cfg.get("recent_output_chars", 900))
                recent_output_chars = max(320, min(recent_output_chars, 4000))

                # Honor configured scheduler concurrency as the effective round width.
                # Without this, the hidden ai_feedback max_actions_per_round cap (default 2)
                # can make max_concurrency appear ignored.
                if use_feedback_loop:
                    max_actions_per_round = max(
                        max_actions_per_round,
                        max(1, min(int(scheduler_concurrency), 8)),
                    )

                if use_feedback_loop and bool(dig_deeper):
                    max_rounds = max(max_rounds, 4)
                    max_actions_per_round = max(max_actions_per_round, 3)
                    recent_output_chars = max(recent_output_chars, 1600)

                attempted_tool_ids = set()
                if use_feedback_loop:
                    attempted_tool_ids = self._existing_tool_attempts_for_target(
                        host_id=host_id,
                        host_ip=host_ip,
                        port=port,
                        protocol=protocol,
                    )

                for _round in range(max_rounds):
                    if resolved_job_id > 0 and self.jobs.is_cancel_requested(resolved_job_id):
                        summary["cancelled"] = True
                        summary["cancel_reason"] = "cancelled by user"
                        return summary
                    if max_runtime_seconds > 0 and (time.monotonic() - started_at) >= int(max_runtime_seconds):
                        summary["stopped_early"] = "dig_deeper_runtime_cap"
                        return summary
                    if max_total_actions > 0 and (summary["executed"] + summary["skipped"] + summary["approval_queued"]) >= int(max_total_actions):
                        summary["stopped_early"] = "dig_deeper_action_cap"
                        return summary

                    context = None
                    if use_feedback_loop:
                        context = self._build_scheduler_target_context(
                            host_id=host_id,
                            host_ip=host_ip,
                            port=port,
                            protocol=protocol,
                            service_name=service_name,
                            attempted_tool_ids=attempted_tool_ids,
                            recent_output_chars=recent_output_chars,
                            analysis_mode="dig_deeper" if bool(dig_deeper) else "standard",
                        )

                    decisions = self.scheduler_planner.plan_actions(
                        service_name,
                        protocol,
                        settings,
                        context=context,
                        excluded_tool_ids=sorted(attempted_tool_ids),
                        limit=max_actions_per_round,
                    )

                    if scheduler_mode == "ai":
                        provider_payload = self.scheduler_planner.get_last_provider_payload(clear=True)
                        self._persist_scheduler_ai_analysis(
                            host_id=host_id,
                            host_ip=host_ip,
                            port=port,
                            protocol=protocol,
                            service_name=service_name,
                            goal_profile=goal_profile,
                            provider_payload=provider_payload,
                        )

                    if not decisions:
                        break

                    round_progress = False
                    execution_tasks: List[Dict[str, Any]] = []
                    round_scheduled_tool_ids: set[str] = set()
                    for decision in decisions:
                        normalized_tool_id = str(decision.tool_id or "").strip().lower()
                        if (
                                not normalized_tool_id
                                or normalized_tool_id in attempted_tool_ids
                                or normalized_tool_id in round_scheduled_tool_ids
                        ):
                            continue

                        summary["considered"] += 1
                        command_template = decision.command_template or self._find_command_template_for_tool(settings, decision.tool_id)

                        if decision.requires_approval and not self.scheduler_config.is_family_preapproved(decision.family_id):
                            approval_id = self._queue_scheduler_approval(decision, host_ip, port, protocol, service_name, command_template)
                            self._record_scheduler_decision(
                                decision,
                                host_ip,
                                port,
                                protocol,
                                service_name,
                                approved=False,
                                executed=False,
                                reason=f"pending approval #{approval_id}",
                                approval_id=int(approval_id),
                            )
                            summary["approval_queued"] += 1
                            attempted_tool_ids.add(normalized_tool_id)
                            round_progress = True
                            continue

                        round_scheduled_tool_ids.add(normalized_tool_id)
                        execution_tasks.append({
                            "decision": decision,
                            "tool_id": normalized_tool_id,
                            "host_ip": host_ip,
                            "port": port,
                            "protocol": protocol,
                            "service_name": service_name,
                            "command_template": command_template,
                            "timeout": int(task_timeout_seconds),
                            "job_id": resolved_job_id,
                        })

                    execution_results = self._execute_scheduler_task_batch(
                        execution_tasks,
                        max_concurrency=scheduler_concurrency,
                    )

                    for result in execution_results:
                        decision = result["decision"]
                        normalized_tool_id = str(result.get("tool_id", "") or "").strip().lower()
                        executed = bool(result.get("executed", False))
                        reason = str(result.get("reason", "") or "")
                        process_id = int(result.get("process_id", 0) or 0)

                        self._record_scheduler_decision(
                            decision,
                            host_ip,
                            port,
                            protocol,
                            service_name,
                            approved=True,
                            executed=executed,
                            reason=reason,
                        )
                        if normalized_tool_id:
                            attempted_tool_ids.add(normalized_tool_id)
                        round_progress = True
                        if executed:
                            summary["executed"] += 1
                        else:
                            summary["skipped"] += 1

                        if process_id and executed:
                            self._save_script_result_if_missing(
                                host_ip=host_ip,
                                port=port,
                                protocol=protocol,
                                tool_id=decision.tool_id,
                                process_id=process_id,
                            )
                        if executed:
                            self._enrich_host_from_observed_results(
                                host_ip=host_ip,
                                port=port,
                                protocol=protocol,
                            )

                    if not round_progress:
                        break
                    if not use_feedback_loop:
                        break

        return summary

    @staticmethod
    def _job_worker_count(preferences: Optional[Dict[str, Any]] = None) -> int:
        source = preferences if isinstance(preferences, dict) else {}
        try:
            value = int(source.get("max_concurrency", 1))
        except (TypeError, ValueError):
            value = 1
        return max(1, min(value, 8))

    @staticmethod
    def _scheduler_max_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
        source = preferences if isinstance(preferences, dict) else {}
        try:
            value = int(source.get("max_concurrency", 1))
        except (TypeError, ValueError):
            value = 1
        return max(1, min(value, 16))

    @staticmethod
    def _scheduler_max_jobs(preferences: Optional[Dict[str, Any]] = None) -> int:
        source = preferences if isinstance(preferences, dict) else {}
        try:
            value = int(source.get("max_jobs", 200))
        except (TypeError, ValueError):
            value = 200
        return max(20, min(value, 2000))

    @staticmethod
    def _project_report_delivery_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        source = preferences if isinstance(preferences, dict) else {}
        raw = source.get("project_report_delivery", {})
        defaults = {
            "provider_name": "",
            "endpoint": "",
            "method": "POST",
            "format": "json",
            "headers": {},
            "timeout_seconds": 30,
            "mtls": {
                "enabled": False,
                "client_cert_path": "",
                "client_key_path": "",
                "ca_cert_path": "",
            },
        }
        if isinstance(raw, dict):
            defaults.update(raw)

        headers = WebRuntime._normalize_project_report_headers(defaults.get("headers", {}))

        method = str(defaults.get("method", "POST") or "POST").strip().upper()
        if method not in {"POST", "PUT", "PATCH"}:
            method = "POST"

        report_format = str(defaults.get("format", "json") or "json").strip().lower()
        if report_format in {"markdown"}:
            report_format = "md"
        if report_format not in {"json", "md"}:
            report_format = "json"

        try:
            timeout_seconds = int(defaults.get("timeout_seconds", 30))
        except (TypeError, ValueError):
            timeout_seconds = 30
        timeout_seconds = max(5, min(timeout_seconds, 300))

        mtls_raw = defaults.get("mtls", {})
        if not isinstance(mtls_raw, dict):
            mtls_raw = {}

        return {
            "provider_name": str(defaults.get("provider_name", "") or ""),
            "endpoint": str(defaults.get("endpoint", "") or ""),
            "method": method,
            "format": report_format,
            "headers": headers,
            "timeout_seconds": int(timeout_seconds),
            "mtls": {
                "enabled": bool(mtls_raw.get("enabled", False)),
                "client_cert_path": str(mtls_raw.get("client_cert_path", "") or ""),
                "client_key_path": str(mtls_raw.get("client_key_path", "") or ""),
                "ca_cert_path": str(mtls_raw.get("ca_cert_path", "") or ""),
            },
        }

    def _execute_scheduler_task_batch(self, tasks: List[Dict[str, Any]], max_concurrency: int) -> List[Dict[str, Any]]:
        if not tasks:
            return []

        concurrency = max(1, min(int(max_concurrency or 1), 16))
        if concurrency <= 1 or len(tasks) <= 1:
            return [self._execute_scheduler_task(task) for task in tasks]

        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="legion-scheduler") as pool:
            future_map = {pool.submit(self._execute_scheduler_task, task): task for task in tasks}
            for future in as_completed(future_map):
                task = future_map[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({
                        "decision": task["decision"],
                        "tool_id": str(task.get("tool_id", "") or ""),
                        "executed": False,
                        "reason": f"error: {exc}",
                        "process_id": 0,
                    })
        return results

    def _execute_scheduler_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        decision = task["decision"]
        executed, reason, process_id = self._execute_scheduler_decision(
            decision,
            host_ip=str(task.get("host_ip", "") or ""),
            port=str(task.get("port", "") or ""),
            protocol=str(task.get("protocol", "tcp") or "tcp"),
            service_name=str(task.get("service_name", "") or ""),
            command_template=str(task.get("command_template", "") or ""),
            timeout=int(task.get("timeout", 300) or 300),
            job_id=int(task.get("job_id", 0) or 0),
        )
        return {
            "decision": decision,
            "tool_id": str(task.get("tool_id", "") or ""),
            "executed": bool(executed),
            "reason": str(reason),
            "process_id": int(process_id or 0),
        }

    @staticmethod
    def _scheduler_feedback_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged = dict(_DEFAULT_AI_FEEDBACK_CONFIG)
        source = preferences.get("ai_feedback", {}) if isinstance(preferences, dict) else {}
        if not isinstance(source, dict):
            source = {}

        if "enabled" in source:
            merged["enabled"] = bool(source.get("enabled"))

        for key in ("max_rounds_per_target", "max_actions_per_round", "recent_output_chars"):
            try:
                merged[key] = int(source.get(key, merged[key]))
            except (TypeError, ValueError):
                continue

        merged["max_rounds_per_target"] = max(1, min(int(merged["max_rounds_per_target"]), 12))
        merged["max_actions_per_round"] = max(1, min(int(merged["max_actions_per_round"]), 8))
        merged["recent_output_chars"] = max(320, min(int(merged["recent_output_chars"]), 4000))
        return merged

    def _existing_tool_attempts_for_target(self, host_id: int, host_ip: str, port: str, protocol: str) -> set:
        attempted = set()
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return attempted

            self._ensure_scheduler_approval_store()
            session = project.database.session()
            try:
                scripts_result = session.execute(text(
                    "SELECT COALESCE(s.scriptId, '') AS script_id "
                    "FROM l1ScriptObj AS s "
                    "LEFT JOIN portObj AS p ON p.id = s.portId "
                    "WHERE s.hostId = :host_id "
                    "AND s.portId IS NOT NULL "
                    "AND COALESCE(p.portId, '') = :port "
                    "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                    "ORDER BY s.id DESC LIMIT 100"
                ), {
                    "host_id": int(host_id or 0),
                    "port": str(port or ""),
                    "protocol": str(protocol or "tcp"),
                })
                for row in scripts_result.fetchall():
                    tool = str(row[0] or "").strip().lower()
                    if tool:
                        attempted.add(tool)

                process_result = session.execute(text(
                    "SELECT COALESCE(p.name, '') AS tool_id "
                    "FROM process AS p "
                    "WHERE COALESCE(p.hostIp, '') = :host_ip "
                    "AND COALESCE(p.port, '') = :port "
                    "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                    "ORDER BY p.id DESC LIMIT 160"
                ), {
                    "host_ip": str(host_ip or ""),
                    "port": str(port or ""),
                    "protocol": str(protocol or "tcp"),
                })
                for row in process_result.fetchall():
                    tool = str(row[0] or "").strip().lower()
                    if tool:
                        attempted.add(tool)

                approval_result = session.execute(text(
                    "SELECT COALESCE(tool_id, '') AS tool_id "
                    "FROM scheduler_pending_approval "
                    "WHERE COALESCE(host_ip, '') = :host_ip "
                    "AND COALESCE(port, '') = :port "
                    "AND LOWER(COALESCE(protocol, '')) = LOWER(:protocol) "
                    "AND LOWER(COALESCE(status, '')) IN ('pending', 'approved', 'running', 'executed') "
                    "ORDER BY id DESC LIMIT 100"
                ), {
                    "host_ip": str(host_ip or ""),
                    "port": str(port or ""),
                    "protocol": str(protocol or "tcp"),
                })
                for row in approval_result.fetchall():
                    tool = str(row[0] or "").strip().lower()
                    if tool:
                        attempted.add(tool)
            finally:
                session.close()
        return attempted

    def _build_scheduler_target_context(
            self,
            *,
            host_id: int,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            attempted_tool_ids: set,
            recent_output_chars: int,
            analysis_mode: str = "standard",
    ) -> Dict[str, Any]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return {}
            settings = self._get_settings()

            session = project.database.session()
            try:
                host_result = session.execute(text(
                    "SELECT COALESCE(h.hostname, '') AS hostname, "
                    "COALESCE(h.osMatch, '') AS os_match "
                    "FROM hostObj AS h WHERE h.id = :host_id LIMIT 1"
                ), {"host_id": int(host_id or 0)}).fetchone()
                hostname = str(host_result[0] or "") if host_result else ""
                os_match = str(host_result[1] or "") if host_result else ""

                service_result = session.execute(text(
                    "SELECT COALESCE(s.name, '') AS service_name, "
                    "COALESCE(s.product, '') AS service_product, "
                    "COALESCE(s.version, '') AS service_version, "
                    "COALESCE(s.extrainfo, '') AS service_extrainfo "
                    "FROM portObj AS p "
                    "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                    "WHERE p.hostId = :host_id "
                    "AND COALESCE(p.portId, '') = :port "
                    "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                    "ORDER BY p.id DESC LIMIT 1"
                ), {
                    "host_id": int(host_id or 0),
                    "port": str(port or ""),
                    "protocol": str(protocol or "tcp"),
                }).fetchone()
                service_name_db = str(service_result[0] or "") if service_result else ""
                service_product = str(service_result[1] or "") if service_result else ""
                service_version = str(service_result[2] or "") if service_result else ""
                service_extrainfo = str(service_result[3] or "") if service_result else ""
                target_service = str(service_name or service_name_db or "").strip()

                host_port_result = session.execute(text(
                    "SELECT COALESCE(p.portId, '') AS port_id, "
                    "COALESCE(p.protocol, '') AS protocol, "
                    "COALESCE(p.state, '') AS state, "
                    "COALESCE(s.name, '') AS service_name, "
                    "COALESCE(s.product, '') AS service_product, "
                    "COALESCE(s.version, '') AS service_version, "
                    "COALESCE(s.extrainfo, '') AS service_extrainfo "
                    "FROM portObj AS p "
                    "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                    "WHERE p.hostId = :host_id "
                    "ORDER BY p.id ASC LIMIT 280"
                ), {
                    "host_id": int(host_id or 0),
                })
                host_port_rows = host_port_result.fetchall()

                script_result = session.execute(text(
                    "SELECT COALESCE(s.scriptId, '') AS script_id, "
                    "COALESCE(s.output, '') AS output, "
                    "COALESCE(p.portId, '') AS port_id, "
                    "COALESCE(p.protocol, '') AS protocol "
                    "FROM l1ScriptObj AS s "
                    "LEFT JOIN portObj AS p ON p.id = s.portId "
                    "WHERE s.hostId = :host_id "
                    "ORDER BY s.id DESC LIMIT 260"
                ), {
                    "host_id": int(host_id or 0),
                })
                script_rows = script_result.fetchall()

                process_result = session.execute(text(
                    "SELECT COALESCE(p.name, '') AS tool_id, "
                    "COALESCE(p.status, '') AS status, "
                    "COALESCE(p.command, '') AS command_text, "
                    "COALESCE(o.output, '') AS output_text, "
                    "COALESCE(p.port, '') AS port, "
                    "COALESCE(p.protocol, '') AS protocol "
                    "FROM process AS p "
                    "LEFT JOIN process_output AS o ON o.processId = p.id "
                    "WHERE COALESCE(p.hostIp, '') = :host_ip "
                    "ORDER BY p.id DESC LIMIT 180"
                ), {
                    "host_ip": str(host_ip or ""),
                })
                process_rows = process_result.fetchall()
            finally:
                session.close()

        # Host CVEs are included in scheduler context and coverage scoring.
        # Keep this resilient so planning still works even if CVE reads fail.
        try:
            host_cves_raw = self._load_cves_for_host(project, int(host_id or 0))
        except Exception:
            host_cves_raw = []

        target_port_value = str(port or "")
        target_protocol_value = str(protocol or "tcp").lower()

        port_scripts: Dict[Tuple[str, str], List[str]] = {}
        port_banners: Dict[Tuple[str, str], str] = {}
        scripts = []
        target_scripts = []
        for row in script_rows:
            script_id = str(row[0] or "").strip()
            output = self._truncate_scheduler_text(row[1], int(recent_output_chars))
            script_port = str(row[2] or "").strip()
            script_protocol = str(row[3] or "tcp").strip().lower() or "tcp"
            if not script_id and not output:
                continue
            item = {
                "script_id": script_id,
                "port": script_port,
                "protocol": script_protocol,
                "excerpt": output,
            }
            scripts.append(item)
            if not script_port or (script_port == target_port_value and script_protocol == target_protocol_value):
                target_scripts.append(item)

            if script_port:
                key = (script_port, script_protocol)
                if script_id:
                    port_scripts.setdefault(key, []).append(script_id)
                if key not in port_banners:
                    candidate_banner = self._scheduler_banner_from_evidence(script_id, output)
                    if candidate_banner:
                        port_banners[key] = candidate_banner

        recent_processes = []
        target_recent_processes = []
        for row in process_rows:
            tool_id = str(row[0] or "").strip()
            status = str(row[1] or "").strip()
            command_text = self._truncate_scheduler_text(row[2], 220)
            output_text = self._truncate_scheduler_text(row[3], int(recent_output_chars))
            process_port = str(row[4] or "").strip()
            process_protocol = str(row[5] or "tcp").strip().lower() or "tcp"
            if not tool_id and not output_text:
                continue
            item = {
                "tool_id": tool_id,
                "status": status,
                "port": process_port,
                "protocol": process_protocol,
                "command_excerpt": command_text,
                "output_excerpt": output_text,
            }
            recent_processes.append(item)
            if process_port == target_port_value and process_protocol == target_protocol_value:
                target_recent_processes.append(item)

            if process_port:
                key = (process_port, process_protocol)
                if key not in port_banners:
                    candidate_banner = self._scheduler_banner_from_evidence(tool_id, output_text)
                    if candidate_banner:
                        port_banners[key] = candidate_banner

        host_port_inventory = []
        host_open_services = set()
        host_open_ports = []
        host_banner_hints = []
        for row in host_port_rows:
            port_value = str(row[0] or "").strip()
            port_protocol = str(row[1] or "tcp").strip().lower() or "tcp"
            state_value = str(row[2] or "").strip()
            service_value = str(row[3] or "").strip()
            product_value = str(row[4] or "").strip()
            version_value = str(row[5] or "").strip()
            extra_value = str(row[6] or "").strip()

            key = (port_value, port_protocol)
            banner_value = str(port_banners.get(key, "") or "")
            if not banner_value:
                banner_value = self._scheduler_service_banner_fallback(
                    service_name=service_value,
                    product=product_value,
                    version=version_value,
                    extrainfo=extra_value,
                )
            if state_value in {"open", "open|filtered"}:
                if service_value:
                    host_open_services.add(service_value)
                if port_value:
                    host_open_ports.append(f"{port_value}/{port_protocol}:{service_value or 'unknown'}")
                if banner_value:
                    host_banner_hints.append(f"{port_value}/{port_protocol}:{banner_value}")

            host_port_inventory.append({
                "port": port_value,
                "protocol": port_protocol,
                "state": state_value,
                "service": service_value,
                "service_product": product_value,
                "service_version": version_value,
                "service_extrainfo": extra_value,
                "banner": banner_value,
                "scripts": port_scripts.get(key, [])[:12],
            })

        inferred_technologies = self._infer_technologies_from_observations(
            service_records=[
                {
                    "port": str(item.get("port", "") or ""),
                    "protocol": str(item.get("protocol", "") or ""),
                    "service_name": str(item.get("service", "") or ""),
                    "service_product": str(item.get("service_product", "") or ""),
                    "service_version": str(item.get("service_version", "") or ""),
                    "service_extrainfo": str(item.get("service_extrainfo", "") or ""),
                    "banner": str(item.get("banner", "") or ""),
                }
                for item in host_port_inventory
                if isinstance(item, dict)
            ],
            script_records=scripts,
            process_records=recent_processes,
            limit=64,
        )

        target_data = {
            "host_ip": str(host_ip or ""),
            "hostname": str(hostname or ""),
            "os": str(os_match or ""),
            "port": str(port or ""),
            "protocol": str(protocol or "tcp"),
            "service": str(target_service or service_name or ""),
            "service_product": str(service_product or ""),
            "service_version": str(service_version or ""),
            "service_extrainfo": str(service_extrainfo or ""),
            "host_open_services": sorted(host_open_services)[:48],
            "host_open_ports": host_open_ports[:120],
            "host_banners": host_banner_hints[:80],
            "shodan_enabled": bool(
                str(getattr(settings, "tools_pyshodan_api_key", "") or "").strip()
                and str(getattr(settings, "tools_pyshodan_api_key", "") or "").strip().lower() not in {
                    "yourkeygoeshere",
                    "changeme",
                }
            ),
        }
        signals = self._extract_scheduler_signals(
            service_name=target_data["service"],
            scripts=scripts,
            recent_processes=recent_processes,
            target=target_data,
        )

        ai_state = self._load_host_ai_analysis(project, int(host_id or 0), str(host_ip or ""))
        ai_context_state = {}
        if isinstance(ai_state, dict) and ai_state:
            host_updates = ai_state.get("host_updates", {}) if isinstance(ai_state.get("host_updates", {}), dict) else {}

            ai_tech = []
            for item in ai_state.get("technologies", [])[:24]:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()[:120]
                version = str(item.get("version", "")).strip()[:120]
                cpe = str(item.get("cpe", "")).strip()[:220]
                evidence = self._truncate_scheduler_text(item.get("evidence", ""), 260)
                if not name and not cpe:
                    continue
                ai_tech.append({
                    "name": name,
                    "version": version,
                    "cpe": cpe,
                    "evidence": evidence,
                })

            ai_findings = []
            for item in ai_state.get("findings", [])[:24]:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title", "")).strip()[:240]
                severity = str(item.get("severity", "")).strip().lower()[:16]
                cve_id = str(item.get("cve", "")).strip()[:64]
                evidence = self._truncate_scheduler_text(item.get("evidence", ""), 260)
                if not title and not cve_id:
                    continue
                ai_findings.append({
                    "title": title,
                    "severity": severity,
                    "cve": cve_id,
                    "evidence": evidence,
                })

            ai_manual_tests = []
            for item in ai_state.get("manual_tests", [])[:16]:
                if not isinstance(item, dict):
                    continue
                command = self._truncate_scheduler_text(item.get("command", ""), 260)
                why = self._truncate_scheduler_text(item.get("why", ""), 180)
                if not command and not why:
                    continue
                ai_manual_tests.append({
                    "command": command,
                    "why": why,
                    "scope_note": self._truncate_scheduler_text(item.get("scope_note", ""), 160),
                })

            merged_context_tech = self._merge_technologies(
                existing=inferred_technologies,
                incoming=ai_tech,
                limit=64,
            )

            ai_context_state = {
                "updated_at": str(ai_state.get("updated_at", "") or ""),
                "provider": str(ai_state.get("provider", "") or ""),
                "goal_profile": str(ai_state.get("goal_profile", "") or ""),
                "next_phase": str(ai_state.get("next_phase", "") or ""),
                "host_updates": {
                    "hostname": str(host_updates.get("hostname", "") or ""),
                    "hostname_confidence": self._ai_confidence_value(host_updates.get("hostname_confidence", 0.0)),
                    "os": str(host_updates.get("os", "") or ""),
                    "os_confidence": self._ai_confidence_value(host_updates.get("os_confidence", 0.0)),
                },
                "technologies": merged_context_tech,
                "findings": ai_findings,
                "manual_tests": ai_manual_tests,
            }

            ai_observed_tech = [
                str(item.get("name", "")).strip().lower()
                for item in merged_context_tech
                if isinstance(item, dict) and str(item.get("name", "")).strip()
            ]
            if ai_observed_tech:
                existing_observed = signals.get("observed_technologies", [])
                if not isinstance(existing_observed, list):
                    existing_observed = []
                merged_observed = []
                seen_observed = set()
                for marker in existing_observed + ai_observed_tech:
                    token = str(marker or "").strip().lower()
                    if not token or token in seen_observed:
                        continue
                    seen_observed.add(token)
                    merged_observed.append(token)
                if merged_observed:
                    signals["observed_technologies"] = merged_observed[:24]
        elif inferred_technologies:
            ai_context_state = {
                "updated_at": "",
                "provider": "",
                "goal_profile": "",
                "next_phase": "",
                "host_updates": {
                    "hostname": "",
                    "hostname_confidence": 0.0,
                    "os": "",
                    "os_confidence": 0.0,
                },
                "technologies": inferred_technologies,
                "findings": [],
                "manual_tests": [],
            }
            inferred_names = [
                str(item.get("name", "")).strip().lower()
                for item in inferred_technologies
                if isinstance(item, dict) and str(item.get("name", "")).strip()
            ]
            if inferred_names:
                existing_observed = signals.get("observed_technologies", [])
                if not isinstance(existing_observed, list):
                    existing_observed = []
                merged_observed = []
                seen_observed = set()
                for marker in existing_observed + inferred_names:
                    token = str(marker or "").strip().lower()
                    if not token or token in seen_observed:
                        continue
                    seen_observed.add(token)
                    merged_observed.append(token)
                if merged_observed:
                    signals["observed_technologies"] = merged_observed[:24]

        host_cves = []
        for row in host_cves_raw[:120]:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name", "") or "").strip()[:96]
            severity = str(row.get("severity", "") or "").strip().lower()[:24]
            product = str(row.get("product", "") or "").strip()[:120]
            version = str(row.get("version", "") or "").strip()[:80]
            url = str(row.get("url", "") or "").strip()[:220]
            if not any([name, severity, product, version, url]):
                continue
            host_cves.append({
                "name": name,
                "severity": severity,
                "product": product,
                "version": version,
                "url": url,
            })

        observed_tool_ids = set()
        observed_tool_ids.update({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()})
        for item in scripts:
            if not isinstance(item, dict):
                continue
            token = str(item.get("script_id", "")).strip().lower()
            if token:
                observed_tool_ids.add(token)
        for item in recent_processes:
            if not isinstance(item, dict):
                continue
            token = str(item.get("tool_id", "")).strip().lower()
            if token:
                observed_tool_ids.add(token)

        coverage = self._build_scheduler_coverage_summary(
            service_name=str(target_data.get("service", "") or service_name or ""),
            signals=signals,
            observed_tool_ids=observed_tool_ids,
            host_cves=host_cves,
            inferred_technologies=inferred_technologies,
            analysis_mode=analysis_mode,
        )

        return {
            "target": target_data,
            "signals": signals,
            "attempted_tool_ids": sorted({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}),
            "host_ports": host_port_inventory,
            "scripts": scripts,
            "recent_processes": recent_processes,
            "target_scripts": target_scripts,
            "target_recent_processes": target_recent_processes,
            "inferred_technologies": inferred_technologies[:64],
            "host_cves": host_cves,
            "coverage": coverage,
            "analysis_mode": str(analysis_mode or "standard").strip().lower() or "standard",
            "host_ai_state": ai_context_state,
        }

    @staticmethod
    def _build_scheduler_coverage_summary(
            *,
            service_name: str,
            signals: Dict[str, Any],
            observed_tool_ids: set,
            host_cves: List[Dict[str, Any]],
            inferred_technologies: List[Dict[str, str]],
            analysis_mode: str,
    ) -> Dict[str, Any]:
        tool_ids = {str(item or "").strip().lower() for item in list(observed_tool_ids or set()) if str(item or "").strip()}
        service_lower = str(service_name or "").strip().rstrip("?").lower()
        signal_map = signals if isinstance(signals, dict) else {}

        is_web = bool(signal_map.get("web_service")) or service_lower in SchedulerPlanner.WEB_SERVICE_IDS
        is_rdp = bool(signal_map.get("rdp_service"))
        is_vnc = bool(signal_map.get("vnc_service"))
        is_smb = service_lower in {"microsoft-ds", "netbios-ssn", "smb"}

        def _has_tool_prefix(prefix: str) -> bool:
            token = str(prefix or "").strip().lower()
            return any(item.startswith(token) for item in tool_ids)

        def _has_any(*tool_names: str) -> bool:
            for tool_name in tool_names:
                token = str(tool_name or "").strip().lower()
                if token and (token in tool_ids or _has_tool_prefix(token)):
                    return True
            return False

        has_discovery = _has_any("nmap", "banner", "fingerprint-strings", "http-title", "ssl-cert")
        has_screenshot = _has_any("screenshooter")
        has_nmap_vuln = _has_any("nmap-vuln.nse")
        has_nuclei = _has_any("nuclei-web", "nuclei")
        has_whatweb = _has_any("whatweb", "whatweb-http", "whatweb-https")
        has_nikto = _has_any("nikto")
        has_web_content = _has_any("web-content-discovery")
        has_smb_signing_checks = _has_any("smb-security-mode", "smb2-security-mode")
        confident_cpe_count = 0
        for item in inferred_technologies[:120]:
            if not isinstance(item, dict):
                continue
            cpe = str(item.get("cpe", "") or "").strip()
            if not cpe:
                continue
            quality = WebRuntime._technology_quality_score(
                name=item.get("name", ""),
                version=item.get("version", ""),
                cpe=cpe,
                evidence=item.get("evidence", ""),
            )
            if quality >= 52:
                confident_cpe_count += 1

        missing: List[str] = []
        recommended_tool_ids: List[str] = []

        def _add_gap(reason: str, *recommended: str):
            token = str(reason or "").strip().lower()
            if token and token not in missing:
                missing.append(token)
            for item in recommended:
                tool_id = str(item or "").strip().lower()
                if tool_id and tool_id not in recommended_tool_ids:
                    recommended_tool_ids.append(tool_id)

        if not has_discovery:
            _add_gap("missing_discovery", "nmap")

        if is_web:
            if not has_screenshot:
                _add_gap("missing_screenshot", "screenshooter")
            if not has_nmap_vuln:
                _add_gap("missing_nmap_vuln", "nmap-vuln.nse")
            if not has_nuclei:
                _add_gap("missing_nuclei_auto", "nuclei-web")
            if (
                    confident_cpe_count > 0
                    and not (has_nmap_vuln and has_nuclei)
                    and int(len(host_cves or [])) == 0
                    and int(signal_map.get("vuln_hits", 0) or 0) == 0
            ):
                _add_gap("missing_cpe_cve_enrichment", "nmap-vuln.nse", "nuclei-web")
            if not inferred_technologies and not has_whatweb:
                _add_gap("missing_technology_fingerprint", "whatweb")
            if has_nmap_vuln or has_nuclei:
                if not has_whatweb:
                    _add_gap("missing_whatweb", "whatweb", "whatweb-http", "whatweb-https")
                if not has_nikto:
                    _add_gap("missing_nikto", "nikto")
                if not has_web_content:
                    _add_gap("missing_web_content_discovery", "web-content-discovery")
        else:
            if not has_screenshot and (is_rdp or is_vnc):
                _add_gap("missing_remote_screenshot", "screenshooter")
            if not (is_rdp or is_vnc) and not _has_any("banner"):
                _add_gap("missing_banner", "banner")
            if is_smb and not has_smb_signing_checks:
                _add_gap("missing_smb_signing_checks", "smb-security-mode", "smb2-security-mode")

        if int(len(host_cves or [])) > 0:
            if is_web and not (has_whatweb and has_nikto and has_web_content):
                _add_gap("missing_followup_after_vuln", "whatweb", "nikto", "web-content-discovery")
            if is_smb and not has_smb_signing_checks:
                _add_gap("missing_smb_followup_after_vuln", "smb-security-mode", "smb2-security-mode")

        if str(analysis_mode or "").strip().lower() == "dig_deeper" and not missing:
            if is_web and not _has_any("wafw00f", "sslscan", "sslyze"):
                _add_gap("missing_deep_tls_waf_checks", "wafw00f", "sslscan", "sslyze")

        stage = "baseline"
        if not missing:
            stage = "post_baseline"
        if str(analysis_mode or "").strip().lower() == "dig_deeper":
            stage = "dig_deeper" if missing else "deep_analysis"

        return {
            "analysis_mode": str(analysis_mode or "standard").strip().lower() or "standard",
            "stage": stage,
            "missing": missing[:24],
            "recommended_tool_ids": recommended_tool_ids[:32],
            "observed_tool_ids": sorted(tool_ids)[:180],
            "has": {
                "discovery": bool(has_discovery),
                "screenshot": bool(has_screenshot),
                "nmap_vuln": bool(has_nmap_vuln),
                "nuclei_auto": bool(has_nuclei),
                "whatweb": bool(has_whatweb),
                "nikto": bool(has_nikto),
                "web_content_discovery": bool(has_web_content),
                "smb_signing_checks": bool(has_smb_signing_checks),
                "confident_cpe_count": int(confident_cpe_count),
            },
            "host_cve_count": int(len(host_cves or [])),
        }

    @staticmethod
    def _scheduler_banner_from_evidence(source_id: Any, text_value: Any) -> str:
        source = str(source_id or "").strip().lower()
        if not source:
            return ""

        interesting = (
            source == "banner"
            or source.startswith("banner-")
            or source in {
                "http-title",
                "http-server-header",
                "ssl-cert",
                "ssh-hostkey",
                "smb-os-discovery",
                "fingerprint-strings",
                "smtp-commands",
                "imap-capabilities",
                "pop3-capabilities",
            }
        )
        if not interesting:
            return ""

        cleaned = WebRuntime._truncate_scheduler_text(text_value, 280)
        if not cleaned:
            return ""
        if cleaned.lower().startswith("starting nmap"):
            return ""
        return cleaned

    @staticmethod
    def _scheduler_service_banner_fallback(*, service_name: str, product: str, version: str, extrainfo: str) -> str:
        parts = []
        product_value = str(product or "").strip()
        version_value = str(version or "").strip()
        extra_value = str(extrainfo or "").strip()
        service_value = str(service_name or "").strip()

        if product_value:
            parts.append(product_value)
        if version_value and version_value.lower() not in product_value.lower():
            parts.append(version_value)
        if extra_value:
            parts.append(extra_value)
        if not parts and service_value:
            parts.append(service_value)

        if not parts:
            return ""
        return WebRuntime._truncate_scheduler_text(" ".join(parts), 200)

    @staticmethod
    def _truncate_scheduler_text(value: Any, max_chars: int) -> str:
        text_value = str(value or "").replace("\r", " ").replace("\x00", " ")
        text_value = " ".join(text_value.split())
        if len(text_value) <= int(max_chars):
            return text_value
        return text_value[:int(max_chars)].rstrip() + "...[truncated]"

    def _extract_scheduler_signals(
            self,
            *,
            service_name: str,
            scripts: List[Dict[str, Any]],
            recent_processes: List[Dict[str, Any]],
            target: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        service_lower = str(service_name or "").strip().lower()
        target_meta = target if isinstance(target, dict) else {}
        target_blob = " ".join([
            str(target_meta.get("hostname", "") or ""),
            str(target_meta.get("os", "") or ""),
            str(target_meta.get("service", "") or ""),
            str(target_meta.get("service_product", "") or ""),
            str(target_meta.get("service_version", "") or ""),
            str(target_meta.get("service_extrainfo", "") or ""),
            " ".join(str(item or "") for item in target_meta.get("host_open_services", []) if str(item or "").strip()),
            " ".join(str(item or "") for item in target_meta.get("host_open_ports", []) if str(item or "").strip()),
            " ".join(str(item or "") for item in target_meta.get("host_banners", []) if str(item or "").strip()),
        ]).lower()
        script_blob = "\n".join(
            f"{str(item.get('script_id', '')).strip()} {str(item.get('excerpt', '')).strip()}"
            for item in scripts
        ).lower()
        process_blob = "\n".join(
            f"{str(item.get('tool_id', '')).strip()} {str(item.get('status', '')).strip()} "
            f"{str(item.get('output_excerpt', '')).strip()}"
            for item in recent_processes
        ).lower()
        combined = f"{target_blob}\n{script_blob}\n{process_blob}"

        missing_tools = set()
        for match in re.findall(r"\b([a-z0-9._+-]+)\s+(?:not found|command not found)\b", combined):
            token = str(match or "").strip().lower()
            if token and len(token) <= 48:
                missing_tools.add(token)
        for match in re.findall(r"(?:/bin/sh:\s*)?([a-z0-9._+-]+):\s*(?:not found|command not found)", combined):
            token = str(match or "").strip().lower()
            if token and len(token) <= 48:
                missing_tools.add(token)

        cve_hits = set(re.findall(r"\bcve-\d{4}-\d+\b", combined))
        allow_blob = ""
        allow_match = re.search(r"allow:\s*([^\n]+)", combined)
        if allow_match:
            allow_blob = str(allow_match.group(1) or "").lower()
        webdav_via_allow = any(token in allow_blob for token in ["propfind", "proppatch", "mkcol", "copy", "move"])

        iis_detected = any(token in combined for token in [
            "microsoft-iis",
            " iis ",
            "iis/7",
            "iis/8",
            "iis/10",
        ])
        webdav_detected = (
            "webdav" in combined
            or webdav_via_allow
            or ("dav" in combined and ("propfind" in combined or "proppatch" in combined))
        )
        vmware_detected = any(token in combined for token in ["vmware", "vsphere", "vcenter", "esxi"])
        coldfusion_detected = any(token in combined for token in ["coldfusion", "cfusion", "adobe coldfusion", "jrun"])
        huawei_detected = any(token in combined for token in ["huawei", "hg5x", "hgw"])
        ubiquiti_detected = any(token in combined for token in ["ubiquiti", "unifi", "dream machine", "udm"])

        observed_technologies = []
        for marker, present in (
                ("iis", iis_detected),
                ("webdav", webdav_detected),
                ("vmware", vmware_detected),
                ("coldfusion", coldfusion_detected),
                ("huawei", huawei_detected),
                ("ubiquiti", ubiquiti_detected),
                ("wordpress", "wordpress" in combined or "wp-content" in combined),
                ("nginx", "nginx" in combined),
                ("apache", "apache" in combined),
        ):
            if present:
                observed_technologies.append(marker)

        signals = {
            "web_service": service_lower in SchedulerPlanner.WEB_SERVICE_IDS,
            "rdp_service": service_lower in {"rdp", "ms-wbt-server", "vmrdp"},
            "vnc_service": service_lower in {"vnc", "vnc-http", "rfb"},
            "tls_detected": any(token in combined for token in ["ssl", "tls", "certificate", "https"]),
            "smb_signing_disabled": any(token in combined for token in [
                "message signing enabled but not required",
                "smb signing disabled",
                "signing: disabled",
                "signing: false",
            ]),
            "directory_listing": "index of /" in combined or "directory listing" in combined,
            "waf_detected": "waf" in combined,
            "shodan_enabled": bool(target_meta.get("shodan_enabled", False)),
            "wordpress_detected": "wordpress" in combined or "wp-content" in combined,
            "iis_detected": iis_detected,
            "webdav_detected": webdav_detected,
            "vmware_detected": vmware_detected,
            "coldfusion_detected": coldfusion_detected,
            "huawei_detected": huawei_detected,
            "ubiquiti_detected": ubiquiti_detected,
            "observed_technologies": observed_technologies[:12],
            "vuln_hits": len(cve_hits),
            "missing_tools": sorted(missing_tools),
        }
        return signals

    @staticmethod
    def _ai_confidence_value(value: Any) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(parsed, 100.0))

    @staticmethod
    def _sanitize_ai_hostname(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "", raw)
        if len(cleaned) < 2:
            return ""
        return cleaned[:160]

    @staticmethod
    def _extract_cpe_tokens(value: Any, limit: int = 8) -> List[str]:
        text_value = str(value or "").strip()
        if not text_value:
            return []
        found = []
        seen = set()
        for pattern in (_CPE22_TOKEN_RE, _CPE23_TOKEN_RE):
            for match in pattern.findall(text_value):
                token = str(match or "").strip().lower()
                if not token or token in seen:
                    continue
                seen.add(token)
                found.append(token[:220])
                if len(found) >= int(limit):
                    return found
        return found

    @staticmethod
    def _extract_version_token(value: Any) -> str:
        text_value = str(value or "").strip()
        if not text_value:
            return ""
        match = _TECH_VERSION_RE.search(text_value)
        if not match:
            return ""
        return WebRuntime._sanitize_technology_version(match.group(1))

    @staticmethod
    def _is_ipv4_like(value: Any) -> bool:
        token = str(value or "").strip()
        if not token or not _IPV4_LIKE_RE.match(token):
            return False
        try:
            return all(0 <= int(part) <= 255 for part in token.split("."))
        except Exception:
            return False

    @staticmethod
    def _sanitize_technology_version(value: Any) -> str:
        token = str(value or "").strip().strip("[](){};,")
        if not token:
            return ""
        if len(token) > 80:
            token = token[:80]
        lowered = token.lower()
        if lowered in {"unknown", "generic", "none", "n/a", "na", "-", "*"}:
            return ""
        if WebRuntime._is_ipv4_like(token):
            return ""
        if "/" in token and not re.search(r"\d", token):
            return ""
        if not re.search(r"[0-9]", token):
            return ""
        return token

    @staticmethod
    def _extract_version_near_tokens(value: Any, tokens: Any) -> str:
        text_value = str(value or "")
        if not text_value:
            return ""
        for raw_token in list(tokens or []):
            token = str(raw_token or "").strip().lower()
            if not token:
                continue
            token_pattern = re.escape(token)
            direct_match = re.search(
                rf"{token_pattern}(?:[^a-z0-9]{{0,24}})(?:version\s*)?v?(\d+(?:[._-][0-9a-z]+)+|\d+[a-z]+\d*)",
                text_value,
                flags=re.IGNORECASE,
            )
            if direct_match:
                version = WebRuntime._sanitize_technology_version(direct_match.group(1))
                if version:
                    return version

            lowered = text_value.lower()
            search_at = lowered.find(token)
            while search_at >= 0:
                window = text_value[search_at: search_at + 160]
                version = WebRuntime._extract_version_token(window)
                if version and (("." in version) or bool(re.search(r"[a-z]", version, flags=re.IGNORECASE))):
                    return version
                search_at = lowered.find(token, search_at + len(token))
        return ""

    @staticmethod
    def _normalize_cpe_token(value: Any) -> str:
        token = str(value or "").strip().lower()[:220]
        if not token:
            return ""
        if token.startswith("cpe:/"):
            parts = token.split(":")
            if len(parts) >= 5:
                version = WebRuntime._sanitize_technology_version(parts[4])
                if version:
                    parts[4] = version.lower()
                    return ":".join(parts)
                return ":".join(parts[:4])
            return token
        if token.startswith("cpe:2.3:"):
            parts = token.split(":")
            if len(parts) >= 6:
                version = WebRuntime._sanitize_technology_version(parts[5])
                if version:
                    parts[5] = version.lower()
                else:
                    parts[5] = "*"
                return ":".join(parts)
            return token
        return token

    @staticmethod
    def _cpe_base(value: Any) -> str:
        token = WebRuntime._normalize_cpe_token(value)
        if token.startswith("cpe:/"):
            parts = token.split(":")
            return ":".join(parts[:4]) if len(parts) >= 4 else token
        if token.startswith("cpe:2.3:"):
            parts = token.split(":")
            return ":".join(parts[:5]) if len(parts) >= 5 else token
        return token

    @staticmethod
    def _is_weak_technology_name(value: Any) -> bool:
        token = str(value or "").strip().lower()
        if not token:
            return False
        return token in _WEAK_TECH_NAME_TOKENS or token in _GENERIC_TECH_NAME_TOKENS

    @staticmethod
    def _technology_canonical_key(name: Any, cpe: Any) -> str:
        normalized_name = re.sub(r"[^a-z0-9]+", " ", str(name or "").strip().lower()).strip()
        cpe_base = WebRuntime._cpe_base(cpe)
        if normalized_name:
            return f"name:{normalized_name}"
        if cpe_base:
            return f"cpe:{cpe_base}"
        return ""

    @staticmethod
    def _technology_quality_score(*, name: Any, version: Any, cpe: Any, evidence: Any) -> int:
        score = 0
        tech_name = str(name or "").strip().lower()
        tech_version = WebRuntime._sanitize_technology_version(version)
        tech_cpe = WebRuntime._normalize_cpe_token(cpe)
        evidence_text = str(evidence or "").strip().lower()

        if tech_name and not WebRuntime._is_weak_technology_name(tech_name):
            score += 18
        if tech_version:
            score += 18
        if tech_cpe:
            score += 32
            if WebRuntime._version_from_cpe(tech_cpe):
                score += 6

        if "ssh banner" in evidence_text:
            score += 48
        elif "banner" in evidence_text:
            score += 22
        if "service " in evidence_text:
            score += 28
        if "output cpe" in evidence_text or "service cpe" in evidence_text:
            score += 20
        if "fingerprint" in evidence_text:
            score += 14
        if "whatweb" in evidence_text or "http-title" in evidence_text or "ssl-cert" in evidence_text:
            score += 12

        if WebRuntime._is_weak_technology_name(tech_name) and not tech_cpe:
            score -= 42
        if not tech_name and not tech_cpe:
            score -= 60

        return int(score)

    @staticmethod
    def _name_from_cpe(cpe: str) -> str:
        token = str(cpe or "").strip().lower()
        if token.startswith("cpe:/"):
            parts = token.split(":")
            if len(parts) >= 4:
                product = str(parts[3] or "").replace("_", " ").strip()
                return product[:120]
        if token.startswith("cpe:2.3:"):
            parts = token.split(":")
            if len(parts) >= 5:
                product = str(parts[4] or "").replace("_", " ").strip()
                return product[:120]
        return ""

    @staticmethod
    def _version_from_cpe(cpe: str) -> str:
        token = WebRuntime._normalize_cpe_token(cpe)
        if token.startswith("cpe:/"):
            parts = token.split(":")
            if len(parts) >= 5:
                return WebRuntime._sanitize_technology_version(parts[4])
            return ""
        if token.startswith("cpe:2.3:"):
            parts = token.split(":")
            if len(parts) >= 6:
                return WebRuntime._sanitize_technology_version(parts[5])
            return ""
        return ""

    @staticmethod
    def _guess_technology_hint(name_or_text: Any, version_hint: Any = "") -> Tuple[str, str]:
        hints = WebRuntime._guess_technology_hints(name_or_text, version_hint=version_hint)
        if hints:
            return hints[0]
        return "", ""

    @staticmethod
    def _guess_technology_hints(name_or_text: Any, version_hint: Any = "") -> List[Tuple[str, str]]:
        blob = str(name_or_text or "").strip().lower()
        version_text = str(version_hint or "")
        version = WebRuntime._extract_version_token(version_text)
        if version and ("." not in version) and (not re.search(r"[a-z]", version, flags=re.IGNORECASE)):
            version = ""
        if not blob:
            return []
        rows: List[Tuple[str, str]] = []
        seen = set()
        for tokens, normalized_name, cpe_base in _TECH_CPE_HINTS:
            if any(str(token).lower() in blob for token in tokens):
                version_candidate = WebRuntime._extract_version_near_tokens(version_text, tokens) or version
                normalized_cpe_base = str(cpe_base or "").strip().lower()
                if version_candidate and normalized_cpe_base:
                    cpe = f"{normalized_cpe_base}:{version_candidate}".lower()
                elif normalized_cpe_base:
                    cpe = normalized_cpe_base
                else:
                    cpe = ""
                key = f"{str(normalized_name).lower()}|{cpe}"
                if key in seen:
                    continue
                seen.add(key)
                rows.append((str(normalized_name), cpe))
        return rows

    def _infer_technologies_from_observations(
            self,
            *,
            service_records: List[Dict[str, Any]],
            script_records: List[Dict[str, Any]],
            process_records: List[Dict[str, Any]],
            limit: int = 180,
    ) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        seen = set()

        def _add(name: Any, version: Any, cpe: Any, evidence: Any):
            tech_name = str(name or "").strip()[:120]
            tech_version = self._sanitize_technology_version(version)
            tech_cpe = self._normalize_cpe_token(cpe)
            tech_evidence = self._truncate_scheduler_text(evidence, 520)

            if not tech_name and tech_cpe:
                tech_name = self._name_from_cpe(tech_cpe)
            if not tech_version and tech_cpe:
                tech_version = self._version_from_cpe(tech_cpe)

            if not tech_cpe:
                hinted_name, hinted_cpe = self._guess_technology_hint(tech_name, tech_version)
                if hinted_name and not tech_name:
                    tech_name = hinted_name
                if hinted_cpe:
                    tech_cpe = self._normalize_cpe_token(hinted_cpe)
                    if tech_cpe and not tech_version:
                        tech_version = self._version_from_cpe(tech_cpe)

            if not tech_name and not tech_cpe:
                return
            if self._is_weak_technology_name(tech_name) and not tech_cpe:
                if not any(marker in tech_evidence.lower() for marker in _TECH_STRONG_EVIDENCE_MARKERS):
                    return

            quality = self._technology_quality_score(
                name=tech_name,
                version=tech_version,
                cpe=tech_cpe,
                evidence=tech_evidence,
            )
            if quality < 20:
                return
            key = "|".join([tech_name.lower(), tech_version.lower(), tech_cpe.lower()])
            if key in seen:
                return
            seen.add(key)
            rows.append({
                "name": tech_name,
                "version": tech_version,
                "cpe": tech_cpe,
                "evidence": tech_evidence,
            })

        for record in service_records[:320]:
            if not isinstance(record, dict):
                continue
            service_name = str(record.get("service_name", "") or "").strip()
            product = str(record.get("service_product", "") or "").strip()
            version = str(record.get("service_version", "") or "").strip()
            extrainfo = str(record.get("service_extrainfo", "") or "").strip()
            banner = str(record.get("banner", "") or "").strip()
            port = str(record.get("port", "") or "").strip()
            protocol = str(record.get("protocol", "") or "").strip().lower()

            evidence_blob = " ".join([
                service_name,
                product,
                version,
                extrainfo,
                banner,
            ])
            cpes = self._extract_cpe_tokens(evidence_blob, limit=3)
            hinted_rows = self._guess_technology_hints(evidence_blob, version_hint=version)

            primary_name = product
            if not primary_name:
                service_token = service_name.lower()
                has_strong_context = bool(version or cpes or hinted_rows or banner or extrainfo)
                if (
                        service_name
                        and service_token not in _GENERIC_TECH_NAME_TOKENS
                        and not self._is_weak_technology_name(service_name)
                        and has_strong_context
                ):
                    primary_name = service_name
            if primary_name and primary_name.lower() not in {"unknown", "generic"}:
                _add(
                    primary_name,
                    version,
                    cpes[0] if cpes else "",
                    f"service {port}/{protocol} {service_name} {product} {version} {extrainfo}".strip(),
                )
            for hinted_name, hinted_cpe in hinted_rows:
                hinted_version = self._version_from_cpe(hinted_cpe) or version
                _add(
                    hinted_name or primary_name,
                    hinted_version,
                    hinted_cpe or (cpes[0] if cpes else ""),
                    f"service fingerprint {port}/{protocol}",
                )
            for token in cpes:
                _add("", "", token, f"service CPE {port}/{protocol}")
            if len(rows) >= int(limit):
                break

        for record in (script_records[:320] + process_records[:220]):
            if not isinstance(record, dict):
                continue
            source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()
            output = str(record.get("excerpt", "") or record.get("output_excerpt", "")).strip()
            if not output:
                continue
            cpes = self._extract_cpe_tokens(output, limit=4)
            for token in cpes:
                _add("", "", token, f"{source_id} output CPE")
            hinted_rows = self._guess_technology_hints(output, version_hint=output)
            for hinted_name, hinted_cpe in hinted_rows:
                version = self._version_from_cpe(hinted_cpe)
                if not version:
                    version = self._extract_version_near_tokens(output, [hinted_name])
                if not version and hinted_cpe:
                    version = self._extract_version_token(output)
                _add(
                    hinted_name,
                    version,
                    hinted_cpe,
                    f"{source_id} output fingerprint",
                )
            if len(rows) >= int(limit):
                break

        return self._normalize_ai_technologies(rows[:int(limit)])

    def _infer_host_technologies(self, project, host_id: int, host_ip: str = "") -> List[Dict[str, str]]:
        session = project.database.session()
        service_rows = []
        script_rows = []
        process_rows = []
        try:
            service_result = session.execute(text(
                "SELECT COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol, "
                "COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "ORDER BY p.id ASC LIMIT 320"
            ), {"host_id": int(host_id)})
            service_rows = service_result.fetchall()

            script_result = session.execute(text(
                "SELECT COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS output "
                "FROM l1ScriptObj AS s "
                "WHERE s.hostId = :host_id "
                "ORDER BY s.id DESC LIMIT 320"
            ), {"host_id": int(host_id)})
            script_rows = script_result.fetchall()

            host_ip_text = str(host_ip or "").strip()
            if host_ip_text:
                process_result = session.execute(text(
                    "SELECT COALESCE(p.name, '') AS tool_id, "
                    "COALESCE(o.output, '') AS output_text "
                    "FROM process AS p "
                    "LEFT JOIN process_output AS o ON o.processId = p.id "
                    "WHERE COALESCE(p.hostIp, '') = :host_ip "
                    "ORDER BY p.id DESC LIMIT 180"
                ), {"host_ip": host_ip_text})
                process_rows = process_result.fetchall()
        except Exception:
            service_rows = []
            script_rows = []
            process_rows = []
        finally:
            session.close()

        service_records = []
        for row in service_rows:
            service_records.append({
                "port": str(row[0] or "").strip(),
                "protocol": str(row[1] or "").strip().lower(),
                "service_name": str(row[2] or "").strip(),
                "service_product": str(row[3] or "").strip(),
                "service_version": str(row[4] or "").strip(),
                "service_extrainfo": str(row[5] or "").strip(),
                "banner": "",
            })

        script_records = []
        for row in script_rows:
            script_records.append({
                "script_id": str(row[0] or "").strip(),
                "excerpt": str(row[1] or "").strip(),
            })

        process_records = []
        for row in process_rows:
            process_records.append({
                "tool_id": str(row[0] or "").strip(),
                "output_excerpt": str(row[1] or "").strip(),
            })

        return self._infer_technologies_from_observations(
            service_records=service_records,
            script_records=script_records,
            process_records=process_records,
            limit=220,
        )

    def _normalize_ai_technologies(self, items: Any) -> List[Dict[str, str]]:
        if not isinstance(items, list):
            return []
        best_rows: Dict[str, Dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()[:120]
            cpe = self._normalize_cpe_token(item.get("cpe", ""))
            version = self._sanitize_technology_version(item.get("version", ""))
            evidence = self._truncate_scheduler_text(item.get("evidence", ""), 520)
            if not name and not cpe:
                continue
            if not name and cpe:
                name = self._name_from_cpe(cpe)
            if not version and cpe:
                version = self._version_from_cpe(cpe)
            if not cpe and name:
                hinted_name, hinted_cpe = self._guess_technology_hint(name, version)
                if hinted_name and not name:
                    name = hinted_name
                if hinted_cpe:
                    cpe = self._normalize_cpe_token(hinted_cpe)
                    if cpe and not version:
                        version = self._version_from_cpe(cpe)

            if self._is_weak_technology_name(name) and not cpe:
                if not any(marker in evidence.lower() for marker in _TECH_STRONG_EVIDENCE_MARKERS):
                    continue

            quality = self._technology_quality_score(
                name=name,
                version=version,
                cpe=cpe,
                evidence=evidence,
            )
            if quality < 20:
                continue

            canonical = self._technology_canonical_key(name, cpe) or "|".join([name.lower(), version.lower(), cpe.lower()])
            candidate = {
                "name": name,
                "version": version,
                "cpe": cpe,
                "evidence": evidence,
                "_quality": quality,
            }
            current = best_rows.get(canonical)
            if current is None:
                best_rows[canonical] = candidate
                continue

            if int(candidate["_quality"]) > int(current.get("_quality", 0)):
                best_rows[canonical] = candidate
                continue
            if int(candidate["_quality"]) == int(current.get("_quality", 0)):
                current_version = str(current.get("version", "") or "")
                if len(version) > len(current_version):
                    best_rows[canonical] = candidate
                    continue
                if cpe and not str(current.get("cpe", "") or ""):
                    best_rows[canonical] = candidate

        rows = sorted(
            list(best_rows.values()),
            key=lambda row: (
                -int(row.get("_quality", 0) or 0),
                str(row.get("name", "") or "").lower(),
                str(row.get("version", "") or "").lower(),
                str(row.get("cpe", "") or "").lower(),
            ),
        )
        trimmed: List[Dict[str, str]] = []
        for row in rows:
            trimmed.append({
                "name": str(row.get("name", "") or "")[:120],
                "version": str(row.get("version", "") or "")[:120],
                "cpe": str(row.get("cpe", "") or "")[:220],
                "evidence": self._truncate_scheduler_text(row.get("evidence", ""), 520),
            })
            if len(trimmed) >= 180:
                break
        return trimmed

    def _merge_technologies(
            self,
            *,
            existing: Any,
            incoming: Any,
            limit: int = 220,
    ) -> List[Dict[str, str]]:
        combined: List[Dict[str, Any]] = []
        if isinstance(incoming, list):
            for item in incoming:
                if isinstance(item, dict):
                    combined.append(dict(item))
        if isinstance(existing, list):
            for item in existing:
                if isinstance(item, dict):
                    combined.append(dict(item))
        rows = self._normalize_ai_technologies(combined)
        return rows[:int(limit)]

    @staticmethod
    def _severity_from_text(value: Any) -> str:
        token = str(value or "").strip().lower()
        if "critical" in token:
            return "critical"
        if "high" in token:
            return "high"
        if "medium" in token:
            return "medium"
        if "low" in token:
            return "low"
        return "info"

    def _infer_findings_from_observations(
            self,
            *,
            host_cves_raw: List[Dict[str, Any]],
            script_records: List[Dict[str, Any]],
            process_records: List[Dict[str, Any]],
            limit: int = 220,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        cve_index: Dict[str, Dict[str, Any]] = {}

        for row in host_cves_raw[:240]:
            if not isinstance(row, dict):
                continue
            cve_name = str(row.get("name", "") or "").strip().upper()
            matched = _CVE_TOKEN_RE.search(cve_name)
            cve_id = matched.group(0).upper() if matched else ""
            severity = self._severity_from_text(row.get("severity", ""))
            product = str(row.get("product", "") or "").strip()
            version = str(row.get("version", "") or "").strip()
            url = str(row.get("url", "") or "").strip()
            title = cve_id or cve_name or f"Potential vulnerability in {product or 'service'}"
            evidence = " | ".join(part for part in [
                f"product={product}" if product else "",
                f"version={version}" if version else "",
                f"url={url}" if url else "",
            ] if part)
            rows.append({
                "title": title,
                "severity": severity,
                "cvss": 0.0,
                "cve": cve_id,
                "evidence": evidence or title,
            })
            if cve_id:
                cve_index[cve_id] = {
                    "severity": severity,
                    "evidence": evidence or title,
                }

        for record in (script_records[:360] + process_records[:220]):
            if not isinstance(record, dict):
                continue
            source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()[:80]
            excerpt = str(record.get("excerpt", "") or record.get("output_excerpt", "")).strip()
            if not excerpt:
                continue
            for match in _CVE_TOKEN_RE.findall(excerpt):
                cve_id = str(match or "").strip().upper()
                if not cve_id:
                    continue
                mapped = cve_index.get(cve_id, {})
                severity = str(mapped.get("severity", "info") or "info")
                evidence = self._truncate_scheduler_text(
                    f"{source_id}: {excerpt}",
                    420,
                )
                rows.append({
                    "title": cve_id,
                    "severity": severity,
                    "cvss": 0.0,
                    "cve": cve_id,
                    "evidence": evidence,
                })

        normalized = self._normalize_ai_findings(rows)
        return normalized[:int(limit)]

    def _infer_host_findings(
            self,
            project,
            *,
            host_id: int,
            host_ip: str,
            host_cves_raw: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        cves = host_cves_raw if isinstance(host_cves_raw, list) else self._load_cves_for_host(project, int(host_id or 0))

        session = project.database.session()
        script_rows = []
        process_rows = []
        try:
            script_result = session.execute(text(
                "SELECT COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS output "
                "FROM l1ScriptObj AS s "
                "WHERE s.hostId = :host_id "
                "ORDER BY s.id DESC LIMIT 360"
            ), {"host_id": int(host_id)})
            script_rows = script_result.fetchall()

            if str(host_ip or "").strip():
                process_result = session.execute(text(
                    "SELECT COALESCE(p.name, '') AS tool_id, "
                    "COALESCE(o.output, '') AS output_text "
                    "FROM process AS p "
                    "LEFT JOIN process_output AS o ON o.processId = p.id "
                    "WHERE COALESCE(p.hostIp, '') = :host_ip "
                    "ORDER BY p.id DESC LIMIT 220"
                ), {"host_ip": str(host_ip or "").strip()})
                process_rows = process_result.fetchall()
        except Exception:
            script_rows = []
            process_rows = []
        finally:
            session.close()

        script_records = [
            {
                "script_id": str(row[0] or "").strip(),
                "excerpt": str(row[1] or "").strip(),
            }
            for row in script_rows
        ]
        process_records = [
            {
                "tool_id": str(row[0] or "").strip(),
                "output_excerpt": str(row[1] or "").strip(),
            }
            for row in process_rows
        ]

        return self._infer_findings_from_observations(
            host_cves_raw=cves,
            script_records=script_records,
            process_records=process_records,
            limit=220,
        )

    def _normalize_ai_findings(self, items: Any) -> List[Dict[str, Any]]:
        if not isinstance(items, list):
            return []
        allowed = {"critical", "high", "medium", "low", "info"}
        rows: List[Dict[str, Any]] = []
        seen = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()[:260]
            severity = str(item.get("severity", "info")).strip().lower()
            if severity not in allowed:
                severity = "info"
            cve_id = str(item.get("cve", "")).strip()[:64]
            cvss_value = self._ai_confidence_value(item.get("cvss"))
            if cvss_value > 10.0:
                cvss_value = 10.0
            evidence = self._truncate_scheduler_text(item.get("evidence", ""), 640)
            if not title and not cve_id:
                continue
            key = "|".join([title.lower(), cve_id.lower(), severity])
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "title": title,
                "severity": severity,
                "cvss": cvss_value,
                "cve": cve_id,
                "evidence": evidence,
            })
            if len(rows) >= 220:
                break
        rows.sort(key=lambda row: self._finding_sort_key(row), reverse=True)
        return rows

    @staticmethod
    def _finding_sort_key(item: Dict[str, Any]) -> Tuple[int, float]:
        severity_rank = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(str(item.get("severity", "info")).strip().lower(), 0)
        try:
            cvss = float(item.get("cvss", 0.0) or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        return severity_rank, cvss

    def _normalize_ai_manual_tests(self, items: Any) -> List[Dict[str, str]]:
        if not isinstance(items, list):
            return []
        rows: List[Dict[str, str]] = []
        seen = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            why = self._truncate_scheduler_text(item.get("why", ""), 320)
            command = self._truncate_scheduler_text(item.get("command", ""), 520)
            scope_note = self._truncate_scheduler_text(item.get("scope_note", ""), 280)
            if not command and not why:
                continue
            key = "|".join([command.lower(), why.lower()])
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "why": why,
                "command": command,
                "scope_note": scope_note,
            })
            if len(rows) >= 160:
                break
        return rows

    @staticmethod
    def _merge_ai_items(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], *, key_fields: List[str], limit: int) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen = set()
        for source in (incoming, existing):
            for item in source:
                if not isinstance(item, dict):
                    continue
                key_parts = [str(item.get(field, "")).strip().lower() for field in key_fields]
                key = "|".join(key_parts)
                if not key or key in seen:
                    continue
                seen.add(key)
                merged.append(dict(item))
                if len(merged) >= int(limit):
                    return merged
        return merged

    def _persist_scheduler_ai_analysis(
            self,
            *,
            host_id: int,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            goal_profile: str,
            provider_payload: Optional[Dict[str, Any]],
    ):
        payload = provider_payload if isinstance(provider_payload, dict) else {}

        host_updates_raw = payload.get("host_updates", {})
        if not isinstance(host_updates_raw, dict):
            host_updates_raw = {}

        provider_technologies = self._normalize_ai_technologies(
            host_updates_raw.get("technologies", [])
            or payload.get("technologies", [])
        )
        findings = self._normalize_ai_findings(payload.get("findings", []))
        manual_tests = self._normalize_ai_manual_tests(payload.get("manual_tests", []))

        hostname_candidate = self._sanitize_ai_hostname(host_updates_raw.get("hostname", ""))
        hostname_confidence = self._ai_confidence_value(host_updates_raw.get("hostname_confidence", 0.0))
        os_candidate = str(host_updates_raw.get("os", "")).strip()[:120]
        os_confidence = self._ai_confidence_value(host_updates_raw.get("os_confidence", 0.0))
        next_phase = str(payload.get("next_phase", "")).strip()[:80]

        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return
            try:
                host_cves_raw = self._load_cves_for_host(project, int(host_id or 0))
            except Exception:
                host_cves_raw = []
            inferred_technologies = self._infer_host_technologies(project, int(host_id), str(host_ip or ""))
            technologies = self._merge_technologies(
                existing=inferred_technologies,
                incoming=provider_technologies,
                limit=220,
            )
            inferred_findings = self._infer_host_findings(
                project,
                host_id=int(host_id),
                host_ip=str(host_ip or ""),
                host_cves_raw=host_cves_raw,
            )
            findings_combined = self._merge_ai_items(
                existing=inferred_findings,
                incoming=findings,
                key_fields=["title", "cve", "severity"],
                limit=260,
            )
            if not any([
                technologies,
                findings_combined,
                manual_tests,
                hostname_candidate,
                os_candidate,
                next_phase,
            ]):
                return
            ensure_scheduler_ai_state_table(project.database)
            existing = get_host_ai_state(project.database, int(host_id)) or {}

            merged_technologies = self._merge_technologies(
                existing=existing.get("technologies", []) if isinstance(existing.get("technologies", []), list) else [],
                incoming=technologies,
                limit=220,
            )
            merged_findings = self._merge_ai_items(
                existing=existing.get("findings", []) if isinstance(existing.get("findings", []), list) else [],
                incoming=findings_combined,
                key_fields=["title", "cve", "severity"],
                limit=260,
            )
            merged_manual = self._merge_ai_items(
                existing=existing.get("manual_tests", []) if isinstance(existing.get("manual_tests", []), list) else [],
                incoming=manual_tests,
                key_fields=["command", "why"],
                limit=200,
            )

            existing_hostname = self._sanitize_ai_hostname(existing.get("hostname", ""))
            existing_hostname_conf = self._ai_confidence_value(existing.get("hostname_confidence", 0.0))
            if hostname_candidate and hostname_confidence >= existing_hostname_conf:
                selected_hostname = hostname_candidate
                selected_hostname_conf = hostname_confidence
            else:
                selected_hostname = existing_hostname
                selected_hostname_conf = existing_hostname_conf

            existing_os = str(existing.get("os_match", "")).strip()[:120]
            existing_os_conf = self._ai_confidence_value(existing.get("os_confidence", 0.0))
            if os_candidate and os_confidence >= existing_os_conf:
                selected_os = os_candidate
                selected_os_conf = os_confidence
            else:
                selected_os = existing_os
                selected_os_conf = existing_os_conf

            state_payload = {
                "host_id": int(host_id),
                "host_ip": str(host_ip or ""),
                "provider": str(payload.get("provider", "") or existing.get("provider", "")),
                "goal_profile": str(goal_profile or existing.get("goal_profile", "")),
                "last_port": str(port or existing.get("last_port", "")),
                "last_protocol": str(protocol or existing.get("last_protocol", "")),
                "last_service": str(service_name or existing.get("last_service", "")),
                "hostname": selected_hostname,
                "hostname_confidence": selected_hostname_conf,
                "os_match": selected_os,
                "os_confidence": selected_os_conf,
                "next_phase": str(next_phase or existing.get("next_phase", "")),
                "technologies": merged_technologies,
                "findings": merged_findings,
                "manual_tests": merged_manual,
                "raw": payload,
            }
            upsert_host_ai_state(project.database, int(host_id), state_payload)

        self._apply_ai_host_updates(
            host_id=int(host_id),
            host_ip=str(host_ip or ""),
            hostname=hostname_candidate,
            hostname_confidence=hostname_confidence,
            os_match=os_candidate,
            os_confidence=os_confidence,
        )

    def _apply_ai_host_updates(
            self,
            *,
            host_id: int,
            host_ip: str,
            hostname: str,
            hostname_confidence: float,
            os_match: str,
            os_confidence: float,
    ):
        alias_to_add = ""
        safe_hostname = self._sanitize_ai_hostname(hostname)
        safe_os_match = str(os_match or "").strip()[:120]
        hostname_conf = self._ai_confidence_value(hostname_confidence)
        os_conf = self._ai_confidence_value(os_confidence)

        if not safe_hostname and not safe_os_match:
            return

        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return

            session = project.database.session()
            try:
                row = session.query(hostObj).filter_by(id=int(host_id)).first()
                if row is None and str(host_ip or "").strip():
                    row = session.query(hostObj).filter_by(ip=str(host_ip or "").strip()).first()
                if row is None:
                    return

                changed = False
                current_hostname = str(getattr(row, "hostname", "") or "")
                current_os = str(getattr(row, "osMatch", "") or "")

                if (
                        safe_hostname
                        and hostname_conf >= _AI_HOST_UPDATE_MIN_CONFIDENCE
                        and is_unknown_hostname(current_hostname)
                        and safe_hostname != current_hostname
                ):
                    row.hostname = safe_hostname
                    alias_to_add = safe_hostname
                    changed = True

                if (
                        safe_os_match
                        and os_conf >= _AI_HOST_UPDATE_MIN_CONFIDENCE
                        and is_unknown_os_match(current_os)
                        and safe_os_match != current_os
                ):
                    row.osMatch = safe_os_match
                    row.osAccuracy = str(int(round(os_conf)))
                    changed = True

                if changed:
                    session.add(row)
                    session.commit()
                else:
                    session.rollback()
            except Exception:
                session.rollback()
            finally:
                session.close()

        if alias_to_add:
            try:
                add_temporary_host_alias(str(host_ip or ""), alias_to_add)
            except Exception:
                pass

    def _enrich_host_from_observed_results(self, *, host_ip: str, port: str, protocol: str):
        alias_to_add = ""
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return

            session = project.database.session()
            try:
                row = session.query(hostObj).filter_by(ip=str(host_ip or "")).first()
                if row is None:
                    return

                need_hostname = is_unknown_hostname(str(getattr(row, "hostname", "") or ""))
                need_os = is_unknown_os_match(str(getattr(row, "osMatch", "") or ""))
                if not need_hostname and not need_os:
                    return

                script_records = []
                script_result = session.execute(text(
                    "SELECT COALESCE(s.scriptId, '') AS script_id, "
                    "COALESCE(s.output, '') AS output "
                    "FROM l1ScriptObj AS s "
                    "WHERE s.hostId = :host_id "
                    "ORDER BY s.id DESC LIMIT 240"
                ), {"host_id": int(getattr(row, "id", 0) or 0)})
                for item in script_result.fetchall():
                    script_id = str(item[0] or "").strip()
                    output = self._truncate_scheduler_text(item[1], 1400)
                    if script_id and output:
                        script_records.append((script_id, output))

                process_result = session.execute(text(
                    "SELECT COALESCE(p.name, '') AS tool_id, "
                    "COALESCE(o.output, '') AS output "
                    "FROM process AS p "
                    "LEFT JOIN process_output AS o ON o.processId = p.id "
                    "WHERE COALESCE(p.hostIp, '') = :host_ip "
                    "ORDER BY p.id DESC LIMIT 120"
                ), {
                    "host_ip": str(host_ip or ""),
                })
                for item in process_result.fetchall():
                    tool_id = str(item[0] or "").strip()
                    output = self._truncate_scheduler_text(item[1], 1400)
                    if tool_id and output:
                        script_records.append((tool_id, output))

                service_records = []
                service_result = session.execute(text(
                    "SELECT COALESCE(s.name, '') AS service_name, "
                    "COALESCE(s.product, '') AS product, "
                    "COALESCE(s.version, '') AS version, "
                    "COALESCE(s.extrainfo, '') AS extrainfo "
                    "FROM portObj AS p "
                    "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                    "WHERE p.hostId = :host_id "
                    "ORDER BY p.id DESC LIMIT 260"
                ), {"host_id": int(getattr(row, "id", 0) or 0)})
                for item in service_result.fetchall():
                    service_records.append((
                        str(item[0] or ""),
                        str(item[1] or ""),
                        str(item[2] or ""),
                        str(item[3] or ""),
                    ))

                changed = False
                if need_hostname:
                    inferred_hostname = infer_hostname_from_nmap_data(
                        str(getattr(row, "hostname", "") or ""),
                        script_records,
                    )
                    if inferred_hostname and is_unknown_hostname(str(getattr(row, "hostname", "") or "")):
                        row.hostname = inferred_hostname
                        alias_to_add = inferred_hostname
                        changed = True

                if need_os:
                    inferred_os = infer_os_from_nmap_scripts(script_records)
                    if not inferred_os:
                        inferred_os = infer_os_from_service_inventory(service_records)
                    if inferred_os and is_unknown_os_match(str(getattr(row, "osMatch", "") or "")):
                        row.osMatch = inferred_os
                        if not str(getattr(row, "osAccuracy", "") or "").strip():
                            row.osAccuracy = "80"
                        changed = True

                if changed:
                    session.add(row)
                    session.commit()
                else:
                    session.rollback()
            except Exception:
                session.rollback()
            finally:
                session.close()

        if alias_to_add:
            try:
                add_temporary_host_alias(str(host_ip or ""), alias_to_add)
            except Exception:
                pass

    def _execute_approved_scheduler_item(self, approval_id: int, job_id: int = 0) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            item = get_pending_approval(project.database, int(approval_id))
            if item is None:
                raise KeyError(f"Unknown approval id: {approval_id}")
            if str(item.get("status", "")).strip().lower() not in {"approved", "pending"}:
                return {"approval_id": int(approval_id), "status": item.get("status", "")}
            update_pending_approval(
                project.database,
                int(approval_id),
                status="running",
                decision_reason="approved & running",
            )
            update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=True,
                executed=False,
                reason="approved & running",
            )

        decision = ScheduledAction(
            tool_id=str(item.get("tool_id", "")),
            label=str(item.get("label", "")),
            command_template=str(item.get("command_template", "")),
            protocol=str(item.get("protocol", "tcp") or "tcp"),
            score=100.0,
            rationale=str(item.get("rationale", "")),
            mode=str(item.get("scheduler_mode", "ai") or "ai"),
            goal_profile=str(item.get("goal_profile", "") or ""),
            family_id=str(item.get("command_family_id", "")),
            danger_categories=self._split_csv(str(item.get("danger_categories", ""))),
            requires_approval=False,
        )

        executed, reason, process_id = self._execute_scheduler_decision(
            decision,
            host_ip=str(item.get("host_ip", "")),
            port=str(item.get("port", "")),
            protocol=str(item.get("protocol", "tcp") or "tcp"),
            service_name=str(item.get("service", "")),
            command_template=str(item.get("command_template", "")),
            timeout=300,
            job_id=int(job_id or 0),
        )

        with self._lock:
            project = self._require_active_project()
            final_reason = "approved & completed" if executed else f"approved & failed ({reason})"
            update_pending_approval(
                project.database,
                int(approval_id),
                status="executed" if executed else "failed",
                decision_reason=final_reason,
            )
            updated_decision = update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=True,
                executed=executed,
                reason=final_reason,
            )

        if updated_decision is None:
            self._record_scheduler_decision(
                decision,
                str(item.get("host_ip", "")),
                str(item.get("port", "")),
                str(item.get("protocol", "")),
                str(item.get("service", "")),
                approved=True,
                executed=executed,
                reason="approved & completed" if executed else f"approved & failed ({reason})",
                approval_id=int(approval_id),
            )

        if process_id and executed:
            self._save_script_result_if_missing(
                host_ip=str(item.get("host_ip", "")),
                port=str(item.get("port", "")),
                protocol=str(item.get("protocol", "")),
                tool_id=str(item.get("tool_id", "")),
                process_id=process_id,
            )

        return {
            "approval_id": int(approval_id),
            "executed": bool(executed),
            "reason": reason,
            "process_id": process_id,
        }

    def _execute_scheduler_decision(
            self,
            decision: ScheduledAction,
            *,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            command_template: str,
            timeout: int,
            job_id: int = 0,
    ) -> Tuple[bool, str, int]:
        if str(decision.tool_id) == "screenshooter":
            executed, reason = self._take_screenshot(host_ip, port, service_name=service_name)
            return executed, reason, 0

        if not command_template:
            return False, "skipped: no matching command template", 0

        command, outputfile = self._build_command(command_template, host_ip, port, protocol, decision.tool_id)
        tab_title = f"{decision.tool_id} ({port}/{protocol})"
        return self._run_command_with_tracking(
            tool_name=decision.tool_id,
            tab_title=tab_title,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            command=command,
            outputfile=outputfile,
            timeout=timeout,
            job_id=int(job_id or 0),
        )

    @staticmethod
    def _is_rdp_service(service_name: str) -> bool:
        value = str(service_name or "").strip().rstrip("?").lower()
        return value in {"rdp", "ms-wbt-server", "vmrdp", "ms-term-serv"}

    @staticmethod
    def _is_vnc_service(service_name: str) -> bool:
        value = str(service_name or "").strip().rstrip("?").lower()
        return value in {"vnc", "vnc-http", "rfb"}

    def _take_screenshot(self, host_ip: str, port: str, service_name: str = "") -> Tuple[bool, str]:
        normalized_service = str(service_name or "").strip().rstrip("?").lower()
        if self._is_rdp_service(normalized_service) or self._is_vnc_service(normalized_service):
            return self._take_remote_service_screenshot(
                host_ip=host_ip,
                port=port,
                service_name=normalized_service,
            )

        with self._lock:
            project = self._require_active_project()
            screenshots_dir = os.path.join(project.properties.outputFolder, "screenshots")
            os.makedirs(screenshots_dir, exist_ok=True)

        host_port = f"{host_ip}:{port}"
        prefer_https = bool(isHttps(host_ip, port))
        url_candidates = [
            f"https://{host_port}",
            f"http://{host_port}",
        ] if prefer_https else [
            f"http://{host_port}",
            f"https://{host_port}",
        ]

        capture = None
        failure_capture = None
        for url in url_candidates:
            current_capture = run_eyewitness_capture(
                url=url,
                output_parent_dir=screenshots_dir,
                delay=5,
                use_xvfb=True,
                timeout=180,
            )
            if current_capture.get("ok"):
                capture = current_capture
                break
            failure_capture = current_capture
            if str(current_capture.get("reason", "") or "") == "eyewitness missing":
                break

        if not capture:
            failed = failure_capture or {}
            reason = str(failed.get("reason", "") or "")
            if reason == "eyewitness missing":
                return False, "skipped: eyewitness missing"
            detail = summarize_eyewitness_failure(failed.get("attempts", []))
            if detail:
                return False, f"skipped: screenshot png missing ({detail})"
            return False, "skipped: screenshot png missing"

        src_path = str(capture.get("screenshot_path", "") or "")
        if not src_path or not os.path.isfile(src_path):
            return False, "skipped: screenshot output missing"

        deterministic_name = f"{host_ip}-{port}-screenshot.png"
        dst_path = os.path.join(screenshots_dir, deterministic_name)
        shutil.copy2(src_path, dst_path)
        returncode = int(capture.get("returncode", 0) or 0)
        if returncode != 0:
            return True, f"completed (eyewitness exited {returncode})"
        return True, "completed"

    def _take_remote_service_screenshot(self, *, host_ip: str, port: str, service_name: str) -> Tuple[bool, str]:
        with self._lock:
            project = self._require_active_project()
            screenshots_dir = os.path.join(project.properties.outputFolder, "screenshots")
            os.makedirs(screenshots_dir, exist_ok=True)

        deterministic_name = f"{host_ip}-{port}-screenshot.png"
        dst_path = os.path.join(screenshots_dir, deterministic_name)
        probe_host_port = f"{host_ip}:{port}"
        if os.path.isfile(dst_path):
            try:
                os.remove(dst_path)
            except Exception:
                pass

        commands = []
        if self._is_vnc_service(service_name):
            commands = [
                ["vncsnapshot", "-allowblank", "-quality", "85", f"{host_ip}::{port}", dst_path],
                ["vncsnapshot", "-allowblank", "-quality", "85", probe_host_port, dst_path],
                ["python3", "-m", "vncdotool", "-s", f"{host_ip}::{port}", "capture", dst_path],
            ]
        elif self._is_rdp_service(service_name):
            commands = [
                ["rdpy-rdpscreenshot", "-o", dst_path, probe_host_port],
                ["rdpy-rdpscreenshot", probe_host_port, dst_path],
            ]

        attempts = []
        for command in commands:
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=90,
                )
                output = self._truncate_scheduler_text(result.stdout or "", 260)
                attempts.append({
                    "command": " ".join(command),
                    "returncode": int(result.returncode),
                    "output": output,
                })
                if result.returncode == 0 and os.path.isfile(dst_path) and os.path.getsize(dst_path) > 0:
                    return True, "completed"
            except FileNotFoundError:
                attempts.append({
                    "command": " ".join(command),
                    "returncode": 127,
                    "output": "command not found",
                })
            except Exception as exc:
                attempts.append({
                    "command": " ".join(command),
                    "returncode": 1,
                    "output": self._truncate_scheduler_text(str(exc), 260),
                })

        detail_parts = []
        for item in attempts[:3]:
            detail_parts.append(
                f"{item.get('command', '')} rc={item.get('returncode', '')} {item.get('output', '')}".strip()
            )
        if detail_parts:
            return False, "skipped: remote screenshot missing (" + " | ".join(detail_parts) + ")"
        return False, "skipped: remote screenshot missing"

    def _run_command_with_tracking(
            self,
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
    ) -> Tuple[bool, str, int]:
        with self._lock:
            project = self._require_active_project()
            self._ensure_process_tables()
            process_repo = project.repositoryContainer.processRepository

        start_time = getTimestamp(True)
        stub = _WebProcessStub(
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
            with self._lock:
                self._ensure_process_tables()
            process_id = int(process_repo.storeProcess(stub) or 0)

        if process_id <= 0:
            return False, "error: failed to create process record", 0

        resolved_job_id = int(job_id or 0)
        if resolved_job_id > 0:
            self._register_job_process(resolved_job_id, int(process_id))
            if self.jobs.is_cancel_requested(resolved_job_id):
                process_repo.storeProcessCancelStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=0)
                process_repo.storeProcessOutput(str(process_id), "[cancelled before start]")
                self._unregister_job_process(int(process_id))
                return False, "killed", int(process_id)

        proc: Optional[subprocess.Popen] = None
        output_parts: List[str] = []
        output_queue: queue.Queue = queue.Queue()
        reader_done = threading.Event()
        started_at = time.monotonic()
        nmap_progress_state = {
            "percent": None,
            "remaining": None,
            "updated_at": 0.0,
        }
        is_nmap_command = self._is_nmap_command(str(tool_name), str(command))
        timed_out = False
        killed = False
        flush_due_at = started_at
        elapsed_due_at = started_at
        process_exited_at = None

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

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=(os.name != "nt"),
            )
            process_repo.storeProcessRunningStatus(str(process_id), str(proc.pid))
            with self._process_runtime_lock:
                self._active_processes[int(process_id)] = proc
                self._kill_requests.discard(int(process_id))

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
                    if is_nmap_command:
                        self._update_nmap_process_progress(
                            process_repo,
                            process_id=int(process_id),
                            text_chunk=str(chunk),
                            state=nmap_progress_state,
                        )

                now = time.monotonic()
                if changed and now >= flush_due_at:
                    self._write_process_output_partial(int(process_id), "".join(output_parts))
                    flush_due_at = now + 0.5

                if now >= elapsed_due_at:
                    elapsed_seconds = int(now - started_at)
                    try:
                        process_repo.storeProcessRunningElapsedTime(str(process_id), elapsed_seconds)
                    except Exception:
                        pass
                    elapsed_due_at = now + 1.0

                with self._process_runtime_lock:
                    kill_requested = int(process_id) in self._kill_requests
                if kill_requested and proc.poll() is None:
                    killed = True
                    self._signal_process_tree(proc, force=False)
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        self._signal_process_tree(proc, force=True)

                if resolved_job_id > 0 and self.jobs.is_cancel_requested(resolved_job_id) and proc.poll() is None:
                    killed = True
                    self._signal_process_tree(proc, force=False)
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        self._signal_process_tree(proc, force=True)

                if (now - started_at) > int(timeout) and proc.poll() is None:
                    timed_out = True
                    self._signal_process_tree(proc, force=True)

                if proc.poll() is not None:
                    if process_exited_at is None:
                        process_exited_at = now
                    if reader_done.is_set() and output_queue.empty():
                        break
                    if (now - process_exited_at) >= float(_PROCESS_READER_EXIT_GRACE_SECONDS):
                        # Avoid hanging indefinitely if descendants kept stdout open
                        # after the tracked shell process exited.
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
            if timed_out:
                combined_output += f"\n[timeout after {int(timeout)}s]"
                process_repo.storeProcessCrashStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=0)
                process_repo.storeProcessOutput(str(process_id), combined_output)
                return False, f"failed: timeout after {int(timeout)}s", int(process_id)

            if killed:
                process_repo.storeProcessKillStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=0)
                process_repo.storeProcessOutput(str(process_id), combined_output)
                return False, "killed", int(process_id)

            if int(proc.returncode or 0) != 0:
                process_repo.storeProcessCrashStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=0)
                process_repo.storeProcessOutput(str(process_id), combined_output)
                return False, f"failed: exit {proc.returncode}", int(process_id)

            try:
                process_repo.storeProcessProgress(
                    str(process_id),
                    percent="100",
                    estimated_remaining=0,
                )
            except Exception:
                pass

            process_repo.storeProcessOutput(str(process_id), combined_output)
            return True, "completed", int(process_id)
        except Exception as exc:
            process_repo.storeProcessCrashStatus(str(process_id))
            try:
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=0)
            except Exception:
                pass
            process_repo.storeProcessOutput(str(process_id), f"[error] {exc}\n{''.join(output_parts)}")
            return False, f"error: {exc}", int(process_id)
        finally:
            with self._process_runtime_lock:
                self._active_processes.pop(int(process_id), None)
                self._kill_requests.discard(int(process_id))
            self._unregister_job_process(int(process_id))

    def _write_process_output_partial(self, process_id: int, output_text: str):
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return
            self._ensure_process_tables()
            session = project.database.session()
            try:
                session.execute(text(
                    "INSERT INTO process_output (processId, output) "
                    "SELECT :process_id, '' "
                    "WHERE NOT EXISTS (SELECT 1 FROM process_output WHERE processId = :process_id)"
                ), {"process_id": int(process_id)})
                session.execute(text(
                    "UPDATE process_output SET output = :output WHERE processId = :process_id"
                ), {"process_id": int(process_id), "output": str(output_text)})
                session.commit()
            except Exception:
                session.rollback()
            finally:
                session.close()

    def _save_script_result_if_missing(self, host_ip: str, port: str, protocol: str, tool_id: str, process_id: int):
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
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

            process_output = self.get_process_output(int(process_id))
            output_text = str(process_output.get("output", "") or "")

            session = project.database.session()
            try:
                row = l1ScriptObj(str(tool_id), output_text, str(port_obj.id), str(host.id))
                session.add(row)
                session.commit()
            except Exception:
                session.rollback()
            finally:
                session.close()

    def _queue_scheduler_approval(
            self,
            decision: ScheduledAction,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            command_template: str,
    ) -> int:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_approval_table(project.database)
            return queue_pending_approval(project.database, {
                "status": "pending",
                "host_ip": str(host_ip),
                "port": str(port),
                "protocol": str(protocol),
                "service": str(service_name),
                "tool_id": str(decision.tool_id),
                "label": str(decision.label),
                "command_template": str(command_template or ""),
                "command_family_id": str(decision.family_id),
                "danger_categories": ",".join(decision.danger_categories),
                "scheduler_mode": str(decision.mode),
                "goal_profile": str(decision.goal_profile),
                "rationale": str(decision.rationale),
                "decision_reason": "pending approval",
                "execution_job_id": "",
            })

    def _record_scheduler_decision(
            self,
            decision: ScheduledAction,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            *,
            approved: bool,
            executed: bool,
            reason: str,
            approval_id: Optional[int] = None,
    ):
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return
            log_scheduler_decision(project.database, {
                "timestamp": getTimestamp(True),
                "host_ip": str(host_ip),
                "port": str(port),
                "protocol": str(protocol),
                "service": str(service_name),
                "scheduler_mode": str(decision.mode),
                "goal_profile": str(decision.goal_profile),
                "tool_id": str(decision.tool_id),
                "label": str(decision.label),
                "command_family_id": str(decision.family_id),
                "danger_categories": ",".join(decision.danger_categories),
                "requires_approval": "True" if decision.requires_approval else "False",
                "approved": "True" if approved else "False",
                "executed": "True" if executed else "False",
                "reason": str(reason),
                "rationale": str(decision.rationale),
                "approval_id": str(approval_id or ""),
            })

    def _project_metadata(self) -> Dict[str, Any]:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return {
                "name": "",
                "output_folder": "",
                "running_folder": "",
                "is_temporary": False,
                "autosave": {
                    "interval_minutes": 0,
                    "last_saved_at": self._autosave_last_saved_at,
                    "last_path": self._autosave_last_path,
                    "last_error": self._autosave_last_error,
                    "last_job_id": self._autosave_last_job_id,
                },
            }

        props = project.properties
        interval_seconds = self._get_autosave_interval_seconds()
        return {
            "name": str(getattr(props, "projectName", "")),
            "output_folder": str(getattr(props, "outputFolder", "")),
            "running_folder": str(getattr(props, "runningFolder", "")),
            "is_temporary": bool(getattr(props, "isTemporary", False)),
            "autosave": {
                "interval_minutes": int(interval_seconds / 60) if interval_seconds > 0 else 0,
                "last_saved_at": self._autosave_last_saved_at,
                "last_path": self._autosave_last_path,
                "last_error": self._autosave_last_error,
                "last_job_id": self._autosave_last_job_id,
            },
        }

    def _summary(self) -> Dict[str, int]:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return {
                "hosts": 0,
                "open_ports": 0,
                "services": 0,
                "cves": 0,
                "running_processes": 0,
                "finished_processes": 0,
            }

        session = project.database.session()
        try:
            hosts = session.execute(text("SELECT COUNT(*) FROM hostObj")).scalar() or 0
            open_ports = session.execute(
                text("SELECT COUNT(*) FROM portObj WHERE state = 'open' OR state = 'open|filtered'")
            ).scalar() or 0
            services = session.execute(text("SELECT COUNT(*) FROM serviceObj")).scalar() or 0
            cves_count = session.execute(text("SELECT COUNT(*) FROM cve")).scalar() or 0
            running_processes = session.execute(
                text("SELECT COUNT(*) FROM process WHERE status IN ('Running', 'Waiting')")
            ).scalar() or 0
            finished_processes = session.execute(
                text("SELECT COUNT(*) FROM process WHERE status = 'Finished'")
            ).scalar() or 0
            return {
                "hosts": int(hosts),
                "open_ports": int(open_ports),
                "services": int(services),
                "cves": int(cves_count),
                "running_processes": int(running_processes),
                "finished_processes": int(finished_processes),
            }
        except Exception:
            return {
                "hosts": 0,
                "open_ports": 0,
                "services": 0,
                "cves": 0,
                "running_processes": 0,
                "finished_processes": 0,
            }
        finally:
            session.close()

    @staticmethod
    def _count_running_or_waiting_processes(project) -> int:
        session = project.database.session()
        try:
            count = session.execute(
                text("SELECT COUNT(*) FROM process WHERE status IN ('Running', 'Waiting')")
            ).scalar()
            return int(count or 0)
        except Exception:
            return 0
        finally:
            session.close()

    @staticmethod
    def _zip_add_file_if_exists(archive: zipfile.ZipFile, src_path: str, arc_path: str):
        path = str(src_path or "").strip()
        if not path or not os.path.isfile(path):
            return
        archive.write(path, arcname=str(arc_path).replace("\\", "/"))

    @staticmethod
    def _zip_add_dir_if_exists(archive: zipfile.ZipFile, src_dir: str, arc_root: str):
        root = str(src_dir or "").strip()
        if not root or not os.path.isdir(root):
            return

        for base, _dirs, files in os.walk(root):
            for file_name in files:
                full_path = os.path.join(base, file_name)
                if not os.path.isfile(full_path):
                    continue
                rel_path = os.path.relpath(full_path, root)
                arc_path = os.path.join(arc_root, rel_path).replace("\\", "/")
                try:
                    archive.write(full_path, arcname=arc_path)
                except OSError:
                    continue

    @staticmethod
    def _bundle_prefix(root_prefix: str, leaf: str) -> str:
        root = str(root_prefix or "").strip("/")
        suffix = str(leaf or "").strip("/")
        if not suffix:
            return f"{root}/" if root else ""
        return f"{root}/{suffix}/" if root else f"{suffix}/"

    @staticmethod
    def _safe_bundle_filename(name: str, fallback: str = "restored.legion") -> str:
        candidate = os.path.basename(str(name or "").strip())
        if not candidate:
            candidate = str(fallback or "restored.legion")
        candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate)
        candidate = candidate.strip("._")
        if not candidate:
            candidate = str(fallback or "restored.legion")
        return candidate

    @staticmethod
    def _safe_bundle_relative_path(path: str) -> str:
        raw = str(path or "").replace("\\", "/").strip()
        if not raw:
            return ""
        raw = raw.lstrip("/")
        parts = []
        for piece in raw.split("/"):
            token = str(piece or "").strip()
            if not token or token == ".":
                continue
            if token == "..":
                return ""
            parts.append(token)
        return "/".join(parts)

    def _read_bundle_manifest(self, archive: zipfile.ZipFile) -> Tuple[str, str, Dict[str, Any]]:
        names = [str(item or "") for item in archive.namelist()]
        manifest_name = ""
        for name in names:
            normalized = name.rstrip("/")
            if normalized.endswith("/manifest.json") or normalized == "manifest.json":
                manifest_name = normalized
                break
        if not manifest_name:
            raise ValueError("Bundle manifest.json is missing.")

        try:
            raw_manifest = archive.read(manifest_name)
        except KeyError as exc:
            raise ValueError("Bundle manifest.json is missing.") from exc

        try:
            manifest = json.loads(raw_manifest.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Bundle manifest.json is invalid.") from exc
        if not isinstance(manifest, dict):
            raise ValueError("Bundle manifest.json must be an object.")

        root_prefix = ""
        if manifest_name.endswith("/manifest.json"):
            root_prefix = manifest_name[:-len("/manifest.json")]

        return manifest_name, str(root_prefix or "").strip("/"), manifest

    def _locate_bundle_session_member(self, archive: zipfile.ZipFile, root_prefix: str, manifest: Dict[str, Any]) -> str:
        names = [str(item or "").rstrip("/") for item in archive.namelist()]
        name_set = set(names)

        manifest_project_name = os.path.basename(str(manifest.get("project_file", "") or "").strip())
        candidates = []

        session_prefix = self._bundle_prefix(root_prefix, "session")
        if manifest_project_name:
            explicit_name = f"{session_prefix}{manifest_project_name}" if session_prefix else manifest_project_name
            if explicit_name in name_set:
                candidates.append(explicit_name)

        if not candidates and session_prefix:
            for name in names:
                if not name.lower().endswith(".legion"):
                    continue
                if name.startswith(session_prefix):
                    candidates.append(name)

        if not candidates:
            for name in names:
                if name.lower().endswith(".legion"):
                    candidates.append(name)

        if not candidates:
            return ""
        candidates.sort(key=lambda item: (len(item), item))
        return candidates[0]

    def _extract_zip_member_to_file(self, archive: zipfile.ZipFile, member_name: str, destination_path: str):
        target = os.path.abspath(str(destination_path or "").strip())
        if not target:
            raise ValueError("Destination path is required.")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        try:
            with archive.open(member_name, "r") as source, open(target, "wb") as handle:
                shutil.copyfileobj(source, handle)
        except KeyError as exc:
            raise ValueError(f"Bundle member is missing: {member_name}") from exc

    def _extract_zip_prefix_to_dir(self, archive: zipfile.ZipFile, prefix: str, destination_dir: str):
        clean_prefix = str(prefix or "").replace("\\", "/")
        if clean_prefix and not clean_prefix.endswith("/"):
            clean_prefix = f"{clean_prefix}/"

        dest_root = os.path.abspath(str(destination_dir or "").strip())
        if not dest_root:
            return
        os.makedirs(dest_root, exist_ok=True)

        names = [str(item or "") for item in archive.namelist()]
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.endswith("/"):
                continue
            if clean_prefix and not normalized.startswith(clean_prefix):
                continue

            relative = normalized[len(clean_prefix):] if clean_prefix else normalized
            safe_relative = self._safe_bundle_relative_path(relative)
            if not safe_relative:
                continue

            destination = os.path.abspath(os.path.join(dest_root, safe_relative))
            if not destination.startswith(f"{dest_root}{os.sep}") and destination != dest_root:
                continue

            os.makedirs(os.path.dirname(destination), exist_ok=True)
            try:
                with archive.open(name, "r") as source, open(destination, "wb") as handle:
                    shutil.copyfileobj(source, handle)
            except Exception:
                continue

    def _hosts(self, limit: int = 100) -> List[Dict[str, Any]]:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return []

        repo_container = project.repositoryContainer
        host_repo = repo_container.hostRepository
        port_repo = repo_container.portRepository
        results = []

        hosts = host_repo.getAllHostObjs()
        for host in hosts[:limit]:
            host_ports = port_repo.getPortsByHostId(host.id)
            open_port_count = sum(
                1 for p in host_ports if str(getattr(p, "state", "")) in {"open", "open|filtered"}
            )
            results.append({
                "id": int(getattr(host, "id", 0) or 0),
                "ip": str(getattr(host, "ip", "") or ""),
                "hostname": str(getattr(host, "hostname", "") or ""),
                "status": str(getattr(host, "status", "") or ""),
                "os": str(getattr(host, "osMatch", "") or ""),
                "open_ports": open_port_count,
            })

        return results

    def _processes(self, limit: int = 75) -> List[Dict[str, Any]]:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return []

        process_repo = project.repositoryContainer.processRepository
        rows = process_repo.getProcesses({}, showProcesses='True', sort='desc', ncol='id')
        trimmed = rows[:limit]
        results = []

        def _to_float(value):
            try:
                return float(str(value).strip())
            except (TypeError, ValueError):
                return None

        for row in trimmed:
            status = str(row.get("status", "") or "")
            status_lower = status.strip().lower()
            terminal = status_lower in {"finished", "crashed", "cancelled", "killed", "failed"}
            estimated_remaining = row.get("estimatedRemaining", 0)
            if terminal:
                estimated_remaining = 0

            percent_value = str(row.get("percent", "") or "")
            if status_lower == "finished":
                numeric = _to_float(percent_value)
                if numeric is None or numeric <= 0.0:
                    percent_value = "100"

            results.append({
                "id": row.get("id", ""),
                "name": row.get("name", ""),
                "hostIp": row.get("hostIp", ""),
                "port": row.get("port", ""),
                "protocol": row.get("protocol", ""),
                "status": status,
                "startTime": row.get("startTime", ""),
                "percent": percent_value,
                "estimatedRemaining": estimated_remaining,
            })
        return results

    @staticmethod
    def _sanitize_provider_config(provider_cfg: Dict[str, Any]) -> Dict[str, Any]:
        value = dict(provider_cfg)
        api_key = str(value.get("api_key", "") or "")
        value["api_key"] = ""
        value["api_key_configured"] = bool(api_key)
        return value

    def _scheduler_preferences(self) -> Dict[str, Any]:
        config = self.scheduler_config.load()
        providers = config.get("providers", {})
        sanitized_providers = {}
        for name, provider_cfg in providers.items():
            sanitized_providers[name] = self._sanitize_provider_config(provider_cfg)
        return {
            "mode": config.get("mode", "deterministic"),
            "available_modes": ["deterministic", "ai"],
            "goal_profile": config.get("goal_profile", "internal_asset_discovery"),
            "goal_profiles": [
                {"id": "internal_asset_discovery", "name": "Internal Asset Discovery"},
                {"id": "external_pentest", "name": "External Pentest"},
            ],
            "provider": config.get("provider", "none"),
            "max_concurrency": self._scheduler_max_concurrency(config),
            "max_jobs": self._scheduler_max_jobs(config),
            "job_workers": int(getattr(self.jobs, "worker_count", 1) or 1),
            "job_max": int(getattr(self.jobs, "max_jobs", 200) or 200),
            "providers": sanitized_providers,
            "dangerous_categories": config.get("dangerous_categories", []),
            "preapproved_families_count": len(config.get("preapproved_command_families", [])),
            "ai_feedback": self._scheduler_feedback_config(config),
            "project_report_delivery": self._project_report_delivery_config(config),
            "cloud_notice": config.get(
                "cloud_notice",
                "Cloud AI mode may send host/service metadata to third-party providers.",
            ),
        }

    def _ensure_scheduler_table(self):
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return
        ensure_scheduler_audit_table(project.database)
        ensure_scheduler_ai_state_table(project.database)

    def _ensure_scheduler_approval_store(self):
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return
        ensure_scheduler_approval_table(project.database)

    def _ensure_process_tables(self):
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return
        session = project.database.session()
        try:
            session.execute(text(
                "CREATE TABLE IF NOT EXISTS process ("
                "pid TEXT,"
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "display TEXT,"
                "name TEXT,"
                "tabTitle TEXT,"
                "hostIp TEXT,"
                "port TEXT,"
                "protocol TEXT,"
                "command TEXT,"
                "startTime TEXT,"
                "endTime TEXT,"
                "estimatedRemaining INTEGER,"
                "elapsed INTEGER,"
                "outputfile TEXT,"
                "status TEXT,"
                "closed TEXT,"
                "percent TEXT"
                ")"
            ))
            session.execute(text(
                "CREATE TABLE IF NOT EXISTS process_output ("
                "processId INTEGER,"
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "output TEXT"
                ")"
            ))
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def _close_active_project(self):
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return
        try:
            db = getattr(project, "database", None)
            if db and hasattr(db, "dispose"):
                db.dispose()
        except Exception:
            pass

        try:
            self.logic.projectManager.closeProject(project)
        except Exception:
            pass
        finally:
            self.logic.activeProject = None

    def _require_active_project(self):
        project = getattr(self.logic, "activeProject", None)
        if project is None:
            raise RuntimeError("No active project is loaded.")
        return project

    def _resolve_host(self, host_id: int):
        project = self._require_active_project()
        session = project.database.session()
        try:
            result = session.execute(text("SELECT id FROM hostObj WHERE id = :id LIMIT 1"), {"id": int(host_id)}).fetchone()
            if not result:
                return None
        finally:
            session.close()
        hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
        for host in hosts:
            if int(getattr(host, "id", 0) or 0) == int(host_id):
                return host
        return None

    def _load_cves_for_host(self, project, host_id: int) -> List[Dict[str, Any]]:
        session = project.database.session()
        try:
            result = session.execute(text(
                "SELECT id, name, severity, product, version, url, source, exploitId, exploit, exploitUrl "
                "FROM cve WHERE hostId = :host_id ORDER BY id DESC"
            ), {"host_id": str(host_id)})
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        finally:
            session.close()

    def _load_host_ai_analysis(self, project, host_id: int, host_ip: str) -> Dict[str, Any]:
        ensure_scheduler_ai_state_table(project.database)
        row = get_host_ai_state(project.database, int(host_id)) or {}
        stored_technologies = row.get("technologies", [])
        stored_findings = row.get("findings", [])
        manual_tests = row.get("manual_tests", [])
        if not isinstance(stored_technologies, list):
            stored_technologies = []
        if not isinstance(stored_findings, list):
            stored_findings = []
        if not isinstance(manual_tests, list):
            manual_tests = []
        host_cves_raw = self._load_cves_for_host(project, int(host_id or 0))
        inferred_technologies = self._infer_host_technologies(project, int(host_id), str(host_ip or ""))
        inferred_findings = self._infer_host_findings(
            project,
            host_id=int(host_id),
            host_ip=str(host_ip or ""),
            host_cves_raw=host_cves_raw,
        )
        technologies = self._merge_technologies(
            existing=inferred_technologies,
            incoming=self._normalize_ai_technologies(stored_technologies),
            limit=240,
        )
        findings = self._merge_ai_items(
            existing=inferred_findings,
            incoming=self._normalize_ai_findings(stored_findings),
            key_fields=["title", "cve", "severity"],
            limit=260,
        )
        return {
            "host_id": int(host_id),
            "host_ip": str(row.get("host_ip", "") or host_ip or ""),
            "updated_at": str(row.get("updated_at", "") or ""),
            "provider": str(row.get("provider", "") or ""),
            "goal_profile": str(row.get("goal_profile", "") or ""),
            "last_target": {
                "port": str(row.get("last_port", "") or ""),
                "protocol": str(row.get("last_protocol", "") or ""),
                "service": str(row.get("last_service", "") or ""),
            },
            "host_updates": {
                "hostname": str(row.get("hostname", "") or ""),
                "hostname_confidence": self._ai_confidence_value(row.get("hostname_confidence", 0.0)),
                "os": str(row.get("os_match", "") or ""),
                "os_confidence": self._ai_confidence_value(row.get("os_confidence", 0.0)),
            },
            "next_phase": str(row.get("next_phase", "") or ""),
            "technologies": technologies,
            "findings": findings,
            "manual_tests": manual_tests,
        }

    def _list_screenshots_for_host(self, project, host_ip: str) -> List[Dict[str, Any]]:
        screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
        if not os.path.isdir(screenshot_dir):
            return []

        prefix = f"{host_ip}-"
        rows = []
        for filename in sorted(os.listdir(screenshot_dir)):
            if not filename.lower().endswith(".png"):
                continue
            if not filename.startswith(prefix):
                continue
            port = ""
            stripped = filename[len(prefix):]
            if stripped.endswith("-screenshot.png"):
                port = stripped[:-len("-screenshot.png")]
            rows.append({
                "filename": filename,
                "port": port,
                "url": f"/api/screenshots/{filename}",
            })
        return rows

    def _tool_run_stats(self, project) -> Dict[str, Dict[str, Any]]:
        session = project.database.session()
        try:
            result = session.execute(text(
                "SELECT p.name, COUNT(*) AS run_count, MAX(p.id) AS max_id "
                "FROM process AS p GROUP BY p.name"
            ))
            rows = result.fetchall()
            stats = {}
            for name, run_count, max_id in rows:
                name_key = str(name or "")
                last_status = ""
                last_start = ""
                if max_id:
                    detail = session.execute(text(
                        "SELECT status, startTime FROM process WHERE id = :id LIMIT 1"
                    ), {"id": int(max_id)}).fetchone()
                    if detail:
                        last_status = str(detail[0] or "")
                        last_start = str(detail[1] or "")
                stats[name_key] = {
                    "run_count": int(run_count or 0),
                    "last_status": last_status,
                    "last_start": last_start,
                }
            return stats
        except Exception:
            return {}
        finally:
            session.close()

    def _get_settings(self) -> Settings:
        return self.settings

    @staticmethod
    def _find_port_action(settings: Settings, tool_id: str):
        for action in settings.portActions:
            if str(action[1]) == str(tool_id):
                return action
        return None

    def _find_command_template_for_tool(self, settings: Settings, tool_id: str) -> str:
        action = self._find_port_action(settings, tool_id)
        if not action:
            return ""
        return str(action[2])

    def _build_command(self, template: str, host_ip: str, port: str, protocol: str, tool_id: str) -> Tuple[str, str]:
        project = self._require_active_project()
        running_folder = project.properties.runningFolder
        outputfile = os.path.join(running_folder, f"{getTimestamp()}-{tool_id}-{host_ip}-{port}")
        outputfile = os.path.normpath(outputfile).replace("\\", "/")

        command = str(template or "")
        if str(tool_id or "").strip().lower() == "nuclei-web":
            command = AppSettings._ensure_nuclei_auto_scan(command)
        if str(tool_id or "").strip().lower() == "web-content-discovery":
            command = AppSettings._ensure_web_content_discovery_command(command)
        if "wapiti" in str(command).lower():
            normalized_tool = str(tool_id or "").strip().lower()
            scheme = "https" if "https-wapiti" in normalized_tool else "http"
            command = AppSettings._ensure_wapiti_command(command, scheme=scheme)
        command = command.replace("[IP]", str(host_ip)).replace("[PORT]", str(port)).replace("[OUTPUT]", outputfile)
        if "nmap" in command and "-oA" not in command:
            command = f"{command} -oA {outputfile}"
        if "nmap" in command and str(protocol).lower() == "udp":
            command = command.replace("-sV", "-sVU")
        return command, outputfile

    def _build_nmap_scan_plan(
            self,
            *,
            targets: List[str],
            discovery: bool,
            staged: bool,
            nmap_path: str,
            nmap_args: str,
            output_prefix: str,
            scan_mode: str = "legacy",
            scan_options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        resolved_path = str(nmap_path or "nmap").strip() or "nmap"
        raw_args = str(nmap_args or "").strip()
        try:
            extra_args = shlex.split(raw_args) if raw_args else []
        except ValueError as exc:
            raise ValueError(f"Invalid nmap arguments: {exc}") from exc

        selected_mode = str(scan_mode or "legacy").strip().lower() or "legacy"
        selected_options = dict(scan_options or {})

        if selected_mode == "rfc1918_discovery":
            options = self._normalize_scan_options(selected_options, {
                "discovery": True,
                "host_discovery_only": True,
                "skip_dns": True,
                "arp_ping": False,
                "force_pn": False,
                "timing": "T3",
                "top_ports": 100,
                "service_detection": False,
                "default_scripts": False,
                "os_detection": False,
            })
            return self._build_single_scan_plan(
                targets=targets,
                nmap_path=resolved_path,
                output_prefix=output_prefix,
                mode="rfc1918_discovery",
                options=options,
                extra_args=extra_args,
            )

        if selected_mode == "easy":
            options = self._normalize_scan_options(selected_options, {
                "discovery": True,
                "skip_dns": True,
                "force_pn": False,
                "timing": "T3",
                "top_ports": 1000,
                "service_detection": True,
                "default_scripts": True,
                "os_detection": False,
                "aggressive": False,
                "full_ports": False,
                "vuln_scripts": False,
            })
            return self._build_single_scan_plan(
                targets=targets,
                nmap_path=resolved_path,
                output_prefix=output_prefix,
                mode="easy",
                options=options,
                extra_args=extra_args,
            )

        if selected_mode == "hard":
            options = self._normalize_scan_options(selected_options, {
                "discovery": False,
                "skip_dns": True,
                "force_pn": False,
                "timing": "T4",
                "top_ports": 1000,
                "service_detection": True,
                "default_scripts": True,
                "os_detection": True,
                "aggressive": False,
                "full_ports": True,
                "vuln_scripts": False,
            })
            return self._build_single_scan_plan(
                targets=targets,
                nmap_path=resolved_path,
                output_prefix=output_prefix,
                mode="hard",
                options=options,
                extra_args=extra_args,
            )

        if staged:
            stage1_prefix = f"{output_prefix}_stage1"
            stage2_prefix = f"{output_prefix}_stage2"
            stage1_cmd_prefix = self._nmap_output_prefix_for_command(stage1_prefix, resolved_path)
            stage2_cmd_prefix = self._nmap_output_prefix_for_command(stage2_prefix, resolved_path)

            stage1_tokens = [resolved_path, "-sn", *targets]
            stage1_tokens = self._append_nmap_stats_every(stage1_tokens, interval="15s")
            stage1_tokens.extend(["-oA", stage1_cmd_prefix])
            stage2_tokens = [resolved_path, "-sV", "-O"]
            if not bool(discovery):
                stage2_tokens.append("-Pn")
            stage2_tokens.extend(self._append_nmap_stats_every(extra_args, interval="15s"))
            stage2_tokens.extend(targets)
            stage2_tokens.extend(["-oA", stage2_cmd_prefix])

            stages = [
                {
                    "tool_name": "nmap-stage1",
                    "tab_title": "Nmap Stage 1 Discovery",
                    "output_prefix": stage1_prefix,
                    "xml_path": f"{stage1_prefix}.xml",
                    "command": self._join_shell_tokens(stage1_tokens),
                    "timeout": 1800,
                },
                {
                    "tool_name": "nmap-stage2",
                    "tab_title": "Nmap Stage 2 Service Scan",
                    "output_prefix": stage2_prefix,
                    "xml_path": f"{stage2_prefix}.xml",
                    "command": self._join_shell_tokens(stage2_tokens),
                    "timeout": 5400,
                },
            ]
            return {"xml_path": f"{stage2_prefix}.xml", "stages": stages}

        output_cmd_prefix = self._nmap_output_prefix_for_command(output_prefix, resolved_path)
        tokens = [resolved_path]
        if not bool(discovery):
            tokens.append("-Pn")
        tokens.extend(["-T4", "-sV", "-O"])
        tokens.extend(self._append_nmap_stats_every(extra_args, interval="15s"))
        tokens.extend(targets)
        tokens.extend(["-oA", output_cmd_prefix])
        stages = [{
            "tool_name": "nmap-scan",
            "tab_title": "Nmap Scan",
            "output_prefix": output_prefix,
            "xml_path": f"{output_prefix}.xml",
            "command": self._join_shell_tokens(tokens),
            "timeout": 5400,
        }]
        return {"xml_path": f"{output_prefix}.xml", "stages": stages}

    def _build_single_scan_plan(
            self,
            *,
            targets: List[str],
            nmap_path: str,
            output_prefix: str,
            mode: str,
            options: Dict[str, Any],
            extra_args: List[str],
    ) -> Dict[str, Any]:
        output_cmd_prefix = self._nmap_output_prefix_for_command(output_prefix, nmap_path)
        tokens = [nmap_path]

        discovery_enabled = bool(options.get("discovery", True))
        host_discovery_only = bool(options.get("host_discovery_only", False))
        skip_dns = bool(options.get("skip_dns", False))
        timing_value = self._normalize_timing(str(options.get("timing", "T3")))
        service_detection = bool(options.get("service_detection", False))
        default_scripts = bool(options.get("default_scripts", False))
        os_detection = bool(options.get("os_detection", False))
        aggressive = bool(options.get("aggressive", False))
        full_ports = bool(options.get("full_ports", False))
        vuln_scripts = bool(options.get("vuln_scripts", False))
        top_ports = self._normalize_top_ports(options.get("top_ports", 1000))
        arp_ping = bool(options.get("arp_ping", False))
        force_pn = bool(options.get("force_pn", False))

        if host_discovery_only:
            tokens.append("-sn")
            if skip_dns:
                tokens.append("-n")
            if arp_ping:
                tokens.append("-PR")
            tokens.append(f"-{timing_value}")
        else:
            if force_pn or not discovery_enabled:
                tokens.append("-Pn")
            if skip_dns:
                tokens.append("-n")
            tokens.append(f"-{timing_value}")
            if full_ports:
                tokens.append("-p-")
            else:
                tokens.extend(["--top-ports", str(top_ports)])

            if aggressive:
                tokens.append("-A")
            else:
                if service_detection:
                    tokens.append("-sV")
                if default_scripts:
                    tokens.append("-sC")
                if os_detection:
                    tokens.append("-O")

            if vuln_scripts:
                tokens.extend(["--script", "vuln"])

        tokens.extend(self._append_nmap_stats_every(extra_args, interval="15s"))
        tokens.extend(targets)
        tokens.extend(["-oA", output_cmd_prefix])

        tab_title = {
            "rfc1918_discovery": "Nmap RFC1918 Discovery",
            "easy": "Nmap Easy Scan",
            "hard": "Nmap Hard Scan",
        }.get(str(mode), "Nmap Scan")

        return {
            "xml_path": f"{output_prefix}.xml",
            "stages": [{
                "tool_name": f"nmap-{mode}",
                "tab_title": tab_title,
                "output_prefix": output_prefix,
                "xml_path": f"{output_prefix}.xml",
                "command": self._join_shell_tokens(tokens),
                "timeout": 7200 if mode == "hard" else 5400,
            }],
        }

    @staticmethod
    def _normalize_scan_options(options: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(defaults)
        merged.update(dict(options or {}))
        return merged

    @staticmethod
    def _normalize_timing(raw: str) -> str:
        value = str(raw or "T3").strip().upper()
        if not value.startswith("T"):
            value = f"T{value}"
        if value not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
            return "T3"
        return value

    @staticmethod
    def _normalize_top_ports(raw: Any) -> int:
        try:
            value = int(raw)
        except Exception:
            return 1000
        return max(1, min(value, 65535))

    @staticmethod
    def _contains_nmap_stats_every(args: List[str]) -> bool:
        for token in args:
            value = str(token or "").strip().lower()
            if value == "--stats-every" or value.startswith("--stats-every="):
                return True
        return False

    @staticmethod
    def _append_nmap_stats_every(args: List[str], interval: str = "15s") -> List[str]:
        values = [str(item) for item in list(args or [])]
        if WebRuntime._contains_nmap_stats_every(values):
            return values
        return values + ["--stats-every", str(interval or "15s")]

    @staticmethod
    def _nmap_output_prefix_for_command(output_prefix: str, nmap_path: str) -> str:
        if is_wsl() and str(nmap_path).lower().endswith(".exe"):
            return to_windows_path(output_prefix)
        return output_prefix

    @staticmethod
    def _join_shell_tokens(tokens: List[str]) -> str:
        rendered = [str(token) for token in tokens]
        if os.name == "nt":
            return subprocess.list2cmdline(rendered)
        if hasattr(shlex, "join"):
            return shlex.join(rendered)
        return " ".join(shlex.quote(token) for token in rendered)

    @staticmethod
    def _compact_targets(targets: List[str]) -> str:
        if not targets:
            return ""
        if len(targets) <= 3:
            return ",".join(str(item) for item in targets)
        return ",".join(str(item) for item in targets[:3]) + ",..."

    @staticmethod
    def _split_csv(raw: str) -> List[str]:
        return [item.strip() for item in str(raw or "").split(",") if item.strip()]

    @staticmethod
    def _is_nmap_command(tool_name: str, command: str) -> bool:
        name = str(tool_name or "").strip().lower()
        if name.startswith("nmap"):
            return True
        command_text = str(command or "").strip().lower()
        return " nmap " in f" {command_text} " or command_text.startswith("nmap ")

    def _update_nmap_process_progress(
            self,
            process_repo,
            *,
            process_id: int,
            text_chunk: str,
            state: Dict[str, Any],
    ):
        percent, remaining = self._extract_nmap_progress_from_text(str(text_chunk or ""))
        if percent is None and remaining is None:
            return

        changed = False
        percent_value = state.get("percent")
        remaining_value = state.get("remaining")

        if percent is not None:
            bounded = max(0.0, min(float(percent), 100.0))
            if percent_value is None or abs(float(percent_value) - bounded) >= 0.1:
                percent_value = bounded
                state["percent"] = bounded
                changed = True

        if remaining is not None:
            bounded_remaining = max(0, int(remaining))
            if remaining_value is None or abs(int(remaining_value) - bounded_remaining) >= 5:
                remaining_value = bounded_remaining
                state["remaining"] = bounded_remaining
                changed = True

        now = time.monotonic()
        last_update = float(state.get("updated_at", 0.0) or 0.0)
        if not changed and (now - last_update) < 10.0:
            return

        try:
            process_repo.storeProcessProgress(
                str(int(process_id)),
                percent=f"{percent_value:.1f}" if percent_value is not None else None,
                estimated_remaining=remaining_value,
            )
            state["updated_at"] = now
        except Exception:
            pass

    @staticmethod
    def _extract_nmap_progress_from_text(text: str) -> Tuple[Optional[float], Optional[int]]:
        raw = str(text or "")
        if not raw:
            return None, None

        percent = None
        remaining_seconds = None

        percent_match = _NMAP_PROGRESS_PERCENT_RE.search(raw)
        if percent_match:
            try:
                percent = float(percent_match.group(1))
            except Exception:
                percent = None

        if percent is None:
            percent_attr_match = _NMAP_PROGRESS_PERCENT_ATTR_RE.search(raw)
            if percent_attr_match:
                try:
                    percent = float(percent_attr_match.group(1))
                except Exception:
                    percent = None

        remaining_match = _NMAP_PROGRESS_REMAINING_PAREN_RE.search(raw)
        if remaining_match:
            remaining_seconds = WebRuntime._parse_duration_seconds(remaining_match.group(1))

        if remaining_seconds is None:
            remaining_attr_match = _NMAP_PROGRESS_REMAINING_ATTR_RE.search(raw)
            if remaining_attr_match:
                try:
                    remaining_seconds = int(float(remaining_attr_match.group(1)))
                except Exception:
                    remaining_seconds = None

        return percent, remaining_seconds

    @staticmethod
    def _parse_duration_seconds(raw: str) -> Optional[int]:
        text = str(raw or "").strip()
        if not text:
            return None

        if text.isdigit():
            return int(text)

        parts = text.split(":")
        if not all(part.isdigit() for part in parts):
            return None
        if len(parts) == 2:
            minutes, seconds = [int(part) for part in parts]
            return (minutes * 60) + seconds
        if len(parts) == 3:
            hours, minutes, seconds = [int(part) for part in parts]
            return (hours * 3600) + (minutes * 60) + seconds
        return None

    def _is_temp_project(self) -> bool:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return False
        return bool(getattr(project.properties, "isTemporary", False))

    @staticmethod
    def _normalize_project_path(path: str) -> str:
        candidate = str(path or "").strip()
        if not candidate:
            raise ValueError("Project path is required.")
        normalized = os.path.abspath(os.path.expanduser(candidate))
        if not normalized.lower().endswith(".legion"):
            normalized = f"{normalized}.legion"
        return normalized

    @staticmethod
    def _normalize_existing_file(path: str) -> str:
        candidate = str(path or "").strip()
        if not candidate:
            raise ValueError("File path is required.")
        normalized = os.path.abspath(os.path.expanduser(candidate))
        if not os.path.isfile(normalized):
            raise FileNotFoundError(f"File not found: {normalized}")
        return normalized

    @staticmethod
    def _normalize_targets(targets) -> List[str]:
        if isinstance(targets, str):
            source = targets.replace(",", " ").split()
        elif isinstance(targets, list):
            source = []
            for item in targets:
                text = str(item or "").strip()
                if text:
                    source.extend(text.replace(",", " ").split())
        else:
            source = []

        deduped = []
        seen = set()
        for value in source:
            key = value.strip()
            if not key:
                continue
            if key in seen:
                continue
            seen.add(key)
            deduped.append(key)

        if not deduped:
            raise ValueError("At least one target is required.")
        return deduped
