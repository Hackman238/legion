import datetime
import glob
import ipaddress
import json
import mimetypes
import os
import queue
import re
import shlex
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple
import psutil
from sqlalchemy import text

from app.cli_utils import import_targets_from_textfile, is_wsl, to_windows_path
from app.core.common import getTempFolder
from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.hostsfile import add_temporary_host_alias
from app.httputil.isHttps import isHttps
from app.importers.nmap_runner import import_nmap_xml_into_project
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
from app.scheduler.execution import (
    ensure_scheduler_execution_table,
    get_execution_record,
    list_execution_records,
    store_execution_record,
)
from app.scheduler.graph import (
    ensure_scheduler_graph_tables,
    export_evidence_graph_graphml,
    export_evidence_graph_json,
    list_graph_annotations,
    list_graph_layout_states,
    query_evidence_graph,
    rebuild_evidence_graph,
    upsert_graph_annotation,
    upsert_graph_layout_state,
)
from app.scheduler.models import ExecutionRecord
from app.scheduler.orchestrator import SchedulerDecisionDisposition, SchedulerOrchestrator
from app.scheduler.policy import (
    ensure_scheduler_engagement_policy_table,
    get_project_engagement_policy,
    list_engagement_presets,
    normalize_engagement_policy,
    preset_from_legacy_goal_profile,
    upsert_project_engagement_policy,
)
from app.scheduler.runners import (
    RunnerExecutionRequest,
    RunnerExecutionResult,
    execute_runner_request,
    normalize_runner_settings,
)
from app.scheduler.insights import (
    delete_host_ai_state,
    ensure_scheduler_ai_state_table,
    get_host_ai_state,
    upsert_host_ai_state,
)
from app.scheduler.state import (
    build_artifact_entries,
    build_attempted_action_entry,
    build_target_urls,
    ensure_scheduler_target_state_table,
    get_target_state,
    load_observed_service_inventory,
    upsert_target_state,
)
from app.scheduler.scan_history import (
    ensure_scan_submission_table,
    list_scan_submissions,
    record_scan_submission,
    update_scan_submission,
)
from app.screenshot_metadata import (
    build_screenshot_metadata,
    build_screenshot_state_row,
    load_screenshot_metadata,
    screenshot_metadata_path,
    write_screenshot_metadata,
)
from app.scheduler.config import (
    DEFAULT_TOOL_EXECUTION_PROFILES,
    SchedulerConfigManager,
    normalize_tool_execution_profiles,
)
from app.scheduler.planner import ScheduledAction, SchedulerPlanner
from app.scheduler.providers import (
    determine_scheduler_phase,
    get_provider_logs,
    reflect_on_scheduler_progress,
    test_provider_connection,
)
from app.scheduler.reporting import (
    build_host_report,
    build_project_report,
    render_host_report_markdown as render_scheduler_host_report_markdown,
    render_project_report_markdown as render_scheduler_project_report_markdown,
)
from app.scheduler.risk import classify_command_danger
from app.scheduler.observation_parsers import extract_tool_observations
from app.screenshot_targets import (
    apply_preferred_target_placeholders,
    choose_preferred_command_host,
    choose_preferred_screenshot_host,
)
from app.settings import AppSettings, Settings
from app.timing import getTimestamp
from app.tooling import (
    audit_legion_tools,
    build_tool_execution_env,
    build_tool_install_plan,
    detect_supported_tool_install_platform,
    execute_tool_install_plan,
    normalize_tool_install_platform,
    tool_audit_summary,
)
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
_NUCLEI_PROGRESS_ELAPSED_RE = re.compile(r"^\[([0-9:]+)\]", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_REQUESTS_RE = re.compile(
    r"Requests:\s*([0-9]+)\s*/\s*([0-9]+)(?:\s*\(([0-9]+(?:\.[0-9]+)?)%\))?",
    flags=re.IGNORECASE,
)
_NUCLEI_PROGRESS_RPS_RE = re.compile(r"RPS:\s*([0-9]+(?:\.[0-9]+)?)", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_MATCHED_RE = re.compile(r"Matched:\s*([0-9]+)", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_ERRORS_RE = re.compile(r"Errors:\s*([0-9]+)", flags=re.IGNORECASE)
_CPE22_TOKEN_RE = re.compile(r"\bcpe:/[aho]:[a-z0-9._:-]+\b", flags=re.IGNORECASE)
_CPE23_TOKEN_RE = re.compile(r"\bcpe:2\.3:[aho]:[a-z0-9._:-]+\b", flags=re.IGNORECASE)
_CVE_TOKEN_RE = re.compile(r"\bcve-\d{4}-\d+\b", flags=re.IGNORECASE)
_TECH_VERSION_RE = re.compile(r"\b(\d+(?:[._-][0-9a-z]+){0,4})\b", flags=re.IGNORECASE)
_REFERENCE_ONLY_FINDING_RE = re.compile(
    r"^(?:https?://|//|bid:\d+\s+cve:cve-\d{4}-\d+|cve:cve-\d{4}-\d+)",
    flags=re.IGNORECASE,
)
_MISSING_NSE_SCRIPT_RE = re.compile(
    r"'([a-z][a-z0-9_.-]+\.nse)'\s+did not match a category, filename, or directory",
    flags=re.IGNORECASE,
)
_PYTHON_TOOL_IMPORT_FAILURE_RE = re.compile(
    r"(?:^|\n)\s*(?:modulenotfounderror|importerror):",
    flags=re.IGNORECASE,
)
_SCHEDULER_METHOD_PATH_RE = re.compile(
    r"\b(?:get|post|head|options|put|delete|patch)\b[^\n]{0,96}\s/[a-z0-9._~!$&'()*+,;=:@%/\-?]*",
    flags=re.IGNORECASE,
)
_SCHEDULER_STATUS_PATH_RE = re.compile(
    r"\b\d{3}\b[^\n]{0,48}\s/[a-z0-9._~!$&'()*+,;=:@%/\-?]*",
    flags=re.IGNORECASE,
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
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
_PSEUDO_TECH_NAME_TOKENS = {
    "cache-control",
    "content-language",
    "content-security-policy",
    "content-type",
    "etag",
    "referrer-policy",
    "strict-transport-security",
    "uncommonheaders",
    "vary",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
    "x-xss-protection",
}
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
_SUPPORTED_WORKSPACE_TOOL_IDS = {
    "curl-headers",
    "curl-options",
    "curl-robots",
    "dirsearch",
    "dnsmap",
    "enum4linux",
    "enum4linux-ng",
    "ffuf",
    "http-sqlmap",
    "httpx",
    "nbtscan",
    "nikto",
    "nmap",
    "nmap-vuln.nse",
    "nuclei-cves",
    "nuclei-exposures",
    "nuclei-web",
    "nuclei-wordpress",
    "rpcclient-enum",
    "smbmap",
    "sqlmap",
    "sslscan",
    "testssl.sh",
    "wafw00f",
    "web-content-discovery",
    "whatweb",
    "whatweb-http",
    "whatweb-https",
    "wpscan",
}
_SUPPORTED_WORKSPACE_TOOL_PREFIXES = (
    "http-vuln-",
)
_DEFAULT_AI_FEEDBACK_CONFIG = {
    "enabled": True,
    "max_rounds_per_target": 5,
    "max_actions_per_round": 6,
    "recent_output_chars": 900,
    "reflection_enabled": True,
    "stall_rounds_without_progress": 2,
    "stall_repeat_selection_threshold": 2,
    "max_reflections_per_target": 1,
}
_DIG_DEEPER_MAX_RUNTIME_SECONDS = 900
_DIG_DEEPER_MAX_TOTAL_ACTIONS = 24
_DIG_DEEPER_TASK_TIMEOUT_SECONDS = 180
_PROCESS_READER_EXIT_GRACE_SECONDS = 2.0
_PROCESS_CRASH_MIN_RUNTIME_SECONDS = 5.0
_AI_HOST_UPDATE_MIN_CONFIDENCE = 70.0


def _get_requests_module():
    try:
        import requests as requests_module
    except Exception as exc:  # pragma: no cover - depends on local environment packaging
        raise RuntimeError(
            f"requests dependency unavailable under {sys.executable} ({sys.version.split()[0]}): {exc}"
        ) from exc
    return requests_module


class WebRuntime:
    def __init__(self, logic):
        self.logic = logic
        self.scheduler_config = SchedulerConfigManager()
        self.scheduler_planner = SchedulerPlanner(self.scheduler_config)
        self.scheduler_orchestrator = SchedulerOrchestrator(self.scheduler_config, self.scheduler_planner)
        self.settings_file = AppSettings()
        self.settings = Settings(self.settings_file)
        self._ui_event_condition = threading.Condition()
        self._ui_event_seq = 0
        self._ui_events: List[Dict[str, Any]] = []
        self._ui_last_emit_monotonic: Dict[str, float] = defaultdict(float)
        scheduler_preferences = self.scheduler_config.load()
        job_workers = self._job_worker_count(scheduler_preferences)
        job_max = self._scheduler_max_jobs(scheduler_preferences)
        self.jobs = WebJobManager(max_jobs=job_max, worker_count=job_workers, on_change=self._handle_job_change)
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

    def _emit_ui_invalidation(self, *channels: str, throttle_seconds: float = 0.0):
        normalized = sorted({str(item or "").strip() for item in channels if str(item or "").strip()})
        if not normalized:
            return
        key = ",".join(normalized)
        with self._ui_event_condition:
            now = time.monotonic()
            if float(throttle_seconds or 0.0) > 0.0:
                last_emitted = float(self._ui_last_emit_monotonic.get(key, 0.0) or 0.0)
                if (now - last_emitted) < float(throttle_seconds):
                    return
            self._ui_last_emit_monotonic[key] = now
            self._ui_event_seq += 1
            self._ui_events.append({
                "type": "invalidate",
                "seq": int(self._ui_event_seq),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "channels": normalized,
            })
            if len(self._ui_events) > 256:
                self._ui_events = self._ui_events[-256:]
            self._ui_event_condition.notify_all()

    def wait_for_ui_event(self, after_seq: int = 0, timeout_seconds: float = 30.0) -> Dict[str, Any]:
        cursor = max(0, int(after_seq or 0))
        timeout_value = max(0.0, float(timeout_seconds or 0.0))
        deadline = time.monotonic() + timeout_value if timeout_value > 0 else None
        with self._ui_event_condition:
            while True:
                pending = [item for item in self._ui_events if int(item.get("seq", 0) or 0) > cursor]
                if pending:
                    channels = sorted({
                        str(channel or "").strip()
                        for item in pending
                        for channel in list(item.get("channels", []) or [])
                        if str(channel or "").strip()
                    })
                    return {
                        "type": "invalidate",
                        "seq": max(int(item.get("seq", 0) or 0) for item in pending),
                        "channels": channels,
                    }
                if deadline is None:
                    self._ui_event_condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"type": "heartbeat", "seq": cursor, "channels": []}
                self._ui_event_condition.wait(remaining)

    def _handle_job_change(self, job: Dict[str, Any], event_name: str):
        channels = {"jobs", "overview"}
        job_type = str(job.get("type", "") or "").strip().lower()
        if job_type in {"nmap-scan", "import-nmap-xml", "scheduler-run", "scheduler-approval-execute", "scheduler-dig-deeper", "tool-run", "process-retry"}:
            channels.add("processes")
        if job_type in {"nmap-scan", "import-nmap-xml", "project-restore-zip"}:
            channels.update({"scan_history", "hosts", "services", "graph"})
        self._emit_ui_invalidation(*sorted(channels))

    def get_workspace_overview(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "project": self._project_metadata(),
                "summary": self._summary(),
                "scheduler": self._scheduler_preferences(),
                "scheduler_rationale_feed": self._scheduler_rationale_feed_locked(limit=12),
            }

    def get_workspace_processes(self, limit: int = 75) -> List[Dict[str, Any]]:
        with self._lock:
            return self._processes(limit=max(1, min(int(limit or 75), 500)))

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self._maybe_schedule_autosave_locked()
            tools_page = self.get_workspace_tools_page(limit=300, offset=0)
            return {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "project": self._project_metadata(),
                "summary": self._summary(),
                "host_filter": "hide_down",
                "hosts": self._hosts(include_down=False),
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
                "scheduler_rationale_feed": self._scheduler_rationale_feed_locked(limit=12),
                "scheduler_approvals": self.get_scheduler_approvals(limit=40, status="pending"),
                "scheduler_executions": self.get_scheduler_execution_records(limit=40),
                "scan_history": self.get_scan_history(limit=40),
                "jobs": self.jobs.list_jobs(limit=20),
            }

    def get_scheduler_preferences(self) -> Dict[str, Any]:
        with self._lock:
            return self._scheduler_preferences()

    @staticmethod
    def _merge_engagement_policy_payload(
            current_policy: Optional[Dict[str, Any]],
            updates: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        merged = dict(current_policy or {})
        incoming = dict(updates or {}) if isinstance(updates, dict) else {}
        if isinstance(merged.get("custom_overrides"), dict) and isinstance(incoming.get("custom_overrides"), dict):
            custom_overrides = dict(merged.get("custom_overrides", {}))
            custom_overrides.update(incoming.get("custom_overrides", {}))
            incoming["custom_overrides"] = custom_overrides
        merged.update(incoming)
        return merged

    def _load_engagement_policy_locked(self, *, persist_if_missing: bool = True) -> Dict[str, Any]:
        config = self.scheduler_config.load()
        fallback_policy = normalize_engagement_policy(
            config.get("engagement_policy", {}),
            fallback_goal_profile=str(config.get("goal_profile", "internal_asset_discovery") or "internal_asset_discovery"),
        )
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return fallback_policy.to_dict()

        ensure_scheduler_engagement_policy_table(project.database)
        stored = get_project_engagement_policy(project.database)
        if stored is None:
            payload = fallback_policy.to_dict()
            if persist_if_missing:
                upsert_project_engagement_policy(
                    project.database,
                    payload,
                    updated_at=getTimestamp(True),
                )
            return payload

        normalized = normalize_engagement_policy(
            stored,
            fallback_goal_profile=fallback_policy.legacy_goal_profile,
        )
        return normalized.to_dict()

    def get_engagement_policy(self) -> Dict[str, Any]:
        with self._lock:
            return self._load_engagement_policy_locked(persist_if_missing=True)

    def set_engagement_policy(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            current = self._load_engagement_policy_locked(persist_if_missing=True)
            merged = self._merge_engagement_policy_payload(current, updates)
            normalized_policy = normalize_engagement_policy(
                merged,
                fallback_goal_profile=str(current.get("legacy_goal_profile", current.get("goal_profile", "internal_asset_discovery")) or "internal_asset_discovery"),
            )
            self.scheduler_config.update_preferences({
                "engagement_policy": normalized_policy.to_dict(),
                "goal_profile": normalized_policy.legacy_goal_profile,
            })
            project = getattr(self.logic, "activeProject", None)
            if project:
                ensure_scheduler_engagement_policy_table(project.database)
                upsert_project_engagement_policy(
                    project.database,
                    normalized_policy.to_dict(),
                    updated_at=getTimestamp(True),
                )
            return normalized_policy.to_dict()

    def apply_scheduler_preferences(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            normalized = dict(updates or {})
            policy_updates = normalized.get("engagement_policy") if isinstance(normalized.get("engagement_policy"), dict) else None
            if policy_updates is not None or "goal_profile" in normalized:
                current_policy = self._load_engagement_policy_locked(persist_if_missing=True)
                if policy_updates is not None:
                    merged_policy = self._merge_engagement_policy_payload(current_policy, policy_updates)
                else:
                    merged_policy = self._merge_engagement_policy_payload(
                        current_policy,
                        {"preset": preset_from_legacy_goal_profile(str(normalized.get("goal_profile", "") or ""))},
                    )
                resolved_policy = normalize_engagement_policy(
                    merged_policy,
                    fallback_goal_profile=str(current_policy.get("legacy_goal_profile", current_policy.get("goal_profile", "internal_asset_discovery")) or "internal_asset_discovery"),
                )
                normalized["engagement_policy"] = resolved_policy.to_dict()
                normalized["goal_profile"] = resolved_policy.legacy_goal_profile
            saved = self.scheduler_config.update_preferences(normalized)
            if isinstance(saved.get("engagement_policy"), dict):
                project = getattr(self.logic, "activeProject", None)
                if project:
                    ensure_scheduler_engagement_policy_table(project.database)
                    upsert_project_engagement_policy(
                        project.database,
                        saved.get("engagement_policy", {}),
                        updated_at=getTimestamp(True),
                    )
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
        prefs = self.get_scheduler_preferences()
        self._emit_ui_invalidation("overview")
        return prefs

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
                    "engagement_preset, tool_id, label, command_family_id, danger_categories, risk_tags, "
                    "requires_approval, policy_decision, policy_reason, risk_summary, safer_alternative, "
                    "family_policy_state, approved, executed, reason, rationale, approval_id "
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

    def _scheduler_family_policy_metadata(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "tool_id": str(item.get("tool_id", "")),
            "label": str(item.get("label", "")),
            "danger_categories": self._split_csv(str(item.get("danger_categories", ""))),
            "risk_tags": self._split_csv(str(item.get("risk_tags", ""))),
            "approval_scope": "family",
        }

    def _apply_family_policy_action(self, item: Dict[str, Any], family_action: str, *, reason: str = "") -> str:
        action = str(family_action or "").strip().lower()
        if action == "allowed":
            self.scheduler_config.approve_family(
                str(item.get("command_family_id", "")),
                self._scheduler_family_policy_metadata(item),
            )
            return "allowed"
        if action == "approval_required":
            self.scheduler_config.require_family_approval(
                str(item.get("command_family_id", "")),
                self._scheduler_family_policy_metadata(item),
                reason=reason,
            )
            return "approval_required"
        if action == "suppressed":
            self.scheduler_config.suppress_family(
                str(item.get("command_family_id", "")),
                self._scheduler_family_policy_metadata(item),
                reason=reason,
            )
            return "suppressed"
        if action == "blocked":
            self.scheduler_config.block_family(
                str(item.get("command_family_id", "")),
                self._scheduler_family_policy_metadata(item),
                reason=reason,
            )
            return "blocked"
        return ""

    def get_scheduler_execution_records(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_execution_table(project.database)
            return list_execution_records(project.database, limit=limit)

    def get_scheduler_rationale_feed(self, limit: int = 18) -> List[Dict[str, Any]]:
        with self._lock:
            return self._scheduler_rationale_feed_locked(limit=limit)

    def _scheduler_rationale_feed_locked(self, limit: int = 18) -> List[Dict[str, Any]]:
        project = getattr(self.logic, "activeProject", None)
        database = getattr(project, "database", None) if project else None
        if database is None:
            return []
        resolved_limit = max(1, min(int(limit or 18), 48))
        provider_logs = list(get_provider_logs(limit=max(resolved_limit * 4, 40)) or [])
        decisions = self.get_scheduler_decisions(limit=max(resolved_limit * 8, 200))
        executions = list_execution_records(database, limit=max(resolved_limit * 10, 240))
        return self._build_scheduler_rationale_feed_items(
            provider_logs,
            decisions,
            executions,
            limit=resolved_limit,
        )

    @staticmethod
    def _safe_json_loads(value: Any) -> Any:
        text_value = str(value or "").strip()
        if not text_value:
            return None
        try:
            return json.loads(text_value)
        except Exception:
            return None

    @staticmethod
    def _dedupe_text_tokens(values: Any, *, limit: int = 12) -> List[str]:
        seen = set()
        items: List[str] = []
        for item in list(values or []):
            token = str(item or "").strip()
            if not token or token in seen:
                continue
            seen.add(token)
            items.append(token)
            if len(items) >= int(limit):
                break
        return items

    @staticmethod
    def _truncate_rationale_text(value: Any, max_chars: int = 180) -> str:
        text_value = re.sub(r"\s+", " ", str(value or "")).strip()
        if len(text_value) <= int(max_chars):
            return text_value
        return text_value[:max_chars].rstrip() + "..."

    @classmethod
    def _scheduler_event_timestamp_epoch(cls, value: Any) -> float:
        normalized = cls._normalize_process_timestamp_to_utc(value)
        if not normalized:
            return 0.0
        try:
            return datetime.datetime.fromisoformat(normalized).timestamp()
        except Exception:
            return 0.0

    @staticmethod
    def _strip_json_fences(value: Any) -> str:
        text_value = str(value or "").strip()
        if not text_value.startswith("```"):
            return text_value
        lines = text_value.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()

    @classmethod
    def _extract_prompt_text_from_provider_request(cls, request_body: Any) -> str:
        payload = cls._safe_json_loads(request_body)
        if not isinstance(payload, dict):
            return ""
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            return ""
        for message in reversed(messages):
            if not isinstance(message, dict):
                continue
            if str(message.get("role", "") or "").strip().lower() != "user":
                continue
            content = message.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                chunks = []
                for item in content:
                    if isinstance(item, dict):
                        if str(item.get("type", "") or "").strip().lower() == "text":
                            chunks.append(str(item.get("text", "") or ""))
                    elif isinstance(item, str):
                        chunks.append(item)
                return "\n".join(chunk for chunk in chunks if chunk.strip())
        return ""

    @staticmethod
    def _extract_scheduler_target_fields_from_prompt(prompt_text: Any) -> Dict[str, str]:
        text_value = str(prompt_text or "")
        payload: Dict[str, str] = {}
        for field_name in ("host_ip", "port", "protocol", "service"):
            match = re.search(rf'"{field_name}"\s*:\s*"([^"]*)"', text_value)
            if match:
                payload[field_name] = str(match.group(1) or "").strip()
        return payload

    @classmethod
    def _extract_provider_response_payload(cls, response_body: Any) -> Dict[str, Any]:
        payload = cls._safe_json_loads(response_body)
        if isinstance(payload, dict) and any(
                key in payload for key in ("actions", "selected_tool_ids", "promote_tool_ids", "suppress_tool_ids", "next_phase", "focus")
        ):
            return payload

        content_candidates: List[str] = []
        if isinstance(payload, dict):
            for choice in list(payload.get("choices", []) or []):
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message", {})
                if isinstance(message, dict):
                    content = message.get("content", "")
                    if isinstance(content, str) and content.strip():
                        content_candidates.append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and str(item.get("type", "") or "").strip().lower() == "text":
                                text_value = str(item.get("text", "") or "")
                                if text_value.strip():
                                    content_candidates.append(text_value)
                text_value = str(choice.get("text", "") or "")
                if text_value.strip():
                    content_candidates.append(text_value)
            for item in list(payload.get("content", []) or []):
                if isinstance(item, dict) and str(item.get("type", "") or "").strip().lower() == "text":
                    text_value = str(item.get("text", "") or "")
                    if text_value.strip():
                        content_candidates.append(text_value)

        for item in content_candidates:
            parsed = cls._safe_json_loads(cls._strip_json_fences(item))
            if isinstance(parsed, dict):
                return parsed
        return {}

    @staticmethod
    def _rationale_list_text(values: Any, *, limit: int = 6) -> str:
        items = WebRuntime._dedupe_text_tokens(values, limit=64)
        if not items:
            return ""
        if len(items) <= int(limit):
            return ", ".join(items)
        remaining = len(items) - int(limit)
        return f"{', '.join(items[:int(limit)])} (+{remaining} more)"

    @staticmethod
    def _rationale_tag_label(value: Any) -> str:
        token = str(value or "").strip()
        if not token:
            return ""
        normalized = token.replace("web_followup", "web followup").replace(":", " / ").replace("_", " ")
        words = [part for part in re.split(r"\s+", normalized) if part]
        if not words:
            return ""
        upper_tokens = {"ai", "http", "https", "rpc", "smb", "tls", "waf", "cve"}
        rendered = []
        for word in words:
            rendered.append(word.upper() if word.lower() in upper_tokens else word.capitalize())
        return " ".join(rendered)

    @classmethod
    def _index_scheduler_rows_by_target_tool(
            cls,
            rows: List[Dict[str, Any]],
            *,
            timestamp_field: str,
    ) -> Dict[Tuple[str, str, str, str], List[Dict[str, Any]]]:
        index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
        for raw_row in list(rows or []):
            if not isinstance(raw_row, dict):
                continue
            item = dict(raw_row)
            item["_sort_ts"] = cls._scheduler_event_timestamp_epoch(item.get(timestamp_field, ""))
            key = (
                str(item.get("host_ip", "") or "").strip(),
                str(item.get("port", "") or "").strip(),
                str(item.get("protocol", "") or "").strip(),
                str(item.get("tool_id", "") or item.get("label", "") or "").strip(),
            )
            if not key[3]:
                continue
            index[key].append(item)
        for entries in index.values():
            entries.sort(key=lambda entry: float(entry.get("_sort_ts", 0.0) or 0.0), reverse=True)
        return index

    @staticmethod
    def _nearest_scheduler_row(rows: List[Dict[str, Any]], event_ts: float) -> Optional[Dict[str, Any]]:
        if not rows:
            return None
        if float(event_ts or 0.0) <= 0.0:
            return rows[0]
        best: Optional[Dict[str, Any]] = None
        best_delta: Optional[float] = None
        for item in list(rows or [])[:10]:
            delta = abs(float(item.get("_sort_ts", 0.0) or 0.0) - float(event_ts or 0.0))
            if best is None or best_delta is None or delta < best_delta:
                best = item
                best_delta = delta
        if best is None:
            return None
        if best_delta is not None and best_delta > 7200:
            return None
        return best

    @classmethod
    def _manual_test_lines(cls, manual_tests: Any, *, limit: int = 2) -> List[str]:
        lines: List[str] = []
        entries = [item for item in list(manual_tests or []) if isinstance(item, dict)]
        for item in entries[:int(limit)]:
            why = cls._truncate_rationale_text(item.get("why", ""), 120)
            command = cls._truncate_rationale_text(item.get("command", ""), 120)
            if why and command:
                lines.append(f"Manual: {why} | {command}")
            elif command:
                lines.append(f"Manual: {command}")
            elif why:
                lines.append(f"Manual: {why}")
        remaining = len(entries) - min(len(entries), int(limit))
        if remaining > 0:
            lines.append(f"Manual: {remaining} more suggestion(s)")
        return lines

    @classmethod
    def _findings_line(cls, findings: Any) -> str:
        items = []
        for item in list(findings or [])[:3]:
            if not isinstance(item, dict):
                continue
            title = cls._truncate_rationale_text(item.get("title", ""), 80)
            severity = str(item.get("severity", "") or "").strip()
            if title and severity:
                items.append(f"{title} [{severity}]")
            elif title:
                items.append(title)
        if not items:
            return ""
        return f"Findings: {', '.join(items)}"

    @classmethod
    def _match_rationale_outcomes(
            cls,
            decision_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
            execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
            *,
            host_ip: str,
            port: str,
            protocol: str,
            tool_ids: List[str],
            event_ts: float,
    ) -> Tuple[str, List[int]]:
        outcome_tokens: List[str] = []
        matched_decision_ids: List[int] = []
        for tool_id in cls._dedupe_text_tokens(tool_ids, limit=16):
            key = (str(host_ip or "").strip(), str(port or "").strip(), str(protocol or "").strip(), tool_id)
            decision = cls._nearest_scheduler_row(decision_index.get(key, []), event_ts)
            execution = cls._nearest_scheduler_row(execution_index.get(key, []), event_ts)
            if isinstance(decision, dict):
                try:
                    decision_id = int(decision.get("id", 0) or 0)
                except (TypeError, ValueError):
                    decision_id = 0
                if decision_id > 0:
                    matched_decision_ids.append(decision_id)
            if isinstance(execution, dict):
                execution_id = str(execution.get("execution_id", "") or "").strip()
                exit_status = str(execution.get("exit_status", "") or "").strip()
                token = f"{tool_id} executed"
                if execution_id:
                    token += f" [{execution_id}"
                    if exit_status:
                        token += f", exit {exit_status}"
                    token += "]"
                elif exit_status:
                    token += f" [exit {exit_status}]"
                outcome_tokens.append(token)
                continue

            if not isinstance(decision, dict):
                continue
            if str(decision.get("executed", "") or "").strip().lower() == "true":
                outcome_tokens.append(f"{tool_id} executed")
            elif str(decision.get("approved", "") or "").strip().lower() == "true":
                outcome_tokens.append(f"{tool_id} approved")
            elif str(decision.get("requires_approval", "") or "").strip().lower() == "true":
                outcome_tokens.append(f"{tool_id} awaiting approval")
            else:
                decision_reason = cls._truncate_rationale_text(
                    decision.get("reason", "") or decision.get("policy_decision", "") or "recorded",
                    72,
                )
                outcome_tokens.append(f"{tool_id} {decision_reason}".strip())

        if not outcome_tokens:
            return "", matched_decision_ids
        return f"Outcome: {cls._rationale_list_text(outcome_tokens, limit=4)}", matched_decision_ids

    @classmethod
    def _build_provider_rationale_entry(
            cls,
            log_row: Dict[str, Any],
            *,
            decision_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
            execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        prompt_metadata = log_row.get("prompt_metadata", {}) if isinstance(log_row.get("prompt_metadata", {}), dict) else {}
        prompt_type = str(prompt_metadata.get("prompt_type", "") or "").strip().lower()
        if prompt_type not in {"ranking", "reflection", "web_followup"}:
            return None

        response_payload = cls._extract_provider_response_payload(log_row.get("response_body", ""))
        if not response_payload:
            return None

        prompt_text = cls._extract_prompt_text_from_provider_request(log_row.get("request_body", ""))
        target = cls._extract_scheduler_target_fields_from_prompt(prompt_text or log_row.get("request_body", ""))
        host_ip = str(target.get("host_ip", "") or "").strip()
        port = str(target.get("port", "") or "").strip()
        protocol = str(target.get("protocol", "") or "").strip()
        service = str(target.get("service", "") or "").strip()
        visible_tool_ids = cls._dedupe_text_tokens(prompt_metadata.get("visible_candidate_tool_ids", []), limit=64)
        selected_tool_ids: List[str] = []
        dropped_tool_ids: List[str] = []
        details: List[str] = []
        headline = ""
        summary = ""

        if prompt_type == "ranking":
            actions_all = []
            for item in list(response_payload.get("actions", []) or []):
                if not isinstance(item, dict):
                    continue
                tool_id = str(item.get("tool_id", "") or "").strip()
                if not tool_id:
                    continue
                actions_all.append({
                    "tool_id": tool_id,
                    "score": int(item.get("score", 0) or 0),
                    "rationale": cls._truncate_rationale_text(item.get("rationale", ""), 180),
                })
            filtered_actions = []
            for item in actions_all:
                if visible_tool_ids and item["tool_id"] not in visible_tool_ids:
                    dropped_tool_ids.append(item["tool_id"])
                    continue
                filtered_actions.append(item)
            selected_tool_ids = [item["tool_id"] for item in filtered_actions]
            headline = cls._rationale_list_text(selected_tool_ids, limit=3) or "No action selected"
            summary = (
                filtered_actions[0].get("rationale", "")
                if filtered_actions else
                cls._truncate_rationale_text("Provider recommended manual review instead of a safe automated action.", 180)
            )
            if selected_tool_ids:
                details.append(f"Selected: {cls._rationale_list_text(selected_tool_ids, limit=4)}")
            else:
                details.append("Selected: none")
            if filtered_actions:
                scores_text = ", ".join(f"{item['tool_id']} {item['score']}" for item in filtered_actions[:4])
                details.append(f"Scores: {scores_text}")
            skipped_tool_ids = [item for item in visible_tool_ids if item not in selected_tool_ids]
            if skipped_tool_ids:
                details.append(f"Not selected: {cls._rationale_list_text(skipped_tool_ids, limit=5)}")
            if dropped_tool_ids:
                details.append(f"Ignored out-of-scope suggestions: {cls._rationale_list_text(dropped_tool_ids, limit=4)}")
            findings_line = cls._findings_line(response_payload.get("findings", []))
            if findings_line:
                details.append(findings_line)
            next_phase = str(response_payload.get("next_phase", "") or "").strip()
            if next_phase:
                details.append(f"Next phase: {next_phase}")
            details.extend(cls._manual_test_lines(response_payload.get("manual_tests", [])))
        elif prompt_type == "web_followup":
            selected_all = cls._dedupe_text_tokens(response_payload.get("selected_tool_ids", []), limit=16)
            selected_tool_ids = [item for item in selected_all if not visible_tool_ids or item in visible_tool_ids]
            dropped_tool_ids = [item for item in selected_all if visible_tool_ids and item not in visible_tool_ids]
            headline = cls._rationale_list_text(selected_tool_ids, limit=3) or "Manual review only"
            summary = cls._truncate_rationale_text(
                response_payload.get("reason", "") or "Provider recommended a bounded follow-up review.",
                200,
            )
            focus = str(response_payload.get("focus", "") or "").strip()
            if selected_tool_ids:
                details.append(f"Selected: {cls._rationale_list_text(selected_tool_ids, limit=4)}")
            else:
                details.append("Selected: none")
            if visible_tool_ids:
                skipped_tool_ids = [item for item in visible_tool_ids if item not in selected_tool_ids]
                if skipped_tool_ids:
                    details.append(f"Not selected: {cls._rationale_list_text(skipped_tool_ids, limit=5)}")
            if dropped_tool_ids:
                details.append(f"Ignored out-of-scope suggestions: {cls._rationale_list_text(dropped_tool_ids, limit=4)}")
            if focus:
                details.append(f"Focus: {focus}")
            details.extend(cls._manual_test_lines(response_payload.get("manual_tests", [])))
        else:
            state = str(response_payload.get("state", "") or "").strip()
            priority_shift = str(response_payload.get("priority_shift", "") or "").strip()
            promote_tool_ids = cls._dedupe_text_tokens(response_payload.get("promote_tool_ids", []), limit=16)
            suppress_tool_ids = cls._dedupe_text_tokens(response_payload.get("suppress_tool_ids", []), limit=24)
            headline = " -> ".join([item for item in [state or "Reflection", priority_shift] if item]) or "Reflection"
            summary = cls._truncate_rationale_text(response_payload.get("reason", "") or "Scheduler reflection recorded.", 220)
            if promote_tool_ids:
                details.append(f"Promote: {cls._rationale_list_text(promote_tool_ids, limit=5)}")
            if suppress_tool_ids:
                details.append(f"Suppress: {cls._rationale_list_text(suppress_tool_ids, limit=5)}")
            details.extend(cls._manual_test_lines(response_payload.get("manual_tests", [])))

        event_ts = cls._scheduler_event_timestamp_epoch(log_row.get("timestamp", ""))
        outcome_line, matched_decision_ids = cls._match_rationale_outcomes(
            decision_index,
            execution_index,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            tool_ids=selected_tool_ids,
            event_ts=event_ts,
        )
        if outcome_line:
            details.insert(0, outcome_line)

        tags = cls._dedupe_text_tokens([
            cls._rationale_tag_label(prompt_type),
            cls._rationale_tag_label(prompt_metadata.get("current_phase", "")),
            cls._rationale_tag_label(prompt_metadata.get("prompt_profile", "")),
            cls._rationale_tag_label(response_payload.get("focus", "") if prompt_type == "web_followup" else response_payload.get("priority_shift", "")),
        ], limit=5)

        normalized_timestamp = cls._normalize_process_timestamp_to_utc(log_row.get("timestamp", "")) or str(log_row.get("timestamp", "") or "")
        return {
            "id": f"provider:{prompt_type}:{normalized_timestamp}:{host_ip}:{port}:{headline}",
            "timestamp": normalized_timestamp,
            "host_ip": host_ip,
            "port": port,
            "protocol": protocol,
            "service": service,
            "kind": prompt_type,
            "headline": headline or cls._rationale_tag_label(prompt_type) or "Decision",
            "summary": summary or "Scheduler decision recorded.",
            "details": [line for line in details if str(line or "").strip()],
            "tags": tags,
            "_matched_decision_ids": matched_decision_ids,
            "_sort_ts": event_ts,
        }

    @classmethod
    def _build_audit_rationale_entry(
            cls,
            decision_row: Dict[str, Any],
            *,
            execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        tool_id = str(decision_row.get("tool_id", "") or decision_row.get("label", "") or "").strip()
        if not tool_id:
            return None
        event_ts = float(decision_row.get("_sort_ts", 0.0) or 0.0)
        execution = cls._nearest_scheduler_row(execution_index.get((
            str(decision_row.get("host_ip", "") or "").strip(),
            str(decision_row.get("port", "") or "").strip(),
            str(decision_row.get("protocol", "") or "").strip(),
            tool_id,
        ), []), event_ts)

        details: List[str] = []
        approval_state = str(decision_row.get("requires_approval", "") or "").strip().lower()
        approved = str(decision_row.get("approved", "") or "").strip().lower()
        executed = str(decision_row.get("executed", "") or "").strip().lower()
        if approved == "true" and executed == "true":
            details.append("Outcome: executed")
        elif approved == "true":
            details.append("Outcome: approved")
        elif approval_state == "true":
            details.append("Outcome: awaiting approval")
        policy_decision = str(decision_row.get("policy_decision", "") or "").strip()
        if policy_decision:
            details.append(f"Policy: {policy_decision}")
        policy_reason = cls._truncate_rationale_text(decision_row.get("policy_reason", ""), 120)
        if policy_reason:
            details.append(f"Policy reason: {policy_reason}")
        safer_alternative = cls._truncate_rationale_text(decision_row.get("safer_alternative", ""), 120)
        if safer_alternative:
            details.append(f"Safer alternative: {safer_alternative}")
        risk_summary = cls._truncate_rationale_text(decision_row.get("risk_summary", ""), 120)
        if risk_summary:
            details.append(f"Risk: {risk_summary}")
        if isinstance(execution, dict):
            execution_id = str(execution.get("execution_id", "") or "").strip()
            exit_status = str(execution.get("exit_status", "") or "").strip()
            if execution_id and exit_status:
                details.append(f"Execution: {execution_id} [exit {exit_status}]")
            elif execution_id:
                details.append(f"Execution: {execution_id}")

        normalized_timestamp = cls._normalize_process_timestamp_to_utc(decision_row.get("timestamp", "")) or str(decision_row.get("timestamp", "") or "")
        return {
            "id": f"audit:{decision_row.get('id', '')}:{tool_id}",
            "timestamp": normalized_timestamp,
            "host_ip": str(decision_row.get("host_ip", "") or "").strip(),
            "port": str(decision_row.get("port", "") or "").strip(),
            "protocol": str(decision_row.get("protocol", "") or "").strip(),
            "service": str(decision_row.get("service", "") or "").strip(),
            "kind": "decision",
            "headline": tool_id,
            "summary": cls._truncate_rationale_text(
                decision_row.get("rationale", "") or decision_row.get("reason", "") or "Scheduler decision recorded.",
                200,
            ),
            "details": [line for line in details if str(line or "").strip()],
            "tags": cls._dedupe_text_tokens([
                "Decision",
                cls._rationale_tag_label(decision_row.get("scheduler_mode", "")),
                cls._rationale_tag_label(decision_row.get("service", "")),
            ], limit=4),
            "_sort_ts": event_ts,
        }

    @classmethod
    def _build_scheduler_rationale_feed_items(
            cls,
            provider_logs: List[Dict[str, Any]],
            decisions: List[Dict[str, Any]],
            executions: List[Dict[str, Any]],
            *,
            limit: int = 18,
    ) -> List[Dict[str, Any]]:
        resolved_limit = max(1, min(int(limit or 18), 48))
        normalized_decisions = [dict(item) for item in list(decisions or []) if isinstance(item, dict)]
        normalized_executions = [dict(item) for item in list(executions or []) if isinstance(item, dict)]
        for item in normalized_decisions:
            item["_sort_ts"] = cls._scheduler_event_timestamp_epoch(item.get("timestamp", ""))
        for item in normalized_executions:
            item["_sort_ts"] = cls._scheduler_event_timestamp_epoch(item.get("started_at", "") or item.get("finished_at", ""))

        decision_index = cls._index_scheduler_rows_by_target_tool(normalized_decisions, timestamp_field="timestamp")
        execution_index = cls._index_scheduler_rows_by_target_tool(normalized_executions, timestamp_field="started_at")

        entries: List[Dict[str, Any]] = []
        matched_decision_ids = set()

        for log_row in reversed(list(provider_logs or [])):
            if not isinstance(log_row, dict):
                continue
            entry = cls._build_provider_rationale_entry(
                log_row,
                decision_index=decision_index,
                execution_index=execution_index,
            )
            if not isinstance(entry, dict):
                continue
            matched_decision_ids.update(int(item) for item in list(entry.pop("_matched_decision_ids", []) or []) if int(item or 0) > 0)
            entries.append(entry)

        for decision_row in normalized_decisions:
            try:
                decision_id = int(decision_row.get("id", 0) or 0)
            except (TypeError, ValueError):
                decision_id = 0
            if decision_id > 0 and decision_id in matched_decision_ids:
                continue
            entry = cls._build_audit_rationale_entry(
                decision_row,
                execution_index=execution_index,
            )
            if isinstance(entry, dict):
                entries.append(entry)

        entries.sort(key=lambda item: float(item.get("_sort_ts", 0.0) or 0.0), reverse=True)
        trimmed = entries[:resolved_limit]
        for item in trimmed:
            item.pop("_sort_ts", None)
        return trimmed

    def get_scan_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            ensure_scan_submission_table(project.database)
            return list_scan_submissions(project.database, limit=limit)

    @staticmethod
    def _project_listing_row(path: str, *, source: str, current_path: str = "") -> Dict[str, Any]:
        normalized_path = os.path.abspath(os.path.expanduser(str(path or "").strip()))
        modified_at = ""
        modified_at_epoch = 0.0
        try:
            modified_at_epoch = float(os.path.getmtime(normalized_path))
            modified_at = datetime.datetime.fromtimestamp(
                modified_at_epoch,
                tz=datetime.timezone.utc,
            ).isoformat()
        except Exception:
            modified_at = ""
            modified_at_epoch = 0.0
        return {
            "name": os.path.basename(normalized_path),
            "path": normalized_path,
            "source": str(source or "filesystem"),
            "is_current": bool(current_path and normalized_path == current_path),
            "exists": os.path.isfile(normalized_path),
            "modified_at": modified_at,
            "modified_at_epoch": modified_at_epoch,
        }

    def list_projects(self, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            current_name = str(self._project_metadata().get("name", "") or "").strip()
            current_path = (
                os.path.abspath(os.path.expanduser(current_name))
                if current_name else ""
            )
        max_items = max(1, min(int(limit or 500), 5000))
        roots = (
            ("temp", getTempFolder()),
            ("autosave", get_legion_autosave_dir()),
        )
        rows: List[Dict[str, Any]] = []
        seen = set()
        for source_name, root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirnames, filenames in os.walk(root):
                for filename in list(filenames or []):
                    if not str(filename or "").strip().lower().endswith(".legion"):
                        continue
                    path = os.path.abspath(os.path.join(dirpath, filename))
                    if path in seen:
                        continue
                    seen.add(path)
                    rows.append(self._project_listing_row(path, source=source_name, current_path=current_path))
        if current_path and os.path.isfile(current_path) and current_path not in seen:
            rows.append(self._project_listing_row(current_path, source="active", current_path=current_path))
        rows.sort(
            key=lambda item: (
                not bool(item.get("is_current", False)),
                -float(item.get("modified_at_epoch", 0.0) or 0.0),
                str(item.get("path", "") or "").lower(),
            )
        )
        return rows[:max_items]

    def _serialize_plan_step_preview(self, step: ScheduledAction) -> Dict[str, Any]:
        return {
            "step_id": str(step.step_id or ""),
            "action_id": str(step.action_id or ""),
            "tool_id": str(step.tool_id or ""),
            "label": str(step.label or ""),
            "description": str(step.description or ""),
            "command_template": str(step.command_template or ""),
            "origin_mode": str(step.origin_mode or ""),
            "origin_planner": str(step.origin_planner or ""),
            "engagement_preset": str(step.engagement_preset or ""),
            "target_ref": dict(step.target_ref or {}),
            "parameters": dict(step.parameters or {}),
            "rationale": str(step.rationale or ""),
            "preconditions": list(step.preconditions or []),
            "success_criteria": list(step.success_criteria or []),
            "approval_state": str(step.approval_state or ""),
            "policy_decision": str(step.policy_decision or ""),
            "policy_reason": str(step.policy_reason or ""),
            "risk_tags": list(step.risk_tags or []),
            "risk_summary": str(step.risk_summary or ""),
            "safer_alternative": str(step.safer_alternative or ""),
            "family_id": str(step.family_id or ""),
            "family_policy_state": str(step.family_policy_state or ""),
            "score": float(step.score or 0.0),
            "pack_ids": list(step.pack_ids or []),
            "methodology_tags": list(step.methodology_tags or []),
            "pack_tags": list(step.pack_tags or []),
            "coverage_gap": str(step.coverage_gap or ""),
            "coverage_notes": str(step.coverage_notes or ""),
            "evidence_expectations": list(step.evidence_expectations or []),
            "runner_type": str(getattr(step.action, "runner_type", "") or ""),
            "service_scope": list(getattr(step.action, "service_scope", []) or []),
            "protocol_scope": list(getattr(step.action, "protocol_scope", []) or []),
        }

    def get_scheduler_plan_preview(
            self,
            *,
            host_id: int = 0,
            host_ip: str = "",
            service: str = "",
            port: str = "",
            protocol: str = "tcp",
            mode: str = "compare",
            limit_targets: int = 20,
            limit_actions: int = 6,
    ) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            scheduler_prefs = self.scheduler_config.load()
            engagement_policy = self._load_engagement_policy_locked(persist_if_missing=True)
            settings = self._get_settings()
            goal_profile = str(
                engagement_policy.get("legacy_goal_profile", scheduler_prefs.get("goal_profile", "internal_asset_discovery"))
                or "internal_asset_discovery"
            )
            targets = self.scheduler_orchestrator.collect_project_targets(
                project,
                host_ids={int(host_id)} if int(host_id or 0) > 0 else None,
                allowed_states={"open", "open|filtered"},
            )

        requested_mode = str(mode or "compare").strip().lower() or "compare"
        if requested_mode not in {"current", "deterministic", "ai", "compare"}:
            requested_mode = "compare"
        resolved_host_ip = str(host_ip or "").strip()
        resolved_service = str(service or "").strip().lower()
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        max_targets = max(1, min(int(limit_targets or 20), 200))
        max_actions = max(1, min(int(limit_actions or 6), 32))
        current_mode = str(scheduler_prefs.get("mode", "deterministic") or "deterministic").strip().lower()
        recent_output_chars = int(
            self.scheduler_orchestrator._scheduler_feedback_config(scheduler_prefs).get("recent_output_chars", 900) or 900
        )

        filtered_targets: List[Any] = []
        for target in list(targets or []):
            if resolved_host_ip and str(target.host_ip or "").strip() != resolved_host_ip:
                continue
            if resolved_service and str(target.service_name or "").strip().lower() != resolved_service:
                continue
            if resolved_port and str(target.port or "").strip() != resolved_port:
                continue
            if resolved_protocol and str(target.protocol or "tcp").strip().lower() != resolved_protocol:
                continue
            filtered_targets.append(target)
            if len(filtered_targets) >= max_targets:
                break

        previews = []
        for target in filtered_targets:
            attempted_summary = self._existing_attempt_summary_for_target(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
            )
            attempted_tool_ids = sorted(attempted_summary["tool_ids"])
            context = self._build_scheduler_target_context(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                goal_profile=goal_profile,
                attempted_tool_ids=set(attempted_tool_ids),
                attempted_family_ids=set(attempted_summary["family_ids"]),
                attempted_command_signatures=set(attempted_summary["command_signatures"]),
                recent_output_chars=recent_output_chars,
                analysis_mode="standard",
            )

            def _preview_for_mode(selected_mode: str) -> Dict[str, Any]:
                steps = self.scheduler_planner.plan_steps(
                    str(target.service_name or ""),
                    str(target.protocol or "tcp"),
                    settings,
                    context=context,
                    excluded_tool_ids=list(attempted_tool_ids),
                    excluded_family_ids=sorted(attempted_summary["family_ids"]),
                    excluded_command_signatures=sorted(attempted_summary["command_signatures"]),
                    limit=max_actions,
                    engagement_policy=engagement_policy,
                    mode_override=selected_mode,
                )
                serialized = [self._serialize_plan_step_preview(step) for step in list(steps or [])]
                fallback_used = bool(
                    selected_mode == "ai"
                    and serialized
                    and not any(str(item.get("origin_mode", "") or "").strip().lower() == "ai" for item in serialized)
                )
                return {
                    "requested_mode": str(selected_mode or ""),
                    "fallback_used": fallback_used,
                    "steps": serialized,
                }

            preview = {
                "target": {
                    "host_id": int(target.host_id or 0),
                    "host_ip": str(target.host_ip or ""),
                    "hostname": str(target.hostname or ""),
                    "port": str(target.port or ""),
                    "protocol": str(target.protocol or "tcp"),
                    "service_name": str(target.service_name or ""),
                },
                "attempted_tool_ids": list(attempted_tool_ids),
                "attempted_family_ids": sorted(attempted_summary["family_ids"]),
            }
            if requested_mode == "compare":
                deterministic_preview = _preview_for_mode("deterministic")
                ai_preview = _preview_for_mode("ai")
                deterministic_tool_ids = {
                    str(item.get("tool_id", "") or "").strip().lower()
                    for item in list(deterministic_preview.get("steps", []) or [])
                    if str(item.get("tool_id", "") or "").strip()
                }
                ai_tool_ids = {
                    str(item.get("tool_id", "") or "").strip().lower()
                    for item in list(ai_preview.get("steps", []) or [])
                    if str(item.get("tool_id", "") or "").strip()
                }
                preview.update({
                    "mode": "compare",
                    "deterministic": deterministic_preview,
                    "ai": ai_preview,
                    "agreement": sorted(deterministic_tool_ids & ai_tool_ids),
                    "deterministic_only": sorted(deterministic_tool_ids - ai_tool_ids),
                    "ai_only": sorted(ai_tool_ids - deterministic_tool_ids),
                })
            else:
                selected_mode = current_mode if requested_mode == "current" else requested_mode
                preview.update({
                    "mode": requested_mode,
                    "selected_mode": selected_mode,
                    "plan": _preview_for_mode(selected_mode),
                })
            previews.append(preview)

        return {
            "requested_mode": requested_mode,
            "current_mode": current_mode,
            "engagement_policy": dict(engagement_policy or {}),
            "target_count": len(previews),
            "targets": previews,
        }

    def get_target_state_view(self, host_id: int = 0, limit: int = 500) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            max_hosts = max(1, min(int(limit or 500), 5000))
            if int(host_id or 0) > 0:
                host = self._resolve_host(int(host_id))
                if host is None:
                    raise KeyError(f"Unknown host id: {host_id}")
                host_row = {
                    "id": int(getattr(host, "id", 0) or 0),
                    "ip": str(getattr(host, "ip", "") or ""),
                    "hostname": str(getattr(host, "hostname", "") or ""),
                    "status": str(getattr(host, "status", "") or ""),
                    "os": str(getattr(host, "osMatch", "") or ""),
                }
                return {
                    "host": host_row,
                    "target_state": get_target_state(project.database, int(host_id)) or {},
                }

            states = []
            for row in list(self._hosts(limit=max_hosts) or []):
                states.append({
                    "host": dict(row),
                    "target_state": get_target_state(project.database, int(row.get("id", 0) or 0)) or {},
                })
            return {
                "count": len(states),
                "states": states,
            }

    def get_findings(self, host_id: int = 0, limit_hosts: int = 500, limit_findings: int = 1000) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            if int(host_id or 0) > 0:
                host = self._resolve_host(int(host_id))
                if host is None:
                    raise KeyError(f"Unknown host id: {host_id}")
                host_rows = [{
                    "id": int(getattr(host, "id", 0) or 0),
                    "ip": str(getattr(host, "ip", "") or ""),
                    "hostname": str(getattr(host, "hostname", "") or ""),
                    "status": str(getattr(host, "status", "") or ""),
                    "os": str(getattr(host, "osMatch", "") or ""),
                }]
            else:
                host_rows = list(self._hosts(limit=max(1, min(int(limit_hosts or 500), 5000))) or [])

            findings = []
            max_items = max(1, min(int(limit_findings or 1000), 5000))
            for row in host_rows:
                state = get_target_state(project.database, int(row.get("id", 0) or 0)) or {}
                for item in list(state.get("findings", []) or []):
                    if not isinstance(item, dict):
                        continue
                    findings.append({
                        "host": dict(row),
                        "title": str(item.get("title", "") or ""),
                        "severity": str(item.get("severity", "") or ""),
                        "confidence": item.get("confidence", 0.0),
                        "source_kind": str(item.get("source_kind", "") or "observed"),
                        "finding": dict(item),
                    })
                    if len(findings) >= max_items:
                        break
                if len(findings) >= max_items:
                    break
            return {
                "count": len(findings),
                "host_scope_count": len(host_rows),
                "findings": findings,
            }

    @staticmethod
    def _read_text_excerpt(path: str, max_chars: int = 4000) -> str:
        normalized_path = str(path or "").strip()
        if not normalized_path or not os.path.isfile(normalized_path):
            return ""
        safe_max_chars = max(0, min(int(max_chars or 4000), 200000))
        if safe_max_chars <= 0:
            return ""
        try:
            size = os.path.getsize(normalized_path)
            read_bytes = max(4096, min(safe_max_chars * 4, 2_000_000))
            with open(normalized_path, "rb") as handle:
                if size > read_bytes:
                    handle.seek(size - read_bytes)
                data = handle.read(read_bytes)
            return data.decode("utf-8", errors="replace")[-safe_max_chars:]
        except Exception:
            return ""

    def get_scheduler_execution_traces(
            self,
            *,
            limit: int = 200,
            host_id: int = 0,
            host_ip: str = "",
            tool_id: str = "",
            include_output: bool = False,
            output_max_chars: int = 4000,
    ) -> List[Dict[str, Any]]:
        resolved_host_ip = str(host_ip or "").strip()
        if int(host_id or 0) > 0 and not resolved_host_ip:
            with self._lock:
                host = self._resolve_host(int(host_id))
                if host is None:
                    raise KeyError(f"Unknown host id: {host_id}")
                resolved_host_ip = str(getattr(host, "ip", "") or "")
        rows = self.get_scheduler_execution_records(limit=max(1, min(max(int(limit or 200), 50), 1000)))
        filtered = []
        normalized_tool_id = str(tool_id or "").strip().lower()
        for item in list(rows or []):
            if resolved_host_ip and str(item.get("host_ip", "") or "").strip() != resolved_host_ip:
                continue
            if normalized_tool_id and str(item.get("tool_id", "") or "").strip().lower() != normalized_tool_id:
                continue
            record = dict(item)
            if include_output:
                record["stdout_excerpt"] = self._read_text_excerpt(
                    str(record.get("stdout_ref", "") or ""),
                    max_chars=output_max_chars,
                )
                record["stderr_excerpt"] = self._read_text_excerpt(
                    str(record.get("stderr_ref", "") or ""),
                    max_chars=output_max_chars,
                )
            filtered.append(record)
            if len(filtered) >= max(1, min(int(limit or 200), 1000)):
                break
        return filtered

    def get_scheduler_execution_trace(self, execution_id: str, output_max_chars: int = 4000) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_execution_table(project.database)
            trace = get_execution_record(project.database, str(execution_id or ""))
        if trace is None:
            raise KeyError(f"Unknown execution id: {execution_id}")
        payload = dict(trace)
        payload["stdout_excerpt"] = self._read_text_excerpt(
            str(payload.get("stdout_ref", "") or ""),
            max_chars=output_max_chars,
        )
        payload["stderr_excerpt"] = self._read_text_excerpt(
            str(payload.get("stderr_ref", "") or ""),
            max_chars=output_max_chars,
        )
        return payload

    def get_evidence_graph(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            resolved = dict(filters or {})
            return query_evidence_graph(
                project.database,
                node_types=resolved.get("node_types"),
                edge_types=resolved.get("edge_types"),
                source_kinds=resolved.get("source_kinds"),
                min_confidence=float(resolved.get("min_confidence", 0.0) or 0.0),
                search=str(resolved.get("search", "") or ""),
                include_ai_suggested=bool(resolved.get("include_ai_suggested", True)),
                hide_nmap_xml_artifacts=bool(resolved.get("hide_nmap_xml_artifacts", False)),
                hide_down_hosts=str(resolved.get("host_filter", "hide_down") or "").strip().lower() != "show_all",
                host_id=int(resolved.get("host_id", 0) or 0) or None,
                limit_nodes=int(resolved.get("limit_nodes", 600) or 600),
                limit_edges=int(resolved.get("limit_edges", 1200) or 1200),
            )

    @staticmethod
    def _path_within(base_path: str, candidate_path: str) -> bool:
        root = os.path.abspath(str(base_path or "").strip())
        target = os.path.abspath(str(candidate_path or "").strip())
        if not root or not target:
            return False
        try:
            return os.path.commonpath([root, target]) == root
        except Exception:
            return False

    def _is_project_artifact_path(self, project, path: str) -> bool:
        candidate = os.path.abspath(str(path or "").strip())
        if not candidate or not os.path.isfile(candidate):
            return False
        roots = [
            getattr(getattr(project, "properties", None), "outputFolder", ""),
            getattr(getattr(project, "properties", None), "runningFolder", ""),
        ]
        return any(self._path_within(root, candidate) for root in roots if str(root or "").strip())

    @staticmethod
    def _read_text_file_head(path: str, max_chars: int = 12000) -> str:
        normalized_path = str(path or "").strip()
        if not normalized_path or not os.path.isfile(normalized_path):
            return ""
        safe_max_chars = max(0, min(int(max_chars or 12000), 200000))
        if safe_max_chars <= 0:
            return ""
        try:
            read_bytes = max(4096, min(safe_max_chars * 4, 2_000_000))
            with open(normalized_path, "rb") as handle:
                data = handle.read(read_bytes)
            return data.decode("utf-8", errors="replace")[:safe_max_chars]
        except Exception:
            return ""

    @staticmethod
    def _binary_file_signature(path: str, sample_size: int = 8192) -> bool:
        normalized_path = str(path or "").strip()
        if not normalized_path or not os.path.isfile(normalized_path):
            return False
        try:
            with open(normalized_path, "rb") as handle:
                sample = handle.read(max(256, min(int(sample_size or 8192), 65536)))
            if not sample:
                return False
            return b"\x00" in sample
        except Exception:
            return False

    def _get_graph_snapshot_locked(self) -> Dict[str, Any]:
        project = self._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return query_evidence_graph(project.database, limit_nodes=5000, limit_edges=10000)

    def _graph_inline_evidence_text(self, project, node: Dict[str, Any], props: Dict[str, Any], *, max_chars: int = 12000) -> str:
        lines: List[str] = []
        seen = set()

        def _remember(value: Any):
            cleaned = str(value or "").strip()
            if not cleaned:
                return
            lowered = cleaned.lower()
            if lowered in seen:
                return
            seen.add(lowered)
            lines.append(cleaned)

        _remember(props.get("evidence", ""))
        for token in list(props.get("evidence_items", []) or []):
            _remember(token)
        for token in list(node.get("evidence_refs", []) or []):
            cleaned = str(token or "").strip()
            if not cleaned:
                continue
            if cleaned.startswith("process_output:") or cleaned.startswith("/api/screenshots/") or self._is_project_artifact_path(project, cleaned):
                continue
            _remember(cleaned)
        inline_text = "\n".join(lines).strip()
        safe_max_chars = max(0, min(int(max_chars or 12000), 200000))
        return inline_text[:safe_max_chars] if safe_max_chars > 0 else ""

    def _resolve_graph_content_entry_locked(self, project, node: Dict[str, Any], *, max_chars: int = 12000) -> Dict[str, Any]:
        node_id = str(node.get("node_id", "") or "")
        node_type = str(node.get("type", "") or "").strip().lower()
        props = node.get("properties", {}) if isinstance(node.get("properties", {}), dict) else {}
        evidence_refs = [
            str(item or "").strip()
            for item in list(node.get("evidence_refs", []) or [])
            if str(item or "").strip()
        ]
        ref = str(
            props.get("artifact_ref", "")
            or props.get("ref", "")
            or ""
        ).strip()
        if not ref:
            for candidate in evidence_refs:
                if candidate.startswith("process_output:") or candidate.startswith("/api/screenshots/") or self._is_project_artifact_path(project, candidate):
                    ref = candidate
                    break
        label = str(node.get("label", "") or os.path.basename(ref) or node_id)
        filename = str(props.get("filename", "") or os.path.basename(ref) or f"{node_type or 'graph-content'}-{node_id}")
        resolved_ref = ref
        if ref.startswith("/api/screenshots/"):
            try:
                resolved_ref = self.get_screenshot_file(os.path.basename(ref))
            except Exception:
                resolved_ref = ref
        elif node_type == "screenshot" and filename.lower().endswith(".png") and not self._is_project_artifact_path(project, ref):
            try:
                resolved_ref = self.get_screenshot_file(filename)
            except Exception:
                resolved_ref = ref
        base = {
            "node_id": node_id,
            "node_type": node_type,
            "label": label,
            "filename": filename,
            "ref": ref,
            "path": "",
            "kind": "unavailable",
            "available": False,
            "preview_text": "",
            "preview_url": "",
            "download_url": "",
            "message": "No preview is available for this graph node.",
        }

        if ref.startswith("process_output:"):
            try:
                process_id = int(ref.split(":", 1)[1])
            except (TypeError, ValueError):
                return base
            payload = self.get_process_output(process_id, offset=0, max_chars=max_chars)
            output_text = str(payload.get("output", "") or payload.get("output_chunk", "") or "")
            return {
                **base,
                "kind": "text",
                "available": bool(output_text),
                "preview_text": output_text,
                "filename": filename if filename.endswith(".txt") else f"process-{process_id}-output.txt",
                "download_url": f"/api/graph/content/{node_id}?download=1",
                "message": "" if output_text else "No captured process output is available.",
            }

        if resolved_ref and self._is_project_artifact_path(project, resolved_ref):
            mimetype = mimetypes.guess_type(resolved_ref)[0] or "application/octet-stream"
            if node_type == "screenshot" or resolved_ref.lower().endswith(".png"):
                return {
                    **base,
                    "path": resolved_ref,
                    "kind": "image",
                    "available": True,
                    "preview_url": f"/api/graph/content/{node_id}",
                    "download_url": f"/api/graph/content/{node_id}?download=1",
                    "message": "",
                }

            if self._binary_file_signature(resolved_ref):
                return {
                    **base,
                    "path": resolved_ref,
                    "kind": "binary",
                    "available": True,
                    "download_url": f"/api/graph/content/{node_id}?download=1",
                    "message": f"Binary artifact ({mimetype}) is available for download.",
                }

            preview_text = self._read_text_file_head(resolved_ref, max_chars=max_chars)
            return {
                **base,
                "path": resolved_ref,
                "kind": "text",
                "available": bool(preview_text),
                "preview_text": preview_text,
                "download_url": f"/api/graph/content/{node_id}?download=1",
                "message": "" if preview_text else "Artifact file is empty.",
            }

        inline_text = self._graph_inline_evidence_text(project, node, props, max_chars=max_chars)
        if inline_text:
            return {
                **base,
                "kind": "text",
                "available": True,
                "preview_text": inline_text,
                "download_url": f"/api/graph/content/{node_id}?download=1",
                "message": "",
            }

        return base

    def get_graph_related_content(self, node_id: str, *, max_chars: int = 12000) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            snapshot = self._get_graph_snapshot_locked()
            nodes = {
                str(item.get("node_id", "") or ""): item
                for item in list(snapshot.get("nodes", []) or [])
                if isinstance(item, dict) and str(item.get("node_id", "") or "").strip()
            }
            selected_id = str(node_id or "").strip()
            selected_node = nodes.get(selected_id)
            if selected_node is None:
                raise KeyError(f"Unknown graph node id: {node_id}")

            candidate_ids = []
            if str(selected_node.get("type", "") or "").strip().lower() in {"artifact", "screenshot", "evidence_record"}:
                candidate_ids.append(selected_id)
            for edge in list(snapshot.get("edges", []) or []):
                if not isinstance(edge, dict):
                    continue
                from_id = str(edge.get("from_node_id", "") or "")
                to_id = str(edge.get("to_node_id", "") or "")
                if selected_id not in {from_id, to_id}:
                    continue
                other_id = to_id if from_id == selected_id else from_id
                other_node = nodes.get(other_id)
                other_type = str(other_node.get("type", "") or "").strip().lower() if isinstance(other_node, dict) else ""
                if other_type in {"artifact", "screenshot", "evidence_record"} and other_id not in candidate_ids:
                    candidate_ids.append(other_id)

            entries = [
                self._resolve_graph_content_entry_locked(project, nodes[candidate_id], max_chars=max_chars)
                for candidate_id in candidate_ids[:8]
                if candidate_id in nodes
            ]
            return {
                "node_id": selected_id,
                "entry_count": len(entries),
                "entries": entries,
            }

    def get_graph_content(self, node_id: str, *, download: bool = False, max_chars: int = 12000) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            snapshot = self._get_graph_snapshot_locked()
            node = next(
                (
                    item for item in list(snapshot.get("nodes", []) or [])
                    if isinstance(item, dict) and str(item.get("node_id", "") or "") == str(node_id or "").strip()
                ),
                None,
            )
            if node is None:
                raise KeyError(f"Unknown graph node id: {node_id}")
            entry = self._resolve_graph_content_entry_locked(project, node, max_chars=max_chars)
            ref = str(entry.get("ref", "") or "").strip()
            resolved_path = str(entry.get("path", "") or "").strip()
            if str(entry.get("kind", "") or "") == "text" and (ref.startswith("process_output:") or not resolved_path):
                return {
                    "kind": "text",
                    "text": str(entry.get("preview_text", "") or ""),
                    "filename": str(entry.get("filename", "") or f"{node_id}.txt"),
                    "mimetype": "text/plain; charset=utf-8",
                    "download": bool(download),
                }
            if (
                    str(entry.get("kind", "") or "") in {"image", "binary", "text"}
                    and resolved_path
                    and self._is_project_artifact_path(project, resolved_path)
            ):
                return {
                    "kind": str(entry.get("kind", "") or "binary"),
                    "path": resolved_path,
                    "filename": str(entry.get("filename", "") or os.path.basename(resolved_path) or f"{node_id}.bin"),
                    "mimetype": mimetypes.guess_type(resolved_path)[0] or (
                        "text/plain; charset=utf-8" if str(entry.get("kind", "") or "") == "text" else "application/octet-stream"
                    ),
                    "download": bool(download),
                }
            raise FileNotFoundError(str(entry.get("message", "") or "Graph content is not available."))

    def rebuild_evidence_graph(self, host_id: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            mutations = rebuild_evidence_graph(project.database, host_id=int(host_id or 0) or None)
            snapshot = query_evidence_graph(project.database, limit_nodes=25, limit_edges=50)
            return {
                "mutations": list(mutations or []),
                "mutation_count": len(list(mutations or [])),
                "nodes": int(snapshot.get("meta", {}).get("total_nodes", 0) or 0),
                "edges": int(snapshot.get("meta", {}).get("total_edges", 0) or 0),
                "host_id": int(host_id or 0) or None,
            }

    def export_evidence_graph_json(self, *, rebuild: bool = False) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            return export_evidence_graph_json(project.database, rebuild=bool(rebuild))

    def export_evidence_graph_graphml(self, *, rebuild: bool = False) -> str:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            return export_evidence_graph_graphml(project.database, rebuild=bool(rebuild))

    def get_evidence_graph_layouts(self) -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            return list_graph_layout_states(project.database)

    def save_evidence_graph_layout(
            self,
            *,
            view_id: str,
            name: str,
            layout_state: Dict[str, Any],
            layout_id: str = "",
    ) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            return upsert_graph_layout_state(
                project.database,
                view_id=str(view_id or ""),
                name=str(name or ""),
                layout_state=layout_state if isinstance(layout_state, dict) else {},
                layout_id=str(layout_id or ""),
            )

    def get_evidence_graph_annotations(self, *, target_ref: str = "", target_kind: str = "") -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            return list_graph_annotations(
                project.database,
                target_ref=str(target_ref or ""),
                target_kind=str(target_kind or ""),
            )

    def save_evidence_graph_annotation(
            self,
            *,
            target_kind: str,
            target_ref: str,
            body: str,
            created_by: str = "operator",
            source_ref: str = "",
            annotation_id: str = "",
    ) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_graph_tables(project.database)
            return upsert_graph_annotation(
                project.database,
                target_kind=str(target_kind or ""),
                target_ref=str(target_ref or ""),
                body=str(body or ""),
                created_by=str(created_by or "operator"),
                source_ref=str(source_ref or ""),
                annotation_id=str(annotation_id or ""),
            )

    @staticmethod
    def _collect_command_artifacts(outputfile: str) -> List[str]:
        base_path = str(outputfile or "").strip()
        if not base_path:
            return []
        matches = []
        for path in sorted(set(glob.glob(f"{base_path}*"))):
            if os.path.exists(path):
                matches.append(path)
        return matches

    def _persist_scheduler_execution_record(
            self,
            decision: ScheduledAction,
            execution_record: Optional[ExecutionRecord],
            *,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(execution_record, ExecutionRecord):
            return None
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            database = getattr(project, "database", None) if project else None
            if database is None:
                return None
            try:
                ensure_scheduler_execution_table(database)
                return store_execution_record(
                    database,
                    execution_record,
                    step=decision,
                    host_ip=host_ip,
                    port=port,
                    protocol=protocol,
                    service=service_name,
                )
            except Exception:
                return None

    def approve_scheduler_approval(
            self,
            approval_id: int,
            approve_family: bool = False,
            run_now: bool = True,
            family_action: str = "",
    ):
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_approval_table(project.database)
            item = get_pending_approval(project.database, int(approval_id))
            if item is None:
                raise KeyError(f"Unknown approval id: {approval_id}")
            if str(item.get("status", "")).strip().lower() not in {"pending", "approved"}:
                return {"approval": item, "job": None}

            resolved_family_action = "allowed" if approve_family and not family_action else str(family_action or "")
            if resolved_family_action not in {"", "allowed", "approval_required"}:
                resolved_family_action = ""
            applied_family_state = self._apply_family_policy_action(
                item,
                resolved_family_action,
                reason="approved via web",
            )
            runner_type = self._runner_type_for_approval_item(item)
            approved_reason = "approved for operator execution" if runner_type == "manual" else "approved via web"

            updated = update_pending_approval(
                project.database,
                int(approval_id),
                status="approved",
                decision_reason=approved_reason,
                family_policy_state=applied_family_state or item.get("family_policy_state", ""),
            )
            update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=True,
                executed=False,
                reason=approved_reason,
            )

        if runner_type == "manual" or not run_now:
            self._emit_ui_invalidation("approvals", "decisions", "overview")
            return {"approval": updated, "job": None}

        job = self._start_job(
            "scheduler-approval-execute",
            lambda job_id: self._execute_approved_scheduler_item(int(approval_id), job_id=job_id),
            payload={
                "approval_id": int(approval_id),
                "approve_family": bool(approve_family),
                "family_action": str(resolved_family_action or ""),
            },
        )
        with self._lock:
            project = self._require_active_project()
            final_state = update_pending_approval(
                project.database,
                int(approval_id),
                status="approved",
                decision_reason="approved & queued",
                execution_job_id=str(job.get("id", "")),
                family_policy_state=applied_family_state or item.get("family_policy_state", ""),
            )
            update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=True,
                executed=False,
                reason="approved & queued",
            )
        self._emit_ui_invalidation("approvals", "decisions", "overview")
        return {"approval": final_state, "job": job}

    def reject_scheduler_approval(self, approval_id: int, reason: str = "rejected via web", family_action: str = ""):
        with self._lock:
            project = self._require_active_project()
            ensure_scheduler_approval_table(project.database)
            item = get_pending_approval(project.database, int(approval_id))
            if item is None:
                raise KeyError(f"Unknown approval id: {approval_id}")
            resolved_family_action = str(family_action or "").strip().lower()
            if resolved_family_action not in {"", "approval_required", "suppressed", "blocked"}:
                resolved_family_action = ""
            applied_family_state = self._apply_family_policy_action(item, resolved_family_action, reason=reason)
            updated = update_pending_approval(
                project.database,
                int(approval_id),
                status="rejected",
                decision_reason=str(reason or "rejected via web"),
                family_policy_state=applied_family_state or item.get("family_policy_state", ""),
            )
            update_scheduler_decision_for_approval(
                project.database,
                int(approval_id),
                approved=False,
                executed=False,
                reason=str(reason or "rejected via web"),
            )
            result = updated
        self._emit_ui_invalidation("approvals", "decisions", "overview")
        return result

    def get_project_details(self) -> Dict[str, Any]:
        with self._lock:
            metadata = self._project_metadata()
            metadata["is_temporary"] = self._is_temp_project()
            return metadata

    def get_tool_audit(self) -> Dict[str, Any]:
        settings = getattr(self, "settings", None)
        if settings is None:
            settings = Settings(AppSettings())
        entries = audit_legion_tools(settings)
        return {
            "summary": tool_audit_summary(entries),
            "tools": [entry.to_dict() for entry in entries],
            "supported_platforms": ["kali", "ubuntu"],
            "recommended_platform": detect_supported_tool_install_platform(),
        }

    @staticmethod
    def _tool_audit_availability(entries: Any) -> Dict[str, List[str]]:
        available = set()
        unavailable = set()
        for item in list(entries or []):
            status = ""
            key = ""
            if isinstance(item, dict):
                key = str(item.get("key", "") or "").strip().lower()
                status = str(item.get("status", "") or "").strip().lower()
            else:
                key = str(getattr(item, "key", "") or "").strip().lower()
                status = str(getattr(item, "status", "") or "").strip().lower()
            if not key:
                continue
            if status == "installed":
                available.add(key)
            elif status in {"missing", "configured-missing"}:
                unavailable.add(key)
        unavailable.difference_update(available)
        return {
            "available_tool_ids": sorted(available),
            "unavailable_tool_ids": sorted(unavailable),
        }

    def _scheduler_tool_audit_snapshot(self) -> Dict[str, List[str]]:
        settings = getattr(self, "settings", None)
        if settings is None:
            settings = Settings(AppSettings())
        return self._tool_audit_availability(audit_legion_tools(settings))

    def get_tool_install_plan(
            self,
            *,
            platform: str = "kali",
            scope: str = "missing",
            tool_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        settings = getattr(self, "settings", None)
        if settings is None:
            settings = Settings(AppSettings())
        entries = audit_legion_tools(settings)
        return build_tool_install_plan(
            entries,
            platform=platform,
            scope=scope,
            tool_keys=tool_keys,
        )

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

    def start_tool_install_job(
            self,
            *,
            platform: str = "kali",
            scope: str = "missing",
            tool_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        normalized_platform = normalize_tool_install_platform(platform)
        normalized_scope = str(scope or "missing").strip().lower() or "missing"
        normalized_keys = [str(item or "").strip() for item in list(tool_keys or []) if str(item or "").strip()]
        payload = {
            "platform": normalized_platform,
            "scope": normalized_scope,
            "tool_keys": normalized_keys,
        }
        return self._start_job(
            "tool-install",
            lambda job_id: self._run_tool_install_job(
                platform=normalized_platform,
                scope=normalized_scope,
                tool_keys=normalized_keys,
                job_id=int(job_id or 0),
            ),
            payload=payload,
        )

    def _run_tool_install_job(
            self,
            *,
            platform: str = "kali",
            scope: str = "missing",
            tool_keys: Optional[List[str]] = None,
            job_id: int = 0,
    ) -> Dict[str, Any]:
        plan = self.get_tool_install_plan(platform=platform, scope=scope, tool_keys=tool_keys)
        resolved_job_id = int(job_id or 0)
        return execute_tool_install_plan(
            plan,
            is_cancel_requested=(lambda: self.jobs.is_cancel_requested(resolved_job_id)) if resolved_job_id > 0 else None,
        )

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
            self._ensure_process_tables()
            props = project.properties
            project_file = str(getattr(props, "projectName", "") or "")
            output_folder = str(getattr(props, "outputFolder", "") or "")
            running_folder = str(getattr(props, "runningFolder", "") or "")
        try:
            provider_logs = self.get_scheduler_provider_logs(limit=1000)
        except Exception:
            provider_logs = []
        try:
            process_history = self._process_history_records(project)
        except Exception:
            process_history = []

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
                "provider_log_count": len(provider_logs) if isinstance(provider_logs, list) else 0,
                "process_history_count": len(process_history) if isinstance(process_history, list) else 0,
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
            archive.writestr(
                f"{root_name}/provider-logs.json",
                json.dumps(list(provider_logs or []), indent=2, sort_keys=True),
            )
            archive.writestr(
                f"{root_name}/process-history.json",
                json.dumps(list(process_history or []), indent=2, sort_keys=True),
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

        self._rebase_restored_project_paths(
            project_path=project_path,
            manifest=manifest,
            output_folder=output_folder,
            running_folder=running_folder,
        )

        with self._lock:
            if self._save_in_progress:
                raise RuntimeError("Project save is in progress. Try again when it finishes.")
            self._close_active_project()
            self.logic.openExistingProject(project_path, projectType="legion")
            self._attach_restored_running_folder_locked(running_folder)
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
        job = self._start_job(
            "import-nmap-xml",
            lambda job_id: self._import_nmap_xml(xml_path, bool(run_actions), job_id=int(job_id or 0)),
            payload={"path": xml_path, "run_actions": bool(run_actions)},
        )
        self._record_scan_submission(
            submission_kind="import_nmap_xml",
            job_id=int(job.get("id", 0) or 0),
            source_path=xml_path,
            run_actions=bool(run_actions),
            result_summary=f"queued import from {os.path.basename(xml_path)}",
        )
        return job

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
        job = self._start_job(
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
        self._record_scan_submission(
            submission_kind="nmap_scan",
            job_id=int(job.get("id", 0) or 0),
            targets=normalized_targets,
            discovery=bool(discovery),
            staged=bool(staged),
            run_actions=bool(run_actions),
            nmap_path=resolved_nmap_path,
            nmap_args=resolved_nmap_args,
            scan_mode=resolved_scan_mode,
            scan_options=resolved_scan_options,
            result_summary=f"queued nmap for {self._compact_targets(normalized_targets)}",
        )
        return job

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
            hostname = str(getattr(host, "hostname", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")

        scan_target = choose_preferred_command_host(hostname, host_ip, "nmap")
        uses_hostname_target = scan_target != host_ip
        default_scan_options = {
            "discovery": True,
            "skip_dns": not uses_hostname_target,
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
            targets=[scan_target],
            discovery=True,
            staged=False,
            run_actions=False,
            nmap_path="nmap",
            nmap_args="",
            scan_mode="easy",
            scan_options=default_scan_options,
        )

    def start_subnet_rescan_job(self, subnet: str) -> Dict[str, Any]:
        normalized_subnet = self._normalize_subnet_target(subnet)
        with self._lock:
            for job in self.jobs.list_jobs(limit=200):
                if str(job.get("type", "")).strip() != "nmap-scan":
                    continue
                status = str(job.get("status", "") or "").strip().lower()
                if status not in {"queued", "running"}:
                    continue
                payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
                try:
                    job_targets = self._normalize_targets(payload.get("targets", []))
                except Exception:
                    job_targets = []
                if normalized_subnet in job_targets:
                    existing_copy = dict(job)
                    existing_copy["existing"] = True
                    return existing_copy
            template = self._best_scan_submission_for_subnet(normalized_subnet, self.get_scan_history(limit=400))

        if isinstance(template, dict):
            return self.start_nmap_scan_job(
                targets=[normalized_subnet],
                discovery=self._record_bool(template.get("discovery"), True),
                staged=self._record_bool(template.get("staged"), False),
                run_actions=self._record_bool(template.get("run_actions"), False),
                nmap_path=str(template.get("nmap_path", "nmap") or "nmap").strip() or "nmap",
                nmap_args=str(template.get("nmap_args", "") or "").strip(),
                scan_mode=str(template.get("scan_mode", "legacy") or "legacy").strip().lower() or "legacy",
                scan_options=dict(template.get("scan_options", {}) or {}),
            )

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
            targets=[normalized_subnet],
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

    def start_host_screenshot_refresh_job(self, host_id: int) -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        with self._lock:
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")
            existing = self._find_active_job(job_type="host-screenshot-refresh", host_id=resolved_host_id)
            if existing is not None:
                existing_copy = dict(existing)
                existing_copy["existing"] = True
                return existing_copy

        targets = self._collect_host_screenshot_targets(resolved_host_id)
        if not targets:
            raise ValueError("Host does not have any open HTTP/HTTPS services to screenshot.")

        return self._start_job(
            "host-screenshot-refresh",
            lambda job_id: self._run_host_screenshot_refresh(
                host_id=resolved_host_id,
                job_id=int(job_id or 0),
            ),
            payload={
                "host_id": resolved_host_id,
                "host_ip": host_ip,
                "target_count": len(targets),
            },
        )

    def start_graph_screenshot_refresh_job(self, host_id: int, port: str, protocol: str = "tcp") -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        if resolved_host_id <= 0 or not resolved_port:
            raise ValueError("host_id and port are required.")
        with self._lock:
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")
            for job in self.jobs.list_jobs(limit=200):
                if str(job.get("type", "")).strip() != "graph-screenshot-refresh":
                    continue
                status = str(job.get("status", "") or "").strip().lower()
                if status not in {"queued", "running"}:
                    continue
                payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
                if int(payload.get("host_id", 0) or 0) != resolved_host_id:
                    continue
                if str(payload.get("port", "") or "").strip() != resolved_port:
                    continue
                if str(payload.get("protocol", "tcp") or "tcp").strip().lower() != resolved_protocol:
                    continue
                existing_copy = dict(job)
                existing_copy["existing"] = True
                return existing_copy
            service_name = self._service_name_for_target(host_ip, resolved_port, resolved_protocol)
            normalized_service = str(service_name or "").strip().rstrip("?").lower()
            if not (
                    self._is_web_screenshot_target(resolved_port, resolved_protocol, normalized_service)
                    or self._is_rdp_service(normalized_service)
                    or self._is_vnc_service(normalized_service)
            ):
                raise ValueError("Target does not support screenshot refresh.")

        return self._start_job(
            "graph-screenshot-refresh",
            lambda job_id: self._run_graph_screenshot_refresh(
                host_id=resolved_host_id,
                port=resolved_port,
                protocol=resolved_protocol,
                job_id=int(job_id or 0),
            ),
            payload={
                "host_id": resolved_host_id,
                "host_ip": host_ip,
                "port": resolved_port,
                "protocol": resolved_protocol,
            },
        )

    def delete_graph_screenshot(
            self,
            *,
            host_id: int,
            artifact_ref: str = "",
            filename: str = "",
            port: str = "",
            protocol: str = "tcp",
    ) -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        if resolved_host_id <= 0:
            raise ValueError("host_id is required.")
        resolved_artifact_ref = str(artifact_ref or "").strip()
        resolved_filename = os.path.basename(str(filename or "").strip())
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        if not resolved_artifact_ref and not resolved_filename:
            raise ValueError("artifact_ref or filename is required.")

        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")

            screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
            candidate_paths: List[str] = []
            if resolved_filename:
                candidate_paths.append(os.path.join(screenshot_dir, resolved_filename))
            if resolved_artifact_ref:
                if resolved_artifact_ref.startswith("/api/screenshots/"):
                    api_filename = os.path.basename(resolved_artifact_ref)
                    if api_filename:
                        candidate_paths.append(os.path.join(screenshot_dir, api_filename))
                else:
                    candidate_paths.append(resolved_artifact_ref)
            normalized_candidates: List[str] = []
            for path in candidate_paths:
                normalized = os.path.abspath(str(path or "").strip())
                if normalized and normalized not in normalized_candidates:
                    normalized_candidates.append(normalized)
                    metadata_candidate = screenshot_metadata_path(normalized)
                    if metadata_candidate and metadata_candidate not in normalized_candidates:
                        normalized_candidates.append(metadata_candidate)

            deleted_files = 0
            deleted_paths: List[str] = []
            for path in normalized_candidates:
                if not os.path.isfile(path):
                    continue
                if not self._is_project_artifact_path(project, path):
                    continue
                try:
                    os.remove(path)
                    deleted_files += 1
                    deleted_paths.append(path)
                except Exception:
                    continue

            target_state = get_target_state(project.database, resolved_host_id) or {}
            filtered_screenshots = []
            for item in list(target_state.get("screenshots", []) or []):
                if not isinstance(item, dict):
                    continue
                item_ref = str(item.get("artifact_ref", "") or item.get("ref", "") or item.get("url", "") or "").strip()
                item_name = os.path.basename(str(item.get("filename", "") or item_ref).strip())
                item_port = str(item.get("port", "") or "").strip()
                item_protocol = str(item.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
                matches_ref = bool(resolved_artifact_ref and (item_ref == resolved_artifact_ref or os.path.basename(item_ref) == resolved_filename))
                matches_name = bool(resolved_filename and item_name == resolved_filename)
                matches_target = True
                if resolved_port:
                    matches_target = item_port == resolved_port
                if matches_target and resolved_protocol:
                    matches_target = item_protocol == resolved_protocol
                if (matches_ref or matches_name) and matches_target:
                    continue
                filtered_screenshots.append(dict(item))

            filtered_artifacts = []
            for item in list(target_state.get("artifacts", []) or []):
                if not isinstance(item, dict):
                    continue
                item_ref = str(item.get("ref", "") or item.get("artifact_ref", "") or "").strip()
                item_kind = str(item.get("kind", "") or "").strip().lower()
                item_name = os.path.basename(item_ref)
                matches_ref = bool(resolved_artifact_ref and (item_ref == resolved_artifact_ref or os.path.basename(item_ref) == resolved_filename))
                matches_name = bool(resolved_filename and item_name == resolved_filename)
                if item_kind == "screenshot" and (matches_ref or matches_name):
                    continue
                filtered_artifacts.append(dict(item))

            updated_state = dict(target_state)
            updated_state["screenshots"] = filtered_screenshots
            updated_state["artifacts"] = filtered_artifacts
            upsert_target_state(project.database, resolved_host_id, updated_state, merge=False)
            rebuild_evidence_graph(project.database, host_id=resolved_host_id)

            return {
                "deleted": True,
                "host_id": resolved_host_id,
                "artifact_ref": resolved_artifact_ref,
                "filename": resolved_filename,
                "deleted_files": int(deleted_files),
                "deleted_paths": deleted_paths,
            }

    @staticmethod
    def _host_target_item_matches_port(item: Any, port: str, protocol: str) -> bool:
        if not isinstance(item, dict):
            return False
        item_port = str(item.get("port", "") or "").strip()
        item_protocol = str(item.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
        return item_port == str(port or "").strip() and item_protocol == str(protocol or "tcp").strip().lower()

    def _delete_project_artifact_refs(self, project, *, screenshots: List[Dict[str, Any]], artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
        candidate_paths: List[str] = []
        for item in list(screenshots or []):
            if not isinstance(item, dict):
                continue
            item_ref = str(item.get("artifact_ref", "") or item.get("ref", "") or item.get("url", "") or "").strip()
            item_name = os.path.basename(str(item.get("filename", "") or item_ref).strip())
            if item_ref.startswith("/api/screenshots/"):
                api_name = os.path.basename(item_ref)
                if api_name:
                    candidate_paths.append(os.path.join(screenshot_dir, api_name))
            elif item_ref and self._is_project_artifact_path(project, item_ref):
                candidate_paths.append(item_ref)
            if item_name:
                candidate_paths.append(os.path.join(screenshot_dir, item_name))

        for item in list(artifacts or []):
            if not isinstance(item, dict):
                continue
            item_ref = str(item.get("ref", "") or item.get("artifact_ref", "") or "").strip()
            if item_ref.startswith("/api/screenshots/"):
                api_name = os.path.basename(item_ref)
                if api_name:
                    candidate_paths.append(os.path.join(screenshot_dir, api_name))
            elif item_ref and self._is_project_artifact_path(project, item_ref):
                candidate_paths.append(item_ref)

        deleted_paths: List[str] = []
        seen_paths = set()
        for path in candidate_paths:
            normalized = os.path.abspath(str(path or "").strip())
            if not normalized or normalized in seen_paths:
                continue
            seen_paths.add(normalized)
            if not os.path.isfile(normalized):
                continue
            if not self._is_project_artifact_path(project, normalized):
                continue
            try:
                os.remove(normalized)
                deleted_paths.append(normalized)
            except Exception:
                continue
        return {
            "deleted_files": len(deleted_paths),
            "deleted_paths": deleted_paths,
        }

    def _prune_target_state_for_port(self, *, project, host_id: int, host_ip: str, hostname: str, port: str, protocol: str) -> Dict[str, Any]:
        target_state = get_target_state(project.database, int(host_id or 0)) or {}
        filtered_service_inventory = [
            dict(item) for item in list(target_state.get("service_inventory", []) or [])
            if not self._host_target_item_matches_port(item, port, protocol)
        ]
        filtered_attempted_actions = [
            dict(item) for item in list(target_state.get("attempted_actions", []) or [])
            if not self._host_target_item_matches_port(item, port, protocol)
        ]
        filtered_screenshots: List[Dict[str, Any]] = []
        removed_screenshots: List[Dict[str, Any]] = []
        for item in list(target_state.get("screenshots", []) or []):
            if self._host_target_item_matches_port(item, port, protocol):
                removed_screenshots.append(dict(item))
                continue
            if isinstance(item, dict):
                filtered_screenshots.append(dict(item))
        filtered_artifacts: List[Dict[str, Any]] = []
        removed_artifacts: List[Dict[str, Any]] = []
        for item in list(target_state.get("artifacts", []) or []):
            if self._host_target_item_matches_port(item, port, protocol):
                removed_artifacts.append(dict(item))
                continue
            if isinstance(item, dict):
                filtered_artifacts.append(dict(item))
        preserved_urls = [
            dict(item) for item in list(target_state.get("urls", []) or [])
            if not self._host_target_item_matches_port(item, port, protocol)
        ]
        rebuilt_urls = build_target_urls(str(host_ip or ""), str(hostname or ""), filtered_service_inventory)

        updated_state = dict(target_state)
        updated_state["service_inventory"] = filtered_service_inventory
        updated_state["attempted_actions"] = filtered_attempted_actions
        updated_state["screenshots"] = filtered_screenshots
        updated_state["artifacts"] = filtered_artifacts
        updated_state["urls"] = preserved_urls + rebuilt_urls
        upsert_target_state(project.database, int(host_id or 0), updated_state, merge=False)
        return {
            "state": updated_state,
            "removed_screenshots": removed_screenshots,
            "removed_artifacts": removed_artifacts,
        }

    def delete_workspace_port(self, *, host_id: int, port: str, protocol: str = "tcp") -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        if resolved_host_id <= 0 or not resolved_port:
            raise ValueError("host_id and port are required.")

        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            repo_container = project.repositoryContainer
            port_repo = repo_container.portRepository
            service_repo = getattr(repo_container, "serviceRepository", None)
            port_obj = port_repo.getPortByHostIdAndPort(host.id, resolved_port, resolved_protocol)
            if port_obj is None:
                raise KeyError(f"Unknown port {resolved_port}/{resolved_protocol} for host {resolved_host_id}")

            host_ip = str(getattr(host, "ip", "") or "").strip()
            hostname = str(getattr(host, "hostname", "") or "").strip()
            service_id = str(getattr(port_obj, "serviceId", "") or "").strip()
            service_name = ""
            if service_id and service_repo is not None:
                try:
                    service_obj = service_repo.getServiceById(service_id)
                except Exception:
                    service_obj = None
                service_name = str(getattr(service_obj, "name", "") or "").strip()

            port_repo.deletePortByHostIdAndPort(host.id, resolved_port, resolved_protocol)

            session = project.database.session()
            try:
                if service_id:
                    session.execute(text(
                        "DELETE FROM serviceObj "
                        "WHERE CAST(id AS TEXT) = :service_id "
                        "AND CAST(id AS TEXT) NOT IN ("
                        "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj WHERE COALESCE(serviceId, '') <> ''"
                        ")"
                    ), {"service_id": service_id})
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

            prune = self._prune_target_state_for_port(
                project=project,
                host_id=resolved_host_id,
                host_ip=host_ip,
                hostname=hostname,
                port=resolved_port,
                protocol=resolved_protocol,
            )
            deleted_file_info = self._delete_project_artifact_refs(
                project,
                screenshots=list(prune.get("removed_screenshots", []) or []),
                artifacts=list(prune.get("removed_artifacts", []) or []),
            )
            rebuild_evidence_graph(project.database, host_id=resolved_host_id)
            return {
                "deleted": True,
                "kind": "port",
                "host_id": resolved_host_id,
                "host_ip": host_ip,
                "hostname": hostname,
                "port": resolved_port,
                "protocol": resolved_protocol,
                "service": service_name,
                **deleted_file_info,
            }

    def delete_workspace_service(
            self,
            *,
            host_id: int,
            port: str,
            protocol: str = "tcp",
            service: str = "",
    ) -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        requested_service = str(service or "").strip().rstrip("?").lower()
        if resolved_host_id <= 0 or not resolved_port:
            raise ValueError("host_id and port are required.")

        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            hostname = str(getattr(host, "hostname", "") or "").strip()

            session = project.database.session()
            try:
                row = session.execute(text(
                    "SELECT p.id, COALESCE(CAST(p.serviceId AS TEXT), ''), COALESCE(s.name, '') "
                    "FROM portObj AS p "
                    "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                    "WHERE p.hostId = :host_id "
                    "AND COALESCE(p.portId, '') = :port "
                    "AND LOWER(COALESCE(p.protocol, 'tcp')) = LOWER(:protocol) "
                    "ORDER BY p.id DESC LIMIT 1"
                ), {
                    "host_id": str(getattr(host, "id", resolved_host_id) or resolved_host_id),
                    "port": resolved_port,
                    "protocol": resolved_protocol,
                }).fetchone()
                if not row:
                    raise KeyError(f"Unknown port {resolved_port}/{resolved_protocol} for host {resolved_host_id}")

                port_row_id = int(row[0] or 0)
                service_id = str(row[1] or "").strip()
                current_service = str(row[2] or "").strip()
                if not service_id and not current_service:
                    raise KeyError(f"No service is associated with {resolved_port}/{resolved_protocol} for host {resolved_host_id}")
                current_service_normalized = current_service.rstrip("?").lower()
                if requested_service and current_service_normalized and requested_service != current_service_normalized:
                    raise ValueError(
                        f"Service mismatch for {resolved_port}/{resolved_protocol}: expected {requested_service}, found {current_service_normalized}"
                    )

                session.execute(text(
                    "UPDATE portObj SET serviceId = NULL WHERE id = :port_row_id"
                ), {"port_row_id": port_row_id})
                if service_id:
                    session.execute(text(
                        "DELETE FROM serviceObj "
                        "WHERE CAST(id AS TEXT) = :service_id "
                        "AND CAST(id AS TEXT) NOT IN ("
                        "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj WHERE COALESCE(serviceId, '') <> ''"
                        ")"
                    ), {"service_id": service_id})
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

            prune = self._prune_target_state_for_port(
                project=project,
                host_id=resolved_host_id,
                host_ip=host_ip,
                hostname=hostname,
                port=resolved_port,
                protocol=resolved_protocol,
            )
            deleted_file_info = self._delete_project_artifact_refs(
                project,
                screenshots=list(prune.get("removed_screenshots", []) or []),
                artifacts=list(prune.get("removed_artifacts", []) or []),
            )
            rebuild_evidence_graph(project.database, host_id=resolved_host_id)
            return {
                "deleted": True,
                "kind": "service",
                "host_id": resolved_host_id,
                "host_ip": host_ip,
                "hostname": hostname,
                "port": resolved_port,
                "protocol": resolved_protocol,
                "service": current_service,
                **deleted_file_info,
            }

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

    @staticmethod
    def _host_is_down(status: Any) -> bool:
        return str(status or "").strip().lower() == "down"

    @staticmethod
    def _workspace_host_services(port_rows: List[Any], service_repo: Any) -> List[str]:
        services = []
        for port in list(port_rows or []):
            if str(getattr(port, "state", "") or "") not in {"open", "open|filtered"}:
                continue
            service_name = ""
            service_id = getattr(port, "serviceId", None)
            if service_id and service_repo is not None:
                try:
                    service_obj = service_repo.getServiceById(service_id)
                except Exception:
                    service_obj = None
                service_name = str(getattr(service_obj, "name", "") or "")
            if not service_name:
                service_name = str(getattr(port, "serviceName", "") or "")
            service_name = service_name.strip()
            if service_name:
                services.append(service_name)
        return sorted({item for item in services if item})

    def _build_workspace_host_row(self, host: Any, port_repo: Any, service_repo: Any) -> Dict[str, Any]:
        ports = list(port_repo.getPortsByHostId(host.id) or [])
        open_ports = [p for p in ports if str(getattr(p, "state", "")) in {"open", "open|filtered"}]
        services = self._workspace_host_services(ports, service_repo)
        return {
            "id": int(host.id),
            "ip": str(getattr(host, "ip", "") or ""),
            "hostname": str(getattr(host, "hostname", "") or ""),
            "status": str(getattr(host, "status", "") or ""),
            "os": str(getattr(host, "osMatch", "") or ""),
            "open_ports": len(open_ports),
            "total_ports": len(ports),
            "services": services,
        }

    def get_workspace_hosts(self, limit: Optional[int] = None, include_down: bool = False, service: str = "") -> List[Dict[str, Any]]:
        with self._lock:
            project = self._require_active_project()
            repo_container = project.repositoryContainer
            host_repo = repo_container.hostRepository
            port_repo = repo_container.portRepository
            service_repo = getattr(repo_container, "serviceRepository", None)
            hosts = list(host_repo.getAllHostObjs())
            if not bool(include_down):
                hosts = [host for host in hosts if not self._host_is_down(getattr(host, "status", ""))]
            service_filter = str(service or "").strip().lower()
            rows = [self._build_workspace_host_row(host, port_repo, service_repo) for host in hosts]
            if service_filter:
                rows = [
                    row for row in rows
                    if any(str(item or "").strip().lower() == service_filter for item in list(row.get("services", []) or []))
                ]
            if limit is not None:
                try:
                    normalized_limit = int(limit)
                except (TypeError, ValueError):
                    normalized_limit = 0
                if normalized_limit > 0:
                    rows = rows[:normalized_limit]
            return rows

    def get_workspace_services(self, limit: int = 300, host_id: int = 0) -> List[Dict[str, Any]]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return []
            session = project.database.session()
            try:
                try:
                    normalized_host_id = int(host_id or 0)
                except (TypeError, ValueError):
                    normalized_host_id = 0
                result = session.execute(text(
                    "SELECT COALESCE(services.name, 'unknown') AS service, "
                    "COUNT(*) AS port_count, "
                    "COUNT(DISTINCT hosts.ip) AS host_count, "
                    "GROUP_CONCAT(DISTINCT ports.protocol) AS protocols "
                    "FROM portObj AS ports "
                    "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                    "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId "
                    "WHERE ports.state IN ('open', 'open|filtered') "
                    "AND (:host_id <= 0 OR hosts.id = :host_id) "
                    "GROUP BY COALESCE(services.name, 'unknown') "
                    "ORDER BY host_count DESC, port_count DESC, service ASC "
                    "LIMIT :limit"
                ), {"limit": max(1, min(int(limit), 2000)), "host_id": normalized_host_id})
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

            def _is_supported_tool(tool_id: str) -> bool:
                normalized_tool = str(tool_id or "").strip().lower()
                if not normalized_tool:
                    return False
                if normalized_tool in _SUPPORTED_WORKSPACE_TOOL_IDS:
                    return True
                return any(normalized_tool.startswith(prefix) for prefix in _SUPPORTED_WORKSPACE_TOOL_PREFIXES)

            for action in settings.portActions:
                label = str(action[0])
                tool_id = str(action[1])
                command_template = str(action[2])
                service_scope = self._split_csv(str(action[3] if len(action) > 3 else ""))

                if not _is_supported_tool(tool_id):
                    continue
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
                if not _is_supported_tool(tool_id):
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

    def get_workspace_tool_targets(
            self,
            *,
            host_id: int = 0,
            service: str = "",
            limit: int = 500,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return []
            session = project.database.session()
            try:
                try:
                    normalized_host_id = int(host_id or 0)
                except (TypeError, ValueError):
                    normalized_host_id = 0
                normalized_service = str(service or "").strip().rstrip("?").lower()
                resolved_limit = max(1, min(int(limit or 500), 5000))
                result = session.execute(text(
                    "SELECT hosts.id AS host_id, "
                    "COALESCE(hosts.ip, '') AS host_ip, "
                    "COALESCE(hosts.hostname, '') AS hostname, "
                    "COALESCE(ports.portId, '') AS port, "
                    "LOWER(COALESCE(ports.protocol, 'tcp')) AS protocol, "
                    "COALESCE(services.name, 'unknown') AS service, "
                    "COALESCE(services.product, '') AS service_product, "
                    "COALESCE(services.version, '') AS service_version "
                    "FROM portObj AS ports "
                    "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                    "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId "
                    "WHERE ports.state IN ('open', 'open|filtered') "
                    "AND (:host_id <= 0 OR hosts.id = :host_id) "
                    "AND (:service = '' OR LOWER(COALESCE(services.name, 'unknown')) = :service) "
                    "ORDER BY hosts.ip ASC, ports.protocol ASC, ports.portId ASC "
                    "LIMIT :limit"
                ), {
                    "host_id": normalized_host_id,
                    "service": normalized_service,
                    "limit": resolved_limit,
                })
                rows = []
                for row in result.mappings():
                    service_name = str(row.get("service", "") or "").strip()
                    port_value = str(row.get("port", "") or "").strip()
                    protocol = str(row.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
                    host_ip = str(row.get("host_ip", "") or "").strip()
                    hostname = str(row.get("hostname", "") or "").strip()
                    label_parts = [host_ip]
                    if hostname:
                        label_parts.append(hostname)
                    if service_name:
                        label_parts.append(service_name)
                    label_parts.append(f"{port_value}/{protocol}")
                    rows.append({
                        "host_id": int(row.get("host_id", 0) or 0),
                        "host_ip": host_ip,
                        "hostname": hostname,
                        "port": port_value,
                        "protocol": protocol,
                        "service": service_name,
                        "service_product": str(row.get("service_product", "") or ""),
                        "service_version": str(row.get("service_version", "") or ""),
                        "label": " | ".join(part for part in label_parts if part),
                    })
                rows.sort(key=lambda item: (
                    str(item.get("host_ip", "") or ""),
                    self._port_sort_key(item.get("port", "")),
                    str(item.get("protocol", "") or ""),
                    str(item.get("service", "") or ""),
                ))
                return rows
            finally:
                session.close()

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

    @staticmethod
    def _strip_nmap_preamble(output_text: str) -> str:
        text_value = str(output_text or "")
        if not text_value.strip():
            return ""
        filtered = []
        for raw_line in text_value.splitlines():
            line = str(raw_line or "")
            stripped = line.strip()
            lowered = stripped.lower()
            if not stripped:
                if filtered:
                    filtered.append("")
                continue
            if re.match(r"(?i)^Starting Nmap\b", stripped):
                continue
            if re.match(r"(?i)^Nmap scan report for\b", stripped):
                continue
            if re.match(r"(?i)^Host is up\b", stripped):
                continue
            if re.match(r"(?i)^Not shown:\b", stripped):
                continue
            if re.match(r"(?i)^All \d+ scanned ports\b", stripped):
                continue
            if re.match(r"(?i)^NSE:\s+(Loaded|Script Pre-scanning|Starting runlevel|Ending runlevel)\b", stripped):
                continue
            if re.match(r"(?i)^Service detection performed\b", stripped):
                continue
            if "nmap.org" in lowered and (
                    lowered.startswith("starting nmap")
                    or lowered.startswith("service detection performed")
                    or lowered.startswith("read data files from")
                    or lowered.startswith("please report")
            ):
                continue
            if re.match(r"(?i)^PORT\s+STATE\s+SERVICE\b", stripped):
                continue
            if re.match(r"(?i)^Nmap done:", stripped):
                continue
            filtered.append(line)
        cleaned = "\n".join(filtered).strip()
        return cleaned or text_value.strip()

    @classmethod
    def _host_detail_script_preview(cls, script_id: str, output_text: str, max_chars: int = 220) -> str:
        raw_output = str(output_text or "")
        display = raw_output
        lowered = " ".join([str(script_id or ""), raw_output[:400]]).lower()
        if "nmap" in lowered or "nse:" in lowered:
            display = cls._strip_nmap_preamble(raw_output)
        display = re.sub(r"\s+", " ", str(display or "")).strip()
        if len(display) > int(max_chars or 220):
            return display[:max(0, int(max_chars or 220) - 1)].rstrip() + "..."
        return display

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
                    script_id = str(getattr(script, "scriptId", "") or "")
                    output = str(getattr(script, "output", "") or "")
                    scripts.append({
                        "id": int(getattr(script, "id", 0) or 0),
                        "script_id": script_id,
                        "output": output,
                        "display_output": self._host_detail_script_preview(script_id, output),
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
            inferred_urls = self._infer_host_urls(
                project,
                host_id=int(host.id),
                host_ip=str(getattr(host, "ip", "") or ""),
            )
            self._persist_shared_target_state(
                host_id=int(host.id),
                host_ip=str(getattr(host, "ip", "") or ""),
                hostname=str(getattr(host, "hostname", "") or ""),
                hostname_confidence=95.0 if str(getattr(host, "hostname", "") or "").strip() else 0.0,
                os_match=str(getattr(host, "osMatch", "") or ""),
                os_confidence=70.0 if str(getattr(host, "osMatch", "") or "").strip() else 0.0,
                technologies=ai_analysis.get("technologies", []) if isinstance(ai_analysis.get("technologies", []), list) else [],
                findings=ai_analysis.get("findings", []) if isinstance(ai_analysis.get("findings", []), list) else [],
                manual_tests=ai_analysis.get("manual_tests", []) if isinstance(ai_analysis.get("manual_tests", []), list) else [],
                next_phase=str(ai_analysis.get("next_phase", "") or ""),
                provider=str(ai_analysis.get("provider", "") or ""),
                goal_profile=str(ai_analysis.get("goal_profile", "") or ""),
                service_inventory=[
                    {
                        "port": str(item.get("port", "") or ""),
                        "protocol": str(item.get("protocol", "") or ""),
                        "state": str(item.get("state", "") or ""),
                        "service": str((item.get("service", {}) or {}).get("name", "") or ""),
                        "service_product": str((item.get("service", {}) or {}).get("product", "") or ""),
                        "service_version": str((item.get("service", {}) or {}).get("version", "") or ""),
                        "service_extrainfo": str((item.get("service", {}) or {}).get("extrainfo", "") or ""),
                    }
                    for item in ports_data
                    if isinstance(item, dict)
                ],
                urls=inferred_urls,
                screenshots=screenshots,
            )
            target_state = get_target_state(project.database, int(host.id)) or {}

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
                "target_state": target_state,
            }

    def get_host_ai_report(self, host_id: int) -> Dict[str, Any]:
        details = self.get_host_workspace(int(host_id))
        host = details.get("host", {}) if isinstance(details.get("host", {}), dict) else {}
        ports = details.get("ports", []) if isinstance(details.get("ports", []), list) else []
        cves = details.get("cves", []) if isinstance(details.get("cves", []), list) else []
        screenshots = details.get("screenshots", []) if isinstance(details.get("screenshots", []), list) else []
        ai_analysis = details.get("ai_analysis", {}) if isinstance(details.get("ai_analysis", {}), dict) else {}
        target_state = details.get("target_state", {}) if isinstance(details.get("target_state", {}), dict) else {}

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
            "target_state": target_state,
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

    def get_host_report(self, host_id: int) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            engagement_policy = self._load_engagement_policy_locked(persist_if_missing=True)
            host_row = {
                "id": int(getattr(host, "id", 0) or 0),
                "ip": str(getattr(host, "ip", "") or ""),
                "hostname": str(getattr(host, "hostname", "") or ""),
                "status": str(getattr(host, "status", "") or ""),
                "os": str(getattr(host, "osMatch", "") or ""),
            }
            project_meta = dict(self._project_metadata())
        return build_host_report(
            project.database,
            host_row=host_row,
            engagement_policy=engagement_policy,
            project_metadata=project_meta,
        )

    def render_host_report_markdown(self, report: Dict[str, Any]) -> str:
        return render_scheduler_host_report_markdown(report)

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

    def get_project_report(self) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            project_meta = dict(self._project_metadata())
            summary = dict(self._summary())
            host_rows = list(self._hosts(limit=5000))
            engagement_policy = self._load_engagement_policy_locked(persist_if_missing=True)
        return build_project_report(
            project.database,
            project_metadata=project_meta,
            engagement_policy=engagement_policy,
            summary=summary,
            host_inventory=host_rows,
        )

    def render_project_report_markdown(self, report: Dict[str, Any]) -> str:
        return render_scheduler_project_report_markdown(report)

    def _push_project_report_common(
            self,
            *,
            report: Dict[str, Any],
            markdown_renderer,
            overrides: Optional[Dict[str, Any]] = None,
            report_label: str = "project report",
    ) -> Dict[str, Any]:
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

        report_format = str(delivery.get("format", "json") or "json").strip().lower()
        if report_format == "md":
            body = markdown_renderer(report)
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
            requests_module = _get_requests_module()
            response = requests_module.request(
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
                "report_label": str(report_label or "project report"),
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
                "report_label": str(report_label or "project report"),
                "error": str(exc),
            }

    def push_project_ai_report(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        report = self.get_project_ai_report()
        return self._push_project_report_common(
            report=report,
            markdown_renderer=self.render_project_ai_report_markdown,
            overrides=overrides,
            report_label="project ai report",
        )

    def push_project_report(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        report = self.get_project_report()
        return self._push_project_report_common(
            report=report,
            markdown_renderer=self.render_project_report_markdown,
            overrides=overrides,
            report_label="project report",
        )

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
            retry_plan = self._build_process_retry_plan(
                tool_name=tool_name,
                host_ip=host_ip,
                port=port,
                protocol=protocol,
            )
            if self._is_nmap_command(tool_name, command):
                command = AppSettings._ensure_nmap_stats_every(command)

        if retry_plan.get("mode") == "tool":
            tool_result = self._run_manual_tool(
                host_ip=str(retry_plan.get("host_ip", "") or ""),
                port=str(retry_plan.get("port", "") or ""),
                protocol=str(retry_plan.get("protocol", "tcp") or "tcp"),
                tool_id=str(retry_plan.get("tool_id", "") or ""),
                command_override="",
                timeout=int(timeout),
                job_id=int(job_id or 0),
            )
            executed = bool(tool_result.get("executed", False))
            reason = str(tool_result.get("reason", "") or "")
            new_process_id = int(tool_result.get("process_id", 0) or 0)
            command = str(tool_result.get("command", "") or "")
            retry_mode = "intent"
            retry_intent = "tool-run"
        elif retry_plan.get("mode") == "nmap_scan":
            scan_result = self._run_nmap_scan_and_import(
                targets=list(retry_plan.get("targets", []) or []),
                discovery=bool(retry_plan.get("discovery", True)),
                staged=bool(retry_plan.get("staged", False)),
                run_actions=bool(retry_plan.get("run_actions", False)),
                nmap_path=str(retry_plan.get("nmap_path", "nmap") or "nmap"),
                nmap_args=str(retry_plan.get("nmap_args", "") or ""),
                scan_mode=str(retry_plan.get("scan_mode", "legacy") or "legacy"),
                scan_options=dict(retry_plan.get("scan_options", {}) or {}),
                job_id=int(job_id or 0),
            )
            stages = list(scan_result.get("stages", []) or [])
            last_stage = stages[-1] if stages else {}
            executed = True
            reason = "completed"
            new_process_id = int(last_stage.get("process_id", 0) or 0)
            command = str(last_stage.get("command", "") or "")
            retry_mode = "intent"
            retry_intent = "nmap_scan"
        else:
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
            retry_mode = "command"
            retry_intent = "command-replay"
        return {
            "source_process_id": int(process_id),
            "process_id": int(new_process_id),
            "executed": bool(executed),
            "reason": str(reason),
            "command": command,
            "retry_mode": retry_mode,
            "retry_intent": retry_intent,
        }

    def _build_process_retry_plan(
            self,
            *,
            tool_name: str,
            host_ip: str,
            port: str,
            protocol: str,
    ) -> Dict[str, Any]:
        normalized_tool = str(tool_name or "").strip()
        normalized_host = str(host_ip or "").strip()
        normalized_port = str(port or "").strip()
        normalized_protocol = str(protocol or "tcp").strip().lower() or "tcp"

        settings = self._get_settings()
        if normalized_tool and normalized_host and normalized_port:
            action = self._find_port_action(settings, normalized_tool)
            if action is not None:
                return {
                    "mode": "tool",
                    "tool_id": normalized_tool,
                    "host_ip": normalized_host,
                    "port": normalized_port,
                    "protocol": normalized_protocol,
                }

        normalized_targets = self._split_process_retry_targets(normalized_host)
        tool_token = normalized_tool.lower()
        if normalized_targets and tool_token in {"nmap-easy", "nmap-hard", "nmap-rfc1918_discovery"}:
            scan_mode = tool_token.split("nmap-", 1)[1]
            return {
                "mode": "nmap_scan",
                "targets": normalized_targets,
                "discovery": scan_mode != "hard",
                "staged": False,
                "run_actions": False,
                "nmap_path": "nmap",
                "nmap_args": "",
                "scan_mode": scan_mode,
                "scan_options": {},
            }

        return {"mode": "command"}

    @staticmethod
    def _split_process_retry_targets(value: str) -> List[str]:
        raw = str(value or "").strip()
        if not raw:
            return []
        tokens = [
            item.strip()
            for item in re.split(r"[\s,]+", raw)
            if item.strip()
        ]
        deduped: List[str] = []
        for item in tokens:
            if item not in deduped:
                deduped.append(item)
        return deduped

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

        result = {
            "killed": True,
            "process_id": process_key,
            "had_live_handle": had_live_handle,
        }
        self._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
        return result

    def clear_processes(self, reset_all: bool = False) -> Dict[str, Any]:
        with self._lock:
            project = self._require_active_project()
            process_repo = project.repositoryContainer.processRepository
            process_repo.toggleProcessDisplayStatus(resetAll=bool(reset_all))
        result = {"cleared": True, "reset_all": bool(reset_all)}
        self._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
        return result

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
        result = {"closed": True, "process_id": int(process_id)}
        self._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
        return result

    def get_process_output(self, process_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
        offset_value = max(0, int(offset or 0))
        max_len = max(256, min(int(max_chars or 12000), 50000))
        with self._lock:
            self._ensure_process_tables()
            project = self._require_active_project()
            session = project.database.session()
            try:
                result = session.execute(text(
                    "SELECT p.id, p.name, p.hostIp, p.port, p.protocol, p.command, p.status, p.startTime, p.endTime, "
                    "COALESCE(p.percent, '') AS percent, "
                    "p.estimatedRemaining AS estimatedRemaining, "
                    "COALESCE(p.elapsed, 0) AS elapsed, "
                    "COALESCE(p.progressMessage, '') AS progressMessage, "
                    "COALESCE(p.progressSource, '') AS progressSource, "
                    "COALESCE(p.progressUpdatedAt, '') AS progressUpdatedAt, "
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
        data["progress"] = self._build_process_progress_payload(
            status=data.get("status", ""),
            percent=data.get("percent", ""),
            estimated_remaining=data.get("estimatedRemaining"),
            elapsed=data.get("elapsed", 0),
            progress_message=data.get("progressMessage", ""),
            progress_source=data.get("progressSource", ""),
            progress_updated_at=data.get("progressUpdatedAt", ""),
        )
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

    def _import_nmap_xml(self, xml_path: str, run_actions: bool = False, job_id: int = 0) -> Dict[str, Any]:
        resolved_job_id = int(job_id or 0)
        if resolved_job_id > 0:
            self._update_scan_submission_status(
                job_id=resolved_job_id,
                status="running",
                result_summary=f"importing {os.path.basename(str(xml_path or ''))}",
            )
        try:
            with self._lock:
                project = self._require_active_project()
                import_nmap_xml_into_project(
                    project=project,
                    xml_path=xml_path,
                    output="",
                    update_progress_observable=None,
                )

                try:
                    self.logic.copyNmapXMLToOutputFolder(xml_path)
                except Exception:
                    pass

                self._ensure_scheduler_table()
                self._ensure_scheduler_approval_store()

            scheduler_result = None
            if run_actions:
                scheduler_result = self._run_scheduler_actions_web()

            result = {
                "xml_path": xml_path,
                "run_actions": bool(run_actions),
                "scheduler_result": scheduler_result,
            }
            if resolved_job_id > 0:
                self._update_scan_submission_status(
                    job_id=resolved_job_id,
                    status="completed",
                    result_summary=f"imported {os.path.basename(str(xml_path or ''))}",
                )
            return result
        except Exception as exc:
            if resolved_job_id > 0:
                self._update_scan_submission_status(
                    job_id=resolved_job_id,
                    status="failed",
                    result_summary=str(exc),
                )
            raise

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
        resolved_job_id = int(job_id or 0)
        if resolved_job_id > 0:
            self._update_scan_submission_status(
                job_id=resolved_job_id,
                status="running",
                result_summary=f"running nmap against {self._compact_targets(targets)}",
            )
        with self._lock:
            project = self._require_active_project()
            running_folder = project.properties.runningFolder
            host_count_before = len(project.repositoryContainer.hostRepository.getAllHostObjs())
            output_prefix = os.path.join(
                running_folder,
                f"web-nmap-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",
            )

        try:
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
                if resolved_job_id > 0 and self.jobs.is_cancel_requested(resolved_job_id):
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
                    job_id=resolved_job_id,
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

            result = {
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
            if resolved_job_id > 0:
                warning_note = f" ({len(warnings)} warning{'s' if len(warnings) != 1 else ''})" if warnings else ""
                self._update_scan_submission_status(
                    job_id=resolved_job_id,
                    status="completed",
                    result_summary=f"imported {imported_hosts} host{'s' if imported_hosts != 1 else ''}{warning_note}",
                )
            self._emit_ui_invalidation("overview", "hosts", "services", "graph", "scan_history")
            return result
        except Exception as exc:
            if resolved_job_id > 0:
                self._update_scan_submission_status(
                    job_id=resolved_job_id,
                    status="failed",
                    result_summary=str(exc),
                )
            self._emit_ui_invalidation("scan_history")
            raise

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
        resolved_job_id = int(job_id or 0)
        normalized_host_ids = {
            int(item) for item in list(host_ids or set())
            if str(item).strip()
        }

        with self._lock:
            project = self._require_active_project()
            settings = self._get_settings()
            scheduler_prefs = self.scheduler_config.load()
            engagement_policy = self._load_engagement_policy_locked(persist_if_missing=True)
            options = self.scheduler_orchestrator.build_run_options(
                scheduler_prefs,
                dig_deeper=bool(dig_deeper),
                job_id=resolved_job_id,
            )
            targets = self.scheduler_orchestrator.collect_project_targets(
                project,
                host_ids=normalized_host_ids,
                allowed_states={"open", "open|filtered"},
            )
            goal_profile = str(
                engagement_policy.get("legacy_goal_profile", scheduler_prefs.get("goal_profile", "internal_asset_discovery"))
                or "internal_asset_discovery"
            )
        def _should_cancel(job_identifier: int) -> bool:
            return int(job_identifier or 0) > 0 and self.jobs.is_cancel_requested(int(job_identifier or 0))

        def _existing_attempts(*, target, **_kwargs):
            return self._existing_attempt_summary_for_target(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
            )

        def _build_context(
                *,
                target,
                attempted_tool_ids,
                attempted_family_ids=None,
                attempted_command_signatures=None,
                recent_output_chars,
                analysis_mode,
        ):
            return self._build_scheduler_target_context(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                goal_profile=goal_profile,
                attempted_tool_ids=set(attempted_tool_ids or set()),
                attempted_family_ids=set(attempted_family_ids or set()),
                attempted_command_signatures=set(attempted_command_signatures or set()),
                recent_output_chars=int(recent_output_chars or 900),
                analysis_mode=str(analysis_mode or "standard"),
            )

        def _on_ai_analysis(*, target, provider_payload):
            self._persist_scheduler_ai_analysis(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                goal_profile=goal_profile,
                provider_payload=provider_payload,
            )

        def _reflect_progress(*, target, context, recent_rounds, trigger=None):
            return reflect_on_scheduler_progress(
                scheduler_prefs,
                goal_profile,
                str(target.service_name or ""),
                str(target.protocol or "tcp"),
                context=context,
                recent_rounds=recent_rounds,
                trigger_reason=str((trigger or {}).get("reason", "") or ""),
                trigger_context=trigger if isinstance(trigger, dict) else {},
            )

        def _on_reflection_analysis(*, target, reflection_payload, recent_rounds):
            _ = recent_rounds
            self._persist_scheduler_reflection_analysis(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                goal_profile=goal_profile,
                reflection_payload=reflection_payload,
            )

        def _handle_blocked(*, target, decision, command_template):
            _ = command_template
            self._persist_shared_target_state(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                scheduler_mode=str(decision.mode),
                goal_profile=str(decision.goal_profile),
                engagement_preset=str(decision.engagement_preset),
                attempted_action=build_attempted_action_entry(
                    decision=decision,
                    status="blocked",
                    reason=str(decision.policy_reason or "blocked by policy"),
                    attempted_at=getTimestamp(True),
                    port=str(target.port or ""),
                    protocol=str(target.protocol or "tcp"),
                    service=str(target.service_name or ""),
                    family_id=str(decision.family_id or ""),
                    command_signature=self._command_signature_for_target(
                        str(command_template or decision.command_template or ""),
                        str(target.protocol or "tcp"),
                    ),
                ),
            )
            self._record_scheduler_decision(
                decision,
                str(target.host_ip or ""),
                str(target.port or ""),
                str(target.protocol or "tcp"),
                str(target.service_name or ""),
                approved=False,
                executed=False,
                reason=decision.policy_reason or "blocked by policy",
            )
            return SchedulerDecisionDisposition(
                action="skipped",
                reason=decision.policy_reason or "blocked by policy",
            )

        def _handle_approval(*, target, decision, command_template):
            approval_id = self._queue_scheduler_approval(
                decision,
                str(target.host_ip or ""),
                str(target.port or ""),
                str(target.protocol or "tcp"),
                str(target.service_name or ""),
                str(command_template or ""),
            )
            self._persist_shared_target_state(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                scheduler_mode=str(decision.mode),
                goal_profile=str(decision.goal_profile),
                engagement_preset=str(decision.engagement_preset),
                attempted_action=build_attempted_action_entry(
                    decision=decision,
                    status="approval_queued",
                    reason=f"pending approval #{approval_id}",
                    attempted_at=getTimestamp(True),
                    port=str(target.port or ""),
                    protocol=str(target.protocol or "tcp"),
                    service=str(target.service_name or ""),
                    family_id=str(decision.family_id or ""),
                    command_signature=self._command_signature_for_target(
                        str(command_template or decision.command_template or ""),
                        str(target.protocol or "tcp"),
                    ),
                ),
            )
            self._record_scheduler_decision(
                decision,
                str(target.host_ip or ""),
                str(target.port or ""),
                str(target.protocol or "tcp"),
                str(target.service_name or ""),
                approved=False,
                executed=False,
                reason=f"pending approval #{approval_id}",
                approval_id=int(approval_id),
            )
            return SchedulerDecisionDisposition(
                action="queued",
                reason=f"pending approval #{approval_id}",
                approval_id=int(approval_id),
            )

        def _execute_batch(tasks, max_concurrency):
            runner_settings = normalize_runner_settings(scheduler_prefs.get("runners", {}))
            payload = []
            for task in list(tasks or []):
                payload.append({
                    "decision": task.decision,
                    "tool_id": str(task.tool_id or ""),
                    "host_ip": str(task.host_ip or ""),
                    "port": str(task.port or ""),
                    "protocol": str(task.protocol or "tcp"),
                    "service_name": str(task.service_name or ""),
                    "command_template": str(task.command_template or ""),
                    "timeout": int(task.timeout or 300),
                    "job_id": int(task.job_id or 0),
                    "approval_id": int(task.approval_id or 0),
                    "runner_preference": str(task.runner_preference or ""),
                    "runner_settings": runner_settings,
                })
            return self._execute_scheduler_task_batch(payload, max_concurrency=max_concurrency)

        def _on_execution_result(*, target, decision, result):
            executed = bool(result.get("executed", False))
            reason = str(result.get("reason", "") or "")
            process_id = int(result.get("process_id", 0) or 0)
            execution_record = result.get("execution_record")
            artifact_refs = list(getattr(execution_record, "artifact_refs", []) or [])
            observed_payload = {}
            observed_raw = {}
            output_text = ""
            if process_id > 0:
                try:
                    process_output = self.get_process_output(int(process_id), offset=0, max_chars=200000)
                    output_text = str(process_output.get("output", "") or "")
                except Exception:
                    output_text = ""
            if output_text or artifact_refs:
                observed_payload = extract_tool_observations(
                    str(decision.tool_id or ""),
                    output_text,
                    port=str(target.port or ""),
                    protocol=str(target.protocol or "tcp"),
                    service=str(target.service_name or ""),
                    artifact_refs=artifact_refs,
                    host_ip=str(target.host_ip or ""),
                    hostname=str(getattr(target, "hostname", "") or ""),
                )
                quality_events = list(observed_payload.get("finding_quality_events", []) or [])
                if quality_events:
                    observed_raw["finding_quality_events"] = quality_events
            self._persist_shared_target_state(
                host_id=int(target.host_id or 0),
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
                scheduler_mode=str(decision.mode),
                goal_profile=str(decision.goal_profile),
                engagement_preset=str(decision.engagement_preset),
                attempted_action=build_attempted_action_entry(
                    decision=decision,
                    status="executed" if executed else "failed",
                    reason=reason,
                    attempted_at=getTimestamp(True),
                    port=str(target.port or ""),
                    protocol=str(target.protocol or "tcp"),
                    service=str(target.service_name or ""),
                    family_id=str(decision.family_id or ""),
                    command_signature=self._command_signature_for_target(
                        str(getattr(decision, "command_template", "") or ""),
                        str(target.protocol or "tcp"),
                    ),
                    artifact_refs=artifact_refs,
                ),
                artifact_refs=artifact_refs,
                screenshots=list(result.get("screenshots", [])) if isinstance(result.get("screenshots", []), list) else None,
                technologies=list(observed_payload.get("technologies", []) or []) or None,
                findings=list(observed_payload.get("findings", []) or []) or None,
                urls=list(observed_payload.get("urls", []) or []) or None,
                raw=observed_raw or None,
            )
            self._record_scheduler_decision(
                decision,
                str(target.host_ip or ""),
                str(target.port or ""),
                str(target.protocol or "tcp"),
                str(target.service_name or ""),
                approved=True,
                executed=executed,
                reason=reason,
                approval_id=int(result.get("approval_id", 0) or 0),
            )
            self._persist_scheduler_execution_record(
                decision,
                execution_record,
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service_name=str(target.service_name or ""),
            )
            if process_id and executed:
                self._save_script_result_if_missing(
                    host_ip=str(target.host_ip or ""),
                    port=str(target.port or ""),
                    protocol=str(target.protocol or "tcp"),
                    tool_id=decision.tool_id,
                    process_id=process_id,
                )
            if executed:
                self._enrich_host_from_observed_results(
                    host_ip=str(target.host_ip or ""),
                    port=str(target.port or ""),
                    protocol=str(target.protocol or "tcp"),
                )

        return self._run_scheduler_targets(
            settings=settings,
            targets=targets,
            engagement_policy=engagement_policy,
            options=options,
            should_cancel=_should_cancel,
            existing_attempts=_existing_attempts,
            build_context=_build_context,
            on_ai_analysis=_on_ai_analysis,
            reflect_progress=_reflect_progress,
            on_reflection_analysis=_on_reflection_analysis,
            handle_blocked=_handle_blocked,
            handle_approval=_handle_approval,
            execute_batch=_execute_batch,
            on_execution_result=_on_execution_result,
        )

    def _run_scheduler_targets(
            self,
            *,
            settings,
            targets,
            engagement_policy,
            options,
            should_cancel,
            existing_attempts,
            build_context,
            on_ai_analysis,
            reflect_progress,
            on_reflection_analysis,
            handle_blocked,
            handle_approval,
            execute_batch,
            on_execution_result,
    ) -> Dict[str, Any]:
        target_list = list(targets or [])
        host_concurrency = max(1, min(int(getattr(options, "host_concurrency", 1) or 1), 8))
        if bool(getattr(options, "dig_deeper", False)) or host_concurrency <= 1 or len(target_list) <= 1:
            return self.scheduler_orchestrator.run_targets(
                settings=settings,
                targets=target_list,
                engagement_policy=engagement_policy,
                options=options,
                should_cancel=should_cancel,
                existing_attempts=existing_attempts,
                build_context=build_context,
                on_ai_analysis=on_ai_analysis,
                reflect_progress=reflect_progress,
                on_reflection_analysis=on_reflection_analysis,
                handle_blocked=handle_blocked,
                handle_approval=handle_approval,
                execute_batch=execute_batch,
                on_execution_result=on_execution_result,
            )

        target_groups = self._group_scheduler_targets_by_host(target_list)
        if len(target_groups) <= 1:
            return self.scheduler_orchestrator.run_targets(
                settings=settings,
                targets=target_list,
                engagement_policy=engagement_policy,
                options=options,
                should_cancel=should_cancel,
                existing_attempts=existing_attempts,
                build_context=build_context,
                on_ai_analysis=on_ai_analysis,
                reflect_progress=reflect_progress,
                on_reflection_analysis=on_reflection_analysis,
                handle_blocked=handle_blocked,
                handle_approval=handle_approval,
                execute_batch=execute_batch,
                on_execution_result=on_execution_result,
            )

        summaries: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(
                max_workers=min(host_concurrency, len(target_groups)),
                thread_name_prefix="legion-scheduler-hosts",
        ) as pool:
            future_map = {
                pool.submit(
                    self.scheduler_orchestrator.run_targets,
                    settings=settings,
                    targets=group,
                    engagement_policy=engagement_policy,
                    options=options,
                    should_cancel=should_cancel,
                    existing_attempts=existing_attempts,
                    build_context=build_context,
                    on_ai_analysis=on_ai_analysis,
                    reflect_progress=reflect_progress,
                    on_reflection_analysis=on_reflection_analysis,
                    handle_blocked=handle_blocked,
                    handle_approval=handle_approval,
                    execute_batch=execute_batch,
                    on_execution_result=on_execution_result,
                ): group
                for group in target_groups
            }
            for future in as_completed(future_map):
                summaries.append(future.result())

        return self._merge_scheduler_run_summaries(
            summaries,
            target_count=len(target_list),
            dig_deeper=bool(getattr(options, "dig_deeper", False)),
        )

    @staticmethod
    def _group_scheduler_targets_by_host(targets) -> List[List[Any]]:
        grouped: List[List[Any]] = []
        index: Dict[Tuple[str, Any], int] = {}
        for target in list(targets or []):
            host_id = int(getattr(target, "host_id", 0) or 0)
            host_ip = str(getattr(target, "host_ip", "") or "").strip()
            hostname = str(getattr(target, "hostname", "") or "").strip()
            if host_id > 0:
                key: Tuple[str, Any] = ("host_id", host_id)
            elif host_ip:
                key = ("host_ip", host_ip)
            elif hostname:
                key = ("hostname", hostname)
            else:
                key = ("target", len(grouped))
            position = index.get(key)
            if position is None:
                position = len(grouped)
                index[key] = position
                grouped.append([])
            grouped[position].append(target)
        return grouped

    @staticmethod
    def _merge_scheduler_run_summaries(
            summaries: Optional[List[Dict[str, Any]]] = None,
            *,
            target_count: int = 0,
            dig_deeper: bool = False,
    ) -> Dict[str, Any]:
        merged = {
            "considered": 0,
            "approval_queued": 0,
            "executed": 0,
            "skipped": 0,
            "host_scope_count": int(target_count or 0),
            "dig_deeper": bool(dig_deeper),
            "reflections": 0,
            "reflection_stops": 0,
        }
        for item in list(summaries or []):
            if not isinstance(item, dict):
                continue
            for key in ("considered", "approval_queued", "executed", "skipped", "reflections", "reflection_stops"):
                try:
                    merged[key] += int(item.get(key, 0) or 0)
                except (TypeError, ValueError):
                    continue
            if bool(item.get("cancelled", False)):
                merged["cancelled"] = True
                if not str(merged.get("cancel_reason", "") or "").strip():
                    merged["cancel_reason"] = str(item.get("cancel_reason", "") or "cancelled by user")
            if not str(merged.get("stopped_early", "") or "").strip():
                stopped_early = str(item.get("stopped_early", "") or "").strip()
                if stopped_early:
                    merged["stopped_early"] = stopped_early
        return merged

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
    def _scheduler_max_host_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
        source = preferences if isinstance(preferences, dict) else {}
        try:
            value = int(source.get("max_host_concurrency", 1))
        except (TypeError, ValueError):
            value = 1
        return max(1, min(value, 8))

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
                        "execution_record": None,
                    })
        return results

    def _execute_scheduler_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        decision = task["decision"]
        approval_id = int(task.get("approval_id", 0) or 0)
        execution_result = self._execute_scheduler_decision(
            decision,
            host_ip=str(task.get("host_ip", "") or ""),
            port=str(task.get("port", "") or ""),
            protocol=str(task.get("protocol", "tcp") or "tcp"),
            service_name=str(task.get("service_name", "") or ""),
            command_template=str(task.get("command_template", "") or ""),
            timeout=int(task.get("timeout", 300) or 300),
            job_id=int(task.get("job_id", 0) or 0),
            capture_metadata=True,
            approval_id=approval_id,
            runner_preference=str(task.get("runner_preference", "") or ""),
            runner_settings=task.get("runner_settings", {}),
        )
        return {
            "decision": decision,
            "tool_id": str(task.get("tool_id", "") or ""),
            "executed": bool(execution_result.get("executed", False)),
            "reason": str(execution_result.get("reason", "") or ""),
            "process_id": int(execution_result.get("process_id", 0) or 0),
            "execution_record": execution_result.get("execution_record"),
            "approval_id": approval_id,
        }

    @staticmethod
    def _scheduler_feedback_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged = dict(_DEFAULT_AI_FEEDBACK_CONFIG)
        source = preferences.get("ai_feedback", {}) if isinstance(preferences, dict) else {}
        if not isinstance(source, dict):
            source = {}

        if "enabled" in source:
            merged["enabled"] = bool(source.get("enabled"))

        for key in (
                "max_rounds_per_target",
                "max_actions_per_round",
                "recent_output_chars",
                "stall_rounds_without_progress",
                "stall_repeat_selection_threshold",
                "max_reflections_per_target",
        ):
            try:
                merged[key] = int(source.get(key, merged[key]))
            except (TypeError, ValueError):
                continue

        merged["reflection_enabled"] = bool(source.get("reflection_enabled", merged.get("reflection_enabled", True)))
        merged["max_rounds_per_target"] = max(1, min(int(merged["max_rounds_per_target"]), 12))
        merged["max_actions_per_round"] = max(1, min(int(merged["max_actions_per_round"]), 8))
        merged["recent_output_chars"] = max(320, min(int(merged["recent_output_chars"]), 4000))
        merged["stall_rounds_without_progress"] = max(1, min(int(merged["stall_rounds_without_progress"]), 6))
        merged["stall_repeat_selection_threshold"] = max(1, min(int(merged["stall_repeat_selection_threshold"]), 8))
        merged["max_reflections_per_target"] = max(0, min(int(merged["max_reflections_per_target"]), 4))
        return merged

    def _existing_attempt_summary_for_target(self, host_id: int, host_ip: str, port: str, protocol: str) -> Dict[str, set]:
        attempted = {
            "tool_ids": set(),
            "family_ids": set(),
            "command_signatures": set(),
        }
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return attempted

            self._ensure_scheduler_approval_store()
            self._ensure_scheduler_table()
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
                        attempted["tool_ids"].add(tool)

                target_state = get_target_state(project.database, int(host_id or 0)) or {}
                for item in list(target_state.get("attempted_actions", []) or []):
                    if not isinstance(item, dict) or not self._target_attempt_matches(item, port, protocol):
                        continue
                    tool = str(item.get("tool_id", "") or "").strip().lower()
                    family_id = str(item.get("family_id", "") or "").strip().lower()
                    command_signature = str(item.get("command_signature", "") or "").strip().lower()
                    if tool:
                        attempted["tool_ids"].add(tool)
                    if family_id:
                        attempted["family_ids"].add(family_id)
                    if command_signature:
                        attempted["command_signatures"].add(command_signature)

                process_result = session.execute(text(
                    "SELECT COALESCE(p.name, '') AS tool_id, "
                    "COALESCE(p.command, '') AS command_text "
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
                    command_text = str(row[1] or "")
                    if tool:
                        attempted["tool_ids"].add(tool)
                    command_signature = self._command_signature_for_target(command_text, protocol)
                    if command_signature:
                        attempted["command_signatures"].add(str(command_signature).strip().lower())

                approval_result = session.execute(text(
                    "SELECT COALESCE(tool_id, '') AS tool_id, "
                    "COALESCE(command_template, '') AS command_template, "
                    "COALESCE(command_family_id, '') AS command_family_id "
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
                    command_template = str(row[1] or "")
                    family_id = str(row[2] or "").strip().lower()
                    if tool:
                        attempted["tool_ids"].add(tool)
                    if family_id:
                        attempted["family_ids"].add(family_id)
                    command_signature = self._command_signature_for_target(command_template, protocol)
                    if command_signature:
                        attempted["command_signatures"].add(str(command_signature).strip().lower())
            finally:
                session.close()
        return attempted

    def _existing_tool_attempts_for_target(self, host_id: int, host_ip: str, port: str, protocol: str) -> set:
        summary = self._existing_attempt_summary_for_target(host_id, host_ip, port, protocol)
        return set(summary.get("tool_ids", set()) or set())

    def _build_scheduler_target_context(
            self,
            *,
            host_id: int,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            goal_profile: str = "internal_asset_discovery",
            attempted_tool_ids: set,
            attempted_family_ids: Optional[set] = None,
            attempted_command_signatures: Optional[set] = None,
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
        analysis_output_chars = max(int(recent_output_chars) * 4, 1600)
        for row in script_rows:
            script_id = str(row[0] or "").strip()
            output = self._build_scheduler_prompt_excerpt(row[1], int(recent_output_chars))
            analysis_output = self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars))
            script_port = str(row[2] or "").strip()
            script_protocol = str(row[3] or "tcp").strip().lower() or "tcp"
            if not script_id and not output and not analysis_output:
                continue
            item = {
                "script_id": script_id,
                "port": script_port,
                "protocol": script_protocol,
                "excerpt": output,
                "analysis_excerpt": analysis_output,
            }
            scripts.append(item)
            if not script_port or (script_port == target_port_value and script_protocol == target_protocol_value):
                target_scripts.append(item)

            if script_port:
                key = (script_port, script_protocol)
                if script_id:
                    port_scripts.setdefault(key, []).append(script_id)
                if key not in port_banners:
                    candidate_banner = self._scheduler_banner_from_evidence(script_id, analysis_output or output)
                    if candidate_banner:
                        port_banners[key] = candidate_banner

        recent_processes = []
        target_recent_processes = []
        for row in process_rows:
            tool_id = str(row[0] or "").strip()
            status = str(row[1] or "").strip()
            command_text = self._truncate_scheduler_text(row[2], 220)
            output_text = self._build_scheduler_prompt_excerpt(row[3], int(recent_output_chars))
            analysis_output = self._build_scheduler_analysis_excerpt(row[3], int(analysis_output_chars))
            process_port = str(row[4] or "").strip()
            process_protocol = str(row[5] or "tcp").strip().lower() or "tcp"
            if not tool_id and not output_text and not analysis_output:
                continue
            item = {
                "tool_id": tool_id,
                "status": status,
                "port": process_port,
                "protocol": process_protocol,
                "command_excerpt": command_text,
                "output_excerpt": output_text,
                "analysis_excerpt": analysis_output,
            }
            recent_processes.append(item)
            if process_port == target_port_value and process_protocol == target_protocol_value:
                target_recent_processes.append(item)

            if process_port:
                key = (process_port, process_protocol)
                if key not in port_banners:
                    candidate_banner = self._scheduler_banner_from_evidence(tool_id, analysis_output or output_text)
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
        tool_audit = self._scheduler_tool_audit_snapshot()

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
            reflection = ai_state.get("reflection", {}) if isinstance(ai_state.get("reflection", {}), dict) else {}
            if reflection:
                ai_context_state["reflection"] = {
                    "state": str(reflection.get("state", "") or "")[:24],
                    "priority_shift": str(reflection.get("priority_shift", "") or "")[:64],
                    "reason": self._truncate_scheduler_text(reflection.get("reason", ""), 220),
                    "promote_tool_ids": [
                        str(item or "").strip().lower()[:80]
                        for item in list(reflection.get("promote_tool_ids", []) or [])[:8]
                        if str(item or "").strip()
                    ],
                    "suppress_tool_ids": [
                        str(item or "").strip().lower()[:80]
                        for item in list(reflection.get("suppress_tool_ids", []) or [])[:8]
                        if str(item or "").strip()
                    ],
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
        current_phase = determine_scheduler_phase(
            goal_profile=str(goal_profile or "internal_asset_discovery"),
            service=str(target_data.get("service", "") or service_name or ""),
            context={
                "analysis_mode": str(analysis_mode or "standard"),
                "signals": signals,
                "coverage": coverage,
                "attempted_tool_ids": sorted(
                    {str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}
                ),
            },
        )
        context_summary = self._build_scheduler_context_summary(
            target=target_data,
            analysis_mode=str(analysis_mode or "standard"),
            coverage=coverage,
            signals=signals,
            current_phase=current_phase,
            attempted_tool_ids=attempted_tool_ids,
            attempted_family_ids=attempted_family_ids,
            summary_technologies=(
                ai_context_state.get("technologies", [])
                if isinstance(ai_context_state.get("technologies", []), list) and ai_context_state.get("technologies", [])
                else inferred_technologies
            ),
            host_cves=host_cves,
            host_ai_state=ai_context_state,
            recent_processes=recent_processes,
            target_recent_processes=target_recent_processes,
        )
        self._persist_shared_target_state(
            host_id=int(host_id or 0),
            host_ip=str(host_ip or ""),
            port=str(port or ""),
            protocol=str(protocol or "tcp"),
            service_name=str(target_data.get("service", "") or service_name or ""),
            hostname=str(target_data.get("hostname", "") or ""),
            hostname_confidence=95.0 if str(target_data.get("hostname", "") or "").strip() else 0.0,
            os_match=str(target_data.get("os", "") or ""),
            os_confidence=70.0 if str(target_data.get("os", "") or "").strip() else 0.0,
            technologies=inferred_technologies[:64],
            service_inventory=host_port_inventory,
            coverage=coverage,
        )

        return {
            "target": target_data,
            "signals": signals,
            "tool_audit": tool_audit,
            "attempted_tool_ids": sorted({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}),
            "attempted_family_ids": sorted({str(item).strip().lower() for item in list(attempted_family_ids or set()) if str(item).strip()}),
            "attempted_command_signatures": sorted({str(item).strip().lower() for item in list(attempted_command_signatures or set()) if str(item).strip()}),
            "host_ports": host_port_inventory,
            "scripts": scripts,
            "recent_processes": recent_processes,
            "target_scripts": target_scripts,
            "target_recent_processes": target_recent_processes,
            "inferred_technologies": inferred_technologies[:64],
            "host_cves": host_cves,
            "coverage": coverage,
            "analysis_mode": str(analysis_mode or "standard").strip().lower() or "standard",
            "context_summary": context_summary,
            "host_ai_state": ai_context_state,
        }

    @staticmethod
    def _build_scheduler_context_summary(
            *,
            target: Optional[Dict[str, Any]],
            analysis_mode: str,
            coverage: Optional[Dict[str, Any]],
            signals: Optional[Dict[str, Any]],
            current_phase: str = "",
            attempted_tool_ids: Any,
            attempted_family_ids: Any = None,
            summary_technologies: Optional[List[Dict[str, Any]]] = None,
            host_cves: Optional[List[Dict[str, Any]]] = None,
            host_ai_state: Optional[Dict[str, Any]] = None,
            recent_processes: Optional[List[Dict[str, Any]]] = None,
            target_recent_processes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        target_payload = target if isinstance(target, dict) else {}
        coverage_payload = coverage if isinstance(coverage, dict) else {}
        signals_payload = signals if isinstance(signals, dict) else {}
        ai_payload = host_ai_state if isinstance(host_ai_state, dict) else {}
        technology_rows = summary_technologies if isinstance(summary_technologies, list) else []
        host_cve_rows = host_cves if isinstance(host_cves, list) else []
        all_recent_processes = recent_processes if isinstance(recent_processes, list) else []
        scoped_recent_processes = target_recent_processes if isinstance(target_recent_processes, list) else []

        def _unique_strings(values: Any, *, limit: int, max_chars: int, lowercase: bool = False) -> List[str]:
            rows: List[str] = []
            seen = set()
            for item in list(values or []):
                token = WebRuntime._truncate_scheduler_text(item, max_chars)
                if lowercase:
                    token = token.lower()
                if not token:
                    continue
                key = token.lower()
                if key in seen:
                    continue
                seen.add(key)
                rows.append(token)
                if len(rows) >= int(limit):
                    break
            return rows

        focus = {}
        analysis_mode_value = str(analysis_mode or coverage_payload.get("analysis_mode", "") or "").strip().lower()
        if analysis_mode_value:
            focus["analysis_mode"] = analysis_mode_value[:24]
        service_value = str(target_payload.get("service", "") or "").strip()
        if service_value:
            focus["service"] = service_value[:64]
        service_product = str(target_payload.get("service_product", "") or "").strip()
        if service_product:
            focus["service_product"] = service_product[:120]
        service_version = str(target_payload.get("service_version", "") or "").strip()
        if service_version:
            focus["service_version"] = service_version[:80]
        coverage_stage = str(coverage_payload.get("stage", "") or "").strip().lower()
        if coverage_stage:
            focus["coverage_stage"] = coverage_stage[:32]
        current_phase_value = str(current_phase or ai_payload.get("next_phase", "") or "").strip().lower()
        if current_phase_value:
            focus["current_phase"] = current_phase_value[:64]

        confirmed_facts = []
        hostname_value = str(target_payload.get("hostname", "") or "").strip()
        if hostname_value:
            confirmed_facts.append(f"hostname: {hostname_value}")
        os_value = str(target_payload.get("os", "") or "").strip()
        if os_value:
            confirmed_facts.append(f"os: {os_value}")
        service_fact = str(target_payload.get("service", "") or "").strip()
        port_value = str(target_payload.get("port", "") or "").strip()
        protocol_value = str(target_payload.get("protocol", "") or "").strip().lower()
        service_stack = " ".join(
            part for part in [
                str(target_payload.get("service_product", "") or "").strip(),
                str(target_payload.get("service_version", "") or "").strip(),
            ]
            if part
        ).strip()
        service_location = ""
        if port_value and protocol_value:
            service_location = f"{port_value}/{protocol_value}"
        elif port_value:
            service_location = port_value
        if service_fact:
            detail_bits = []
            if service_location:
                detail_bits.append(f"on {service_location}")
            if service_stack:
                detail_bits.append(f"({service_stack})")
            confirmed_facts.append(
                " ".join(part for part in [f"service: {service_fact}", " ".join(detail_bits).strip()] if part).strip()
            )
        elif service_stack:
            confirmed_facts.append(f"service stack: {service_stack}")
        confirmed_facts = _unique_strings(confirmed_facts, limit=6, max_chars=140)

        coverage_missing = _unique_strings(
            coverage_payload.get("missing", []),
            limit=8,
            max_chars=64,
            lowercase=True,
        )
        recommended_tools = _unique_strings(
            coverage_payload.get("recommended_tool_ids", []),
            limit=8,
            max_chars=80,
            lowercase=True,
        )

        active_signals = []
        for key, value in sorted(signals_payload.items(), key=lambda item: str(item[0] or "").lower()):
            if isinstance(value, bool) and value:
                active_signals.append(str(key or "").strip().lower()[:48])
            if len(active_signals) >= 10:
                break

        technology_labels = []
        for item in technology_rows[:16]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "").strip()
            version = str(item.get("version", "") or "").strip()
            cpe = str(item.get("cpe", "") or "").strip()
            label = " ".join(part for part in [name, version] if part).strip() or cpe
            label = WebRuntime._truncate_scheduler_text(label, 96)
            if label:
                technology_labels.append(label)
        known_technologies = _unique_strings(technology_labels, limit=8, max_chars=96)
        likely_technologies = list(known_technologies)

        finding_labels = []
        ai_findings = ai_payload.get("findings", []) if isinstance(ai_payload.get("findings", []), list) else []
        sorted_findings = sorted(
            [item for item in ai_findings if isinstance(item, dict)],
            key=lambda row: WebRuntime._finding_sort_key(row),
            reverse=True,
        )
        for item in sorted_findings[:10]:
            title = str(item.get("title", "") or item.get("cve", "") or "").strip()
            severity = str(item.get("severity", "") or "").strip().lower()
            label = title
            if severity:
                label = f"{label} [{severity}]".strip()
            label = WebRuntime._truncate_scheduler_text(label, 120)
            if label:
                finding_labels.append(label)
        for item in host_cve_rows[:8]:
            if not isinstance(item, dict):
                continue
            cve_name = str(item.get("name", "") or "").strip()
            severity = str(item.get("severity", "") or "").strip().lower()
            label = cve_name or str(item.get("product", "") or "").strip()
            if severity and label:
                label = f"{label} [{severity}]"
            label = WebRuntime._truncate_scheduler_text(label, 120)
            if label:
                finding_labels.append(label)
        top_findings = _unique_strings(finding_labels, limit=8, max_chars=120)
        important_findings = list(top_findings)

        attempted_values = sorted({
            str(item or "").strip().lower()
            for item in list(attempted_tool_ids or set())
            if str(item or "").strip()
        })
        recent_attempts = _unique_strings(attempted_values, limit=10, max_chars=80, lowercase=True)
        attempted_families = _unique_strings(
            sorted({
                str(item or "").strip().lower()
                for item in list(attempted_family_ids or set())
                if str(item or "").strip()
            }),
            limit=8,
            max_chars=80,
            lowercase=True,
        )

        def _failure_labels(process_rows: List[Dict[str, Any]]) -> List[str]:
            rows = []
            for item in process_rows[:32]:
                if not isinstance(item, dict):
                    continue
                tool_id = str(item.get("tool_id", "") or "").strip().lower()
                status = str(item.get("status", "") or "").strip().lower()
                output_excerpt = str(item.get("output_excerpt", "") or "").strip().lower()
                failure_reason = ""
                if any(token in status for token in ["crash", "fail", "error", "timeout", "cancel", "kill", "missing"]):
                    failure_reason = status
                missing_scripts = WebRuntime._extract_missing_nse_script_tokens(output_excerpt)
                if not failure_reason and missing_scripts and (
                        (tool_id.endswith(".nse") and tool_id in missing_scripts)
                        or not tool_id
                ):
                    failure_reason = "missing script"
                elif not failure_reason:
                    unavailable_tokens = WebRuntime._extract_unavailable_tool_tokens(output_excerpt)
                    if unavailable_tokens and (
                            not tool_id
                            or bool(unavailable_tokens & WebRuntime._scheduler_tool_alias_tokens(tool_id))
                    ):
                        failure_reason = "command not found"
                if not failure_reason and WebRuntime._looks_like_local_tool_dependency_failure(output_excerpt):
                    failure_reason = "dependency failure"
                if not failure_reason and "no such file" in output_excerpt:
                    failure_reason = "missing file"
                elif not failure_reason and ("traceback" in output_excerpt or "exception" in output_excerpt):
                    failure_reason = "exception"
                if not failure_reason:
                    continue
                label = ": ".join(part for part in [tool_id[:80], failure_reason[:80]] if part)
                if label:
                    rows.append(label)
            return rows

        recent_failures = _unique_strings(
            _failure_labels(scoped_recent_processes) + _failure_labels(all_recent_processes),
            limit=6,
            max_chars=120,
            lowercase=True,
        )

        manual_tests = []
        for item in list(ai_payload.get("manual_tests", []) or [])[:6]:
            if not isinstance(item, dict):
                continue
            command = WebRuntime._truncate_scheduler_text(item.get("command", ""), 140)
            if command:
                manual_tests.append(command)
        manual_tests = _unique_strings(manual_tests, limit=4, max_chars=140)

        reflection_posture = {}
        reflection = ai_payload.get("reflection", {}) if isinstance(ai_payload.get("reflection", {}), dict) else {}
        if reflection:
            reflection_state = str(reflection.get("state", "") or "").strip().lower()
            if reflection_state:
                reflection_posture["state"] = reflection_state[:24]
            priority_shift = str(reflection.get("priority_shift", "") or "").strip().lower()
            if priority_shift:
                reflection_posture["priority_shift"] = priority_shift[:64]
            trigger_reason = str(reflection.get("trigger_reason", "") or "").strip().lower()
            if trigger_reason:
                reflection_posture["trigger_reason"] = trigger_reason[:64]
            reason = WebRuntime._truncate_scheduler_text(reflection.get("reason", ""), 180)
            if reason:
                reflection_posture["reason"] = reason
            suppress_tool_ids = _unique_strings(
                reflection.get("suppress_tool_ids", []),
                limit=6,
                max_chars=80,
                lowercase=True,
            )
            if suppress_tool_ids:
                reflection_posture["suppress_tool_ids"] = suppress_tool_ids
            promote_tool_ids = _unique_strings(
                reflection.get("promote_tool_ids", []),
                limit=6,
                max_chars=80,
                lowercase=True,
            )
            if promote_tool_ids:
                reflection_posture["promote_tool_ids"] = promote_tool_ids

        summary = {}
        if focus:
            summary["focus"] = focus
        if confirmed_facts:
            summary["confirmed_facts"] = confirmed_facts
        if coverage_missing:
            summary["missing_coverage"] = list(coverage_missing)
            summary["coverage_missing"] = coverage_missing
        if recommended_tools:
            summary["followup_candidates"] = list(recommended_tools)
            summary["recommended_tools"] = recommended_tools
        if active_signals:
            summary["active_signals"] = active_signals
        if known_technologies:
            summary["likely_technologies"] = list(likely_technologies)
            summary["known_technologies"] = known_technologies
        if top_findings:
            summary["important_findings"] = list(important_findings)
            summary["top_findings"] = top_findings
        if attempted_families:
            summary["attempted_families"] = attempted_families
        if recent_attempts:
            summary["recent_attempts"] = recent_attempts
        if recent_failures:
            summary["recent_failures"] = recent_failures
        if manual_tests:
            summary["manual_tests"] = manual_tests
        if reflection_posture:
            summary["reflection_posture"] = reflection_posture
        return summary

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
        has_targeted_nuclei = _has_any("nuclei-cves", "nuclei-exposures", "nuclei-wordpress")
        has_whatweb = _has_any("whatweb", "whatweb-http", "whatweb-https")
        has_nikto = _has_any("nikto")
        has_web_content = _has_any("web-content-discovery", "dirsearch", "ffuf")
        has_http_followup = _has_any("curl-headers", "curl-options", "curl-robots")
        has_smb_signing_checks = _has_any("smb-security-mode", "smb2-security-mode")
        has_internal_safe_enum = _has_any("enum4linux-ng", "smbmap", "rpcclient-enum", "smb-enum-users.nse")
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
                    and not (has_nmap_vuln and (has_nuclei or has_targeted_nuclei))
                    and int(len(host_cves or [])) == 0
                    and int(signal_map.get("vuln_hits", 0) or 0) == 0
            ):
                _add_gap("missing_cpe_cve_enrichment", "nmap-vuln.nse", "nuclei-web", "nuclei-cves", "nuclei-exposures")
            if not inferred_technologies and not has_whatweb:
                _add_gap("missing_technology_fingerprint", "whatweb")
            if has_nmap_vuln or has_nuclei or has_targeted_nuclei:
                if not has_whatweb:
                    _add_gap("missing_whatweb", "whatweb", "whatweb-http", "whatweb-https")
                if not has_nikto:
                    _add_gap("missing_nikto", "nikto")
                if not has_web_content:
                    _add_gap("missing_web_content_discovery", "web-content-discovery", "dirsearch", "ffuf")
                if not has_http_followup:
                    _add_gap("missing_http_followup", "curl-headers", "curl-options", "curl-robots")
        else:
            if not has_screenshot and (is_rdp or is_vnc):
                _add_gap("missing_remote_screenshot", "screenshooter")
            if not (is_rdp or is_vnc) and not _has_any("banner"):
                _add_gap("missing_banner", "banner")
            if is_smb and not has_smb_signing_checks:
                _add_gap("missing_smb_signing_checks", "smb-security-mode", "smb2-security-mode")
            if is_smb and not has_internal_safe_enum:
                _add_gap("missing_internal_safe_enum", "enum4linux-ng", "smbmap", "rpcclient-enum")

        if int(len(host_cves or [])) > 0:
            if is_web and not (has_whatweb and has_nikto and has_web_content and (has_targeted_nuclei or has_http_followup)):
                _add_gap(
                    "missing_followup_after_vuln",
                    "whatweb",
                    "nikto",
                    "web-content-discovery",
                    "dirsearch",
                    "ffuf",
                    "nuclei-cves",
                    "nuclei-exposures",
                    "curl-headers",
                    "curl-options",
                    "curl-robots",
                )
            if is_smb and not has_smb_signing_checks:
                _add_gap("missing_smb_followup_after_vuln", "smb-security-mode", "smb2-security-mode")
            if is_smb and not has_internal_safe_enum:
                _add_gap("missing_internal_safe_enum", "enum4linux-ng", "smbmap", "rpcclient-enum")

        if str(analysis_mode or "").strip().lower() == "dig_deeper" and not missing:
            if is_web and not _has_any("wafw00f", "sslscan", "testssl.sh", "sslyze"):
                _add_gap("missing_deep_tls_waf_checks", "wafw00f", "sslscan", "testssl.sh")

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
                "internal_safe_enum": bool(has_internal_safe_enum),
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

    @staticmethod
    def _scheduler_output_lines(value: Any, *, max_line_chars: int = 240, max_lines: int = 320) -> List[str]:
        raw_value = str(value or "").replace("\x00", " ").replace("\r\n", "\n").replace("\r", "\n")
        lines: List[str] = []
        for raw_line in raw_value.split("\n"):
            cleaned = " ".join(str(raw_line or "").split()).strip()
            if not cleaned:
                continue
            if len(cleaned) > int(max_line_chars):
                cleaned = cleaned[:int(max_line_chars)].rstrip() + "...[truncated]"
            lines.append(cleaned)
            if len(lines) >= int(max_lines):
                break
        return lines

    @staticmethod
    def _scheduler_line_signal_score(value: Any) -> int:
        line = str(value or "").strip()
        if not line:
            return 0
        lowered = line.lower()
        score = 0
        if _CVE_TOKEN_RE.search(line):
            score += 4
        if _CPE22_TOKEN_RE.search(line) or _CPE23_TOKEN_RE.search(line):
            score += 4
        if "http://" in lowered or "https://" in lowered:
            score += 2
        if _SCHEDULER_METHOD_PATH_RE.search(line) or _SCHEDULER_STATUS_PATH_RE.search(line):
            score += 3
        for token in (
                "server:",
                "x-powered-by:",
                "location:",
                "allow:",
                "title:",
                "set-cookie:",
                "content-type:",
                "vulnerable",
                "vulnerability",
                "found",
                "interesting",
                "detected",
                "warning",
                "error",
                "exception",
                "traceback",
                "timeout",
                "redirect",
                "wordpress",
                "wp-content",
                "wp-json",
                "jetty",
                "nginx",
                "apache",
                "traccar",
                "pihole",
                "pi-hole",
                "webdav",
                "propfind",
                "tls",
                "ssl",
                "certificate",
                "waf",
                "plugin",
                "theme",
        ):
            if token in lowered:
                score += 1
        return score

    @classmethod
    def _build_scheduler_excerpt(
            cls,
            value: Any,
            max_chars: int,
            *,
            multiline: bool,
            head_lines: int,
            signal_lines: int,
            tail_lines: int,
            max_line_chars: int,
    ) -> str:
        lines = cls._scheduler_output_lines(
            value,
            max_line_chars=max_line_chars,
            max_lines=400 if multiline else 260,
        )
        if not lines:
            return ""
        separator = "\n" if multiline else " | "
        joined = separator.join(lines)
        if len(joined) <= int(max_chars):
            return joined

        selected: List[str] = []
        seen: Set[str] = set()

        def _add(line: str) -> None:
            token = str(line or "").strip()
            key = token.lower()
            if not token or key in seen:
                return
            seen.add(key)
            selected.append(token)

        for line in lines[:int(head_lines)]:
            _add(line)

        middle_start = int(head_lines)
        middle_end = len(lines) - int(tail_lines) if int(tail_lines) > 0 else len(lines)
        middle = lines[middle_start:middle_end]
        scored_middle = [
            (cls._scheduler_line_signal_score(line), index, line)
            for index, line in enumerate(middle)
        ]
        scored_middle = [item for item in scored_middle if item[0] > 0]
        scored_middle.sort(key=lambda item: (-item[0], item[1]))
        for _, _, line in scored_middle[:int(signal_lines)]:
            _add(line)

        if len(selected) <= int(head_lines) and middle:
            _add(middle[0])

        if int(tail_lines) > 0:
            for line in lines[-int(tail_lines):]:
                _add(line)

        rendered = separator.join(selected)
        if not rendered:
            rendered = joined

        truncated = len(selected) < len(lines) or len(joined) > int(max_chars)
        marker = "\n...[truncated]" if multiline else " ...[truncated]"
        if truncated and len(rendered) + len(marker) <= int(max_chars):
            return rendered + marker
        if len(rendered) <= int(max_chars):
            return rendered
        budget = max(0, int(max_chars) - len(marker))
        if budget <= 0:
            return marker.strip()
        if multiline and budget >= 80:
            body_budget = max(0, budget - 1)
            head_budget = max(40, body_budget // 2)
            tail_budget = max(20, body_budget - head_budget)
            return (
                rendered[:head_budget].rstrip()
                + marker
                + "\n"
                + rendered[-tail_budget:].lstrip()
            )
        return rendered[:budget].rstrip() + marker

    @classmethod
    def _build_scheduler_prompt_excerpt(cls, value: Any, max_chars: int) -> str:
        return cls._build_scheduler_excerpt(
            value,
            max_chars,
            multiline=False,
            head_lines=2,
            signal_lines=6,
            tail_lines=1,
            max_line_chars=220,
        )

    @classmethod
    def _build_scheduler_analysis_excerpt(cls, value: Any, max_chars: int) -> str:
        return cls._build_scheduler_excerpt(
            value,
            max_chars,
            multiline=True,
            head_lines=3,
            signal_lines=10,
            tail_lines=2,
            max_line_chars=260,
        )

    @staticmethod
    def _scheduler_tool_alias_tokens(tool_id: Any) -> Set[str]:
        token = str(tool_id or "").strip().lower()
        if not token:
            return set()
        aliases = {token}
        if token in {"whatweb", "whatweb-http", "whatweb-https"}:
            aliases.update({"whatweb", "whatweb-http", "whatweb-https"})
        elif token.endswith(".nse"):
            aliases.add("nmap")
        return aliases

    @staticmethod
    def _extract_unavailable_tool_tokens(text: Any) -> Set[str]:
        normalized = str(text or "").replace("\r", "\n").strip().lower()
        if not normalized:
            return set()

        found = set()
        patterns = (
            r"(?:^|\n)\s*(?:/bin/sh|bash|zsh|sh|fish):\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
            r"(?:^|\n)\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
            r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+command not found(?:\s|$)",
            r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+not found(?:\s|$)",
        )
        for pattern in patterns:
            for match in re.findall(pattern, normalized):
                token = str(match or "").strip().lower()
                if token:
                    found.add(token[:48])
        return found

    @staticmethod
    def _extract_missing_nse_script_tokens(text: Any) -> Set[str]:
        normalized = str(text or "").replace("\r", "\n").strip().lower()
        if not normalized:
            return set()
        return {
            str(match or "").strip().lower()[:96]
            for match in _MISSING_NSE_SCRIPT_RE.findall(normalized)
            if str(match or "").strip()
        }

    @staticmethod
    def _looks_like_local_tool_dependency_failure(text: Any) -> bool:
        normalized = str(text or "").replace("\r", "\n").strip().lower()
        if not normalized or "traceback" not in normalized:
            return False
        return bool(_PYTHON_TOOL_IMPORT_FAILURE_RE.search(normalized))

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
            " ".join([
                str(item.get("script_id", "")).strip(),
                self._observation_text_for_analysis(
                    item.get("script_id", ""),
                    item.get("analysis_excerpt", "") or item.get("excerpt", ""),
                ),
            ]).strip()
            for item in scripts
        ).lower()
        process_blob = "\n".join(
            " ".join([
                str(item.get("tool_id", "")).strip(),
                str(item.get("status", "")).strip(),
                self._observation_text_for_analysis(
                    item.get("tool_id", ""),
                    item.get("analysis_excerpt", "") or item.get("output_excerpt", ""),
                ),
            ]).strip()
            for item in recent_processes
        ).lower()
        signal_evidence_blob = "\n".join(
            text
            for text in (
                str(service_name or "").strip().lower(),
                target_blob,
                "\n".join(
                    self._observation_text_for_analysis(
                        item.get("script_id", ""),
                        item.get("analysis_excerpt", "") or item.get("excerpt", ""),
                    )
                    for item in scripts
                    if isinstance(item, dict)
                ).lower(),
                "\n".join(
                    self._observation_text_for_analysis(
                        item.get("tool_id", ""),
                        item.get("analysis_excerpt", "") or item.get("output_excerpt", ""),
                    )
                    for item in recent_processes
                    if isinstance(item, dict)
                ).lower(),
            )
            if str(text or "").strip()
        )
        combined = f"{target_blob}\n{script_blob}\n{process_blob}"

        missing_tools = set()
        missing_tools.update(self._extract_unavailable_tool_tokens(target_blob))
        missing_tools.update(self._extract_unavailable_tool_tokens(script_blob))
        for item in recent_processes:
            if not isinstance(item, dict):
                continue
            tool_id = str(item.get("tool_id", "") or "").strip().lower()
            tool_tokens = self._scheduler_tool_alias_tokens(item.get("tool_id", ""))
            process_failure_blob = "\n".join([
                str(item.get("status", "") or ""),
                str(item.get("output_excerpt", "") or ""),
            ])
            missing_nse_scripts = self._extract_missing_nse_script_tokens(process_failure_blob)
            if missing_nse_scripts:
                missing_tools.update(token for token in missing_nse_scripts if token.endswith(".nse"))
                if tool_id.endswith(".nse"):
                    missing_tools.add(tool_id)
                continue
            if self._looks_like_local_tool_dependency_failure(process_failure_blob):
                if tool_tokens:
                    missing_tools.update(tool_tokens)
                elif tool_id:
                    missing_tools.add(tool_id)
                continue
            detected = self._extract_unavailable_tool_tokens(process_failure_blob)
            if not detected:
                continue
            if tool_tokens and detected & tool_tokens:
                missing_tools.update(tool_tokens)
            else:
                missing_tools.update(detected)

        cve_hits = set(re.findall(r"\bcve-\d{4}-\d+\b", signal_evidence_blob))
        allow_blob = ""
        allow_match = re.search(r"allow:\s*([^\n]+)", signal_evidence_blob)
        if allow_match:
            allow_blob = str(allow_match.group(1) or "").lower()
        webdav_via_allow = any(token in allow_blob for token in ["propfind", "proppatch", "mkcol", "copy", "move"])

        iis_detected = any(token in signal_evidence_blob for token in [
            "microsoft-iis",
            " iis ",
            "iis/7",
            "iis/8",
            "iis/10",
        ])
        webdav_detected = (
            "webdav" in signal_evidence_blob
            or webdav_via_allow
            or ("dav" in signal_evidence_blob and ("propfind" in signal_evidence_blob or "proppatch" in signal_evidence_blob))
        )
        vmware_detected = any(token in signal_evidence_blob for token in ["vmware", "vsphere", "vcenter", "esxi"])
        coldfusion_detected = any(token in signal_evidence_blob for token in ["coldfusion", "cfusion", "adobe coldfusion", "jrun"])
        huawei_detected = any(token in signal_evidence_blob for token in ["huawei", "hg5x", "hgw"])
        ubiquiti_detected = any(token in signal_evidence_blob for token in ["ubiquiti", "unifi", "dream machine", "udm"])
        wordpress_detected = any(
            token in signal_evidence_blob
            for token in ["wordpress", "wp-content", "wp-includes", "wp-json", "/wp-admin", "xmlrpc.php"]
        )

        observed_technologies = []
        for marker, present in (
                ("iis", iis_detected),
                ("webdav", webdav_detected),
                ("vmware", vmware_detected),
                ("coldfusion", coldfusion_detected),
                ("huawei", huawei_detected),
                ("ubiquiti", ubiquiti_detected),
                ("wordpress", wordpress_detected),
                ("nginx", "nginx" in signal_evidence_blob),
                ("apache", "apache" in signal_evidence_blob),
        ):
            if present:
                observed_technologies.append(marker)

        signals = {
            "web_service": service_lower in SchedulerPlanner.WEB_SERVICE_IDS,
            "rdp_service": service_lower in {"rdp", "ms-wbt-server", "vmrdp"},
            "vnc_service": service_lower in {"vnc", "vnc-http", "rfb"},
            "tls_detected": any(token in signal_evidence_blob for token in ["ssl", "tls", "certificate", "https"]),
            "smb_signing_disabled": any(token in combined for token in [
                "message signing enabled but not required",
                "smb signing disabled",
                "signing: disabled",
                "signing: false",
            ]),
            "directory_listing": "index of /" in signal_evidence_blob or "directory listing" in signal_evidence_blob,
            "waf_detected": "waf" in signal_evidence_blob,
            "shodan_enabled": bool(target_meta.get("shodan_enabled", False)),
            "wordpress_detected": wordpress_detected,
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
        if re.fullmatch(r"0+", lowered):
            return ""
        if re.fullmatch(r"0+[a-z]{1,2}", lowered):
            return ""
        if WebRuntime._is_ipv4_like(token):
            return ""
        if "/" in token and not re.search(r"\d", token):
            return ""
        if not re.search(r"[0-9]", token):
            return ""
        return token

    @staticmethod
    def _sanitize_technology_version_for_tech(
            *,
            name: Any,
            version: Any,
            cpe: Any = "",
            evidence: Any = "",
    ) -> str:
        cleaned = WebRuntime._sanitize_technology_version(version)
        if not cleaned:
            return ""
        lowered_name = re.sub(r"[^a-z0-9]+", " ", str(name or "").strip().lower()).strip()
        cpe_base = WebRuntime._cpe_base(cpe)
        evidence_text = str(evidence or "").strip().lower()
        major_match = re.match(r"^(\d+)", cleaned)
        major = int(major_match.group(1)) if major_match else None

        if major is not None:
            if lowered_name in {"apache", "apache http server"} or "cpe:/a:apache:http_server" in cpe_base:
                if major > 3:
                    return ""
            if lowered_name == "nginx" or "cpe:/a:nginx:nginx" in cpe_base:
                if major > 2:
                    return ""
            if lowered_name == "php" or "cpe:/a:php:php" in cpe_base:
                if major < 3:
                    return ""

        if (
                re.fullmatch(r"[78]\.\d{2}", cleaned)
                and any(marker in evidence_text for marker in ("nmap", ".nse", "output fingerprint", "service fingerprint"))
        ):
            return ""
        return cleaned

    @staticmethod
    def _technology_hint_source_text(source_id: Any, output_text: Any) -> str:
        return WebRuntime._observation_text_for_analysis(source_id, output_text)

    @staticmethod
    def _observation_text_for_analysis(source_id: Any, output_text: Any) -> str:
        cleaned = _ANSI_ESCAPE_RE.sub("", str(output_text or ""))
        if not cleaned.strip():
            return ""
        source_token = str(source_id or "").strip().lower()
        lowered = cleaned.lower()
        if (
                "nmap" in source_token
                or "nse" in source_token
                or "starting nmap" in lowered
                or "nmap done:" in lowered
        ):
            cleaned = WebRuntime._strip_nmap_preamble(cleaned)
        return cleaned.strip()

    @staticmethod
    def _cve_evidence_lines(source_id: Any, output_text: Any, limit: int = 24) -> List[Tuple[str, str]]:
        cleaned = WebRuntime._observation_text_for_analysis(source_id, output_text)
        if not cleaned:
            return []
        rows: List[Tuple[str, str]] = []
        seen = set()
        for raw_line in cleaned.splitlines():
            line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
            if not line:
                continue
            lowered = line.lower()
            if lowered.startswith(("stats:", "initiating ", "completed ", "discovered open port ")):
                continue
            if "nmap.org" in lowered:
                continue
            for match in _CVE_TOKEN_RE.findall(line):
                cve_id = str(match or "").strip().upper()
                if not cve_id:
                    continue
                key = (cve_id, line.lower())
                if key in seen:
                    continue
                seen.add(key)
                rows.append((cve_id, line))
                if len(rows) >= int(limit):
                    return rows
        return rows

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
            tech_cpe = self._normalize_cpe_token(cpe)
            tech_evidence = self._truncate_scheduler_text(evidence, 520)
            tech_version = self._sanitize_technology_version_for_tech(
                name=tech_name,
                version=version,
                cpe=tech_cpe,
                evidence=tech_evidence,
            )

            if not tech_name and tech_cpe:
                tech_name = self._name_from_cpe(tech_cpe)
            if not tech_version and tech_cpe:
                cpe_version = self._sanitize_technology_version_for_tech(
                    name=tech_name,
                    version=self._version_from_cpe(tech_cpe),
                    cpe=tech_cpe,
                    evidence=tech_evidence,
                )
                if cpe_version:
                    tech_version = cpe_version
                else:
                    tech_cpe = self._cpe_base(tech_cpe)

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
            output = str(
                record.get("analysis_excerpt", "")
                or record.get("excerpt", "")
                or record.get("output_excerpt", "")
            ).strip()
            if not output:
                continue
            analysis_output = self._technology_hint_source_text(source_id, output)
            parsed = extract_tool_observations(
                source_id,
                output,
                port=str(record.get("port", "") or ""),
                protocol=str(record.get("protocol", "tcp") or "tcp"),
                service=str(record.get("service", "") or ""),
                artifact_refs=list(record.get("artifact_refs", []) or []),
                host_ip=str(record.get("host_ip", "") or ""),
                hostname=str(record.get("hostname", "") or ""),
            )
            for item in list(parsed.get("technologies", []) or [])[:24]:
                if not isinstance(item, dict):
                    continue
                _add(
                    item.get("name", ""),
                    item.get("version", ""),
                    item.get("cpe", ""),
                    item.get("evidence", "") or f"{source_id} parsed output",
                )
            cpes = self._extract_cpe_tokens(analysis_output or output, limit=4)
            for token in cpes:
                _add("", "", token, f"{source_id} output CPE")
            hinted_rows = self._guess_technology_hints(analysis_output or output, version_hint=analysis_output or output)
            for hinted_name, hinted_cpe in hinted_rows:
                version = self._version_from_cpe(hinted_cpe)
                if not version:
                    version = self._extract_version_near_tokens(analysis_output or output, [hinted_name])
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
        analysis_output_chars = 2400
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
                "analysis_excerpt": self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
            })

        process_records = []
        for row in process_rows:
            process_records.append({
                "tool_id": str(row[0] or "").strip(),
                "analysis_excerpt": self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
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
            evidence = self._truncate_scheduler_text(item.get("evidence", ""), 520)
            version = self._sanitize_technology_version_for_tech(
                name=name,
                version=item.get("version", ""),
                cpe=cpe,
                evidence=evidence,
            )
            if not name and not cpe:
                continue
            if not name and cpe:
                name = self._name_from_cpe(cpe)
            if str(name or "").strip().lower() in _PSEUDO_TECH_NAME_TOKENS and not cpe:
                continue
            if not version and cpe:
                cpe_version = self._sanitize_technology_version_for_tech(
                    name=name,
                    version=self._version_from_cpe(cpe),
                    cpe=cpe,
                    evidence=evidence,
                )
                if cpe_version:
                    version = cpe_version
                else:
                    cpe = self._cpe_base(cpe)
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
            excerpt = str(
                record.get("analysis_excerpt", "")
                or record.get("excerpt", "")
                or record.get("output_excerpt", "")
            ).strip()
            if not excerpt:
                continue
            cleaned_excerpt = self._observation_text_for_analysis(source_id, excerpt)
            parsed = extract_tool_observations(
                source_id,
                cleaned_excerpt or excerpt,
                port=str(record.get("port", "") or ""),
                protocol=str(record.get("protocol", "tcp") or "tcp"),
                service=str(record.get("service", "") or ""),
                artifact_refs=list(record.get("artifact_refs", []) or []),
                host_ip=str(record.get("host_ip", "") or ""),
                hostname=str(record.get("hostname", "") or ""),
            )
            for item in list(parsed.get("findings", []) or [])[:32]:
                if not isinstance(item, dict):
                    continue
                rows.append({
                    "title": str(item.get("title", "") or ""),
                    "severity": self._severity_from_text(item.get("severity", "info")),
                    "cvss": 0.0,
                    "cve": str(item.get("cve", "") or "").upper(),
                    "evidence": self._truncate_scheduler_text(item.get("evidence", "") or cleaned_excerpt or excerpt, 420),
                })
            suppressed_cves = {
                str(item.get("cve", "") or "").strip().upper()
                for item in list(parsed.get("finding_quality_events", []) or [])
                if isinstance(item, dict) and str(item.get("action", "") or "").strip().lower() == "suppressed"
            }
            for cve_id, evidence_line in self._cve_evidence_lines(source_id, cleaned_excerpt or excerpt):
                if cve_id in suppressed_cves:
                    continue
                mapped = cve_index.get(cve_id, {})
                severity = str(mapped.get("severity", "info") or "info")
                evidence = self._truncate_scheduler_text(
                    f"{source_id}: {evidence_line}",
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
        analysis_output_chars = 2400
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
                "analysis_excerpt": self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
            }
            for row in script_rows
        ]
        process_records = [
            {
                "tool_id": str(row[0] or "").strip(),
                "analysis_excerpt": self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
            }
            for row in process_rows
        ]

        return self._infer_findings_from_observations(
            host_cves_raw=cves,
            script_records=script_records,
            process_records=process_records,
            limit=220,
        )

    def _infer_urls_from_observations(
            self,
            *,
            script_records: List[Dict[str, Any]],
            process_records: List[Dict[str, Any]],
            limit: int = 160,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for record in (script_records[:320] + process_records[:220]):
            if not isinstance(record, dict):
                continue
            source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()
            output = str(
                record.get("analysis_excerpt", "")
                or record.get("excerpt", "")
                or record.get("output_excerpt", "")
            ).strip()
            if not output:
                continue
            parsed = extract_tool_observations(
                source_id,
                output,
                port=str(record.get("port", "") or ""),
                protocol=str(record.get("protocol", "tcp") or "tcp"),
                service=str(record.get("service", "") or ""),
                artifact_refs=list(record.get("artifact_refs", []) or []),
                host_ip=str(record.get("host_ip", "") or ""),
                hostname=str(record.get("hostname", "") or ""),
            )
            for item in list(parsed.get("urls", []) or [])[:32]:
                if not isinstance(item, dict):
                    continue
                rows.append({
                    "url": str(item.get("url", "") or ""),
                    "port": str(item.get("port", "") or record.get("port", "") or ""),
                    "protocol": str(item.get("protocol", "tcp") or record.get("protocol", "tcp") or "tcp"),
                    "service": str(item.get("service", "") or record.get("service", "") or ""),
                    "label": str(item.get("label", "") or source_id),
                    "confidence": float(item.get("confidence", 90.0) or 90.0),
                    "source_kind": str(item.get("source_kind", "observed") or "observed"),
                    "observed": bool(item.get("observed", True)),
                })
            if len(rows) >= int(limit):
                break
        return rows[:int(limit)]

    def _infer_host_urls(self, project, *, host_id: int, host_ip: str = "") -> List[Dict[str, Any]]:
        session = project.database.session()
        script_rows = []
        process_rows = []
        analysis_output_chars = 2400
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
                "analysis_excerpt": self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
            }
            for row in script_rows
        ]
        process_records = [
            {
                "tool_id": str(row[0] or "").strip(),
                "analysis_excerpt": self._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
            }
            for row in process_rows
        ]
        return self._infer_urls_from_observations(
            script_records=script_records,
            process_records=process_records,
            limit=160,
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
            evidence_lower = str(evidence or "").strip().lower()
            if _REFERENCE_ONLY_FINDING_RE.match(title) or evidence_lower in {"previous scan result", "previous tls scan result"}:
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
            key = command.lower()
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

    @staticmethod
    def _coverage_gaps_from_summary(coverage: Any) -> List[Dict[str, Any]]:
        if not isinstance(coverage, dict):
            return []
        missing = coverage.get("missing", [])
        if not isinstance(missing, list):
            return []
        recommended = coverage.get("recommended_tool_ids", [])
        if not isinstance(recommended, list):
            recommended = []
        rows = []
        for gap_id in missing[:32]:
            token = str(gap_id or "").strip().lower()
            if not token:
                continue
            rows.append({
                "gap_id": token,
                "description": token.replace("_", " "),
                "recommended_tool_ids": list(recommended[:16]),
                "analysis_mode": str(coverage.get("analysis_mode", "") or "").strip().lower(),
                "stage": str(coverage.get("stage", "") or "").strip().lower(),
                "host_cve_count": int(coverage.get("host_cve_count", 0) or 0),
                "source_kind": "inferred",
                "observed": False,
            })
        return rows

    def _persist_shared_target_state(
            self,
            *,
            host_id: int,
            host_ip: str,
            port: str = "",
            protocol: str = "tcp",
            service_name: str = "",
            scheduler_mode: str = "",
            goal_profile: str = "",
            engagement_preset: str = "",
            provider: str = "",
            hostname: str = "",
            hostname_confidence: float = 0.0,
            os_match: str = "",
            os_confidence: float = 0.0,
            next_phase: str = "",
            technologies: Optional[List[Dict[str, Any]]] = None,
            findings: Optional[List[Dict[str, Any]]] = None,
            manual_tests: Optional[List[Dict[str, Any]]] = None,
            service_inventory: Optional[List[Dict[str, Any]]] = None,
            urls: Optional[List[Dict[str, Any]]] = None,
            coverage: Optional[Dict[str, Any]] = None,
            attempted_action: Optional[Dict[str, Any]] = None,
            artifact_refs: Optional[List[str]] = None,
            screenshots: Optional[List[Dict[str, Any]]] = None,
            raw: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if int(host_id or 0) <= 0:
            return {}

        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return {}
            ensure_scheduler_target_state_table(project.database)
            host_obj = self._resolve_host(int(host_id))
            resolved_host_ip = str(host_ip or getattr(host_obj, "ip", "") or "")
            resolved_hostname = str(hostname or getattr(host_obj, "hostname", "") or "")
            resolved_os = str(os_match or getattr(host_obj, "osMatch", "") or "")
            if service_inventory is None:
                try:
                    resolved_service_inventory = load_observed_service_inventory(project.database, int(host_id))
                except Exception:
                    resolved_service_inventory = []
            else:
                resolved_service_inventory = list(service_inventory or [])
            resolved_urls = build_target_urls(resolved_host_ip, resolved_hostname, resolved_service_inventory)
            for item in list(urls or []):
                if isinstance(item, dict):
                    resolved_urls.append(dict(item))
            coverage_gaps = self._coverage_gaps_from_summary(coverage)
            attempted_actions = [attempted_action] if isinstance(attempted_action, dict) and attempted_action else []
            artifact_entries = build_artifact_entries(
                list(artifact_refs or []),
                tool_id=str((attempted_action or {}).get("tool_id", "") or ""),
                port=str(port or ""),
                protocol=str(protocol or "tcp"),
            )
            screenshot_rows = []
            for item in list(screenshots or []):
                if not isinstance(item, dict):
                    continue
                row = build_screenshot_state_row(
                    artifact_ref=str(item.get("artifact_ref", "") or item.get("url", "") or "").strip(),
                    metadata=item,
                    port=str(item.get("port", "") or port or "").strip(),
                    protocol=str(item.get("protocol", "") or protocol or "tcp").strip().lower(),
                )
                if row:
                    screenshot_rows.append(row)
            for artifact in artifact_entries:
                if str(artifact.get("kind", "") or "").strip().lower() != "screenshot":
                    continue
                artifact_ref = str(artifact.get("ref", "") or "").strip()
                row = build_screenshot_state_row(
                    screenshot_path=artifact_ref,
                    artifact_ref=artifact_ref,
                    metadata=load_screenshot_metadata(artifact_ref),
                    port=str(port or artifact.get("port", "") or "").strip(),
                    protocol=str(protocol or artifact.get("protocol", "tcp") or "tcp").strip().lower(),
                )
                if row:
                    screenshot_rows.append(row)

            payload = {
                "host_ip": resolved_host_ip,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "last_mode": str(scheduler_mode or ""),
                "provider": str(provider or ""),
                "goal_profile": str(goal_profile or ""),
                "engagement_preset": str(engagement_preset or ""),
                "last_port": str(port or ""),
                "last_protocol": str(protocol or "tcp"),
                "last_service": str(service_name or ""),
                "hostname": resolved_hostname,
                "hostname_confidence": float(hostname_confidence or 0.0),
                "hostname_source_kind": "observed" if resolved_hostname else "",
                "os_match": resolved_os,
                "os_confidence": float(os_confidence or 0.0),
                "os_source_kind": "observed" if resolved_os else "",
                "next_phase": str(next_phase or ""),
                "service_inventory": resolved_service_inventory,
                "urls": resolved_urls,
                "coverage_gaps": coverage_gaps,
                "attempted_actions": attempted_actions,
                "screenshots": screenshot_rows,
                "artifacts": [{"artifact_ref": row.get("ref", ""), **row} for row in artifact_entries],
                "raw": raw if isinstance(raw, dict) else {},
            }
            if technologies is not None:
                payload["technologies"] = list(technologies or [])
            if findings is not None:
                payload["findings"] = list(findings or [])
            if manual_tests is not None:
                payload["manual_tests"] = list(manual_tests or [])
            return upsert_target_state(project.database, int(host_id), payload, merge=True)

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
            existing_raw = existing.get("raw", {}) if isinstance(existing.get("raw", {}), dict) else {}
            existing_findings = self._normalize_ai_findings(existing.get("findings", []))

            merged_technologies = self._merge_technologies(
                existing=existing.get("technologies", []) if isinstance(existing.get("technologies", []), list) else [],
                incoming=technologies,
                limit=220,
            )
            merged_findings = self._merge_ai_items(
                existing=existing_findings,
                incoming=findings_combined,
                key_fields=["title", "cve", "severity"],
                limit=260,
            )
            merged_manual = self._merge_ai_items(
                existing=existing.get("manual_tests", []) if isinstance(existing.get("manual_tests", []), list) else [],
                incoming=manual_tests,
                key_fields=["command"],
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

            raw_payload = dict(existing_raw)
            raw_payload.update(payload)
            if isinstance(existing_raw.get("reflection", {}), dict) and "reflection" not in raw_payload:
                raw_payload["reflection"] = dict(existing_raw.get("reflection", {}))

            state_payload = {
                "host_id": int(host_id),
                "host_ip": str(host_ip or ""),
                "_sync_target_state": False,
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
                "raw": raw_payload,
            }
            upsert_host_ai_state(project.database, int(host_id), state_payload)
            self._persist_shared_target_state(
                host_id=int(host_id),
                host_ip=str(host_ip or ""),
                port=str(port or ""),
                protocol=str(protocol or "tcp"),
                service_name=str(service_name or ""),
                scheduler_mode="ai",
                goal_profile=str(goal_profile or existing.get("goal_profile", "")),
                engagement_preset=str(existing.get("engagement_preset", "") or ""),
                provider=str(payload.get("provider", "") or existing.get("provider", "")),
                hostname=selected_hostname,
                hostname_confidence=selected_hostname_conf,
                os_match=selected_os,
                os_confidence=selected_os_conf,
                next_phase=str(next_phase or existing.get("next_phase", "")),
                technologies=provider_technologies or None,
                findings=findings or None,
                manual_tests=manual_tests or None,
                raw=raw_payload,
            )

        self._apply_ai_host_updates(
            host_id=int(host_id),
            host_ip=str(host_ip or ""),
            hostname=hostname_candidate,
            hostname_confidence=hostname_confidence,
            os_match=os_candidate,
            os_confidence=os_confidence,
        )

    def _persist_scheduler_reflection_analysis(
            self,
            *,
            host_id: int,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            goal_profile: str,
            reflection_payload: Optional[Dict[str, Any]],
    ):
        payload = reflection_payload if isinstance(reflection_payload, dict) else {}
        reflection_state = str(payload.get("state", "") or "").strip().lower()
        reason = self._truncate_scheduler_text(payload.get("reason", ""), 320)
        priority_shift = str(payload.get("priority_shift", "") or "").strip().lower()[:64]
        trigger_reason = str(payload.get("trigger_reason", "") or "").strip().lower()[:64]
        trigger_context_raw = payload.get("trigger_context", {}) if isinstance(payload.get("trigger_context", {}), dict) else {}
        trigger_context = {}
        for key in ("round_number", "current_phase", "previous_phase", "window_size", "repeated_selection_count"):
            value = trigger_context_raw.get(key, "")
            if value in ("", None):
                continue
            trigger_context[str(key)] = value
        trigger_recent_failures = [
            self._truncate_scheduler_text(item, 120)
            for item in list(trigger_context_raw.get("recent_failures", []) or [])[:6]
            if self._truncate_scheduler_text(item, 120)
        ]
        if trigger_recent_failures:
            trigger_context["recent_failures"] = trigger_recent_failures
        promote_tool_ids = [
            str(item or "").strip().lower()[:120]
            for item in list(payload.get("promote_tool_ids", []) or [])[:16]
            if str(item or "").strip()
        ]
        suppress_tool_ids = [
            str(item or "").strip().lower()[:120]
            for item in list(payload.get("suppress_tool_ids", []) or [])[:16]
            if str(item or "").strip()
        ]
        manual_tests = self._normalize_ai_manual_tests(payload.get("manual_tests", []))

        if not any([reflection_state, reason, priority_shift, trigger_reason, trigger_context, promote_tool_ids, suppress_tool_ids, manual_tests]):
            return

        reflection_record = {
            "state": reflection_state or "continue",
            "reason": reason,
            "priority_shift": priority_shift,
            "trigger_reason": trigger_reason,
            "trigger_context": trigger_context,
            "promote_tool_ids": promote_tool_ids,
            "suppress_tool_ids": suppress_tool_ids,
            "manual_tests": manual_tests,
            "provider": str(payload.get("provider", "") or ""),
            "prompt_version": str(payload.get("prompt_version", "") or ""),
            "prompt_type": str(payload.get("prompt_type", "") or "reflection"),
            "reflected_at": getTimestamp(True),
        }

        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if not project:
                return
            ensure_scheduler_ai_state_table(project.database)
            existing = get_host_ai_state(project.database, int(host_id)) or {}
            existing_raw = existing.get("raw", {}) if isinstance(existing.get("raw", {}), dict) else {}
            existing_technologies = self._normalize_ai_technologies(existing.get("technologies", []))
            existing_findings = self._normalize_ai_findings(existing.get("findings", []))
            merged_manual = self._merge_ai_items(
                existing=existing.get("manual_tests", []) if isinstance(existing.get("manual_tests", []), list) else [],
                incoming=manual_tests,
                key_fields=["command"],
                limit=200,
            )
            raw_payload = dict(existing_raw)
            raw_payload["reflection"] = reflection_record

            state_payload = {
                "host_id": int(host_id),
                "host_ip": str(host_ip or existing.get("host_ip", "")),
                "_sync_target_state": False,
                "provider": str(payload.get("provider", "") or existing.get("provider", "")),
                "goal_profile": str(goal_profile or existing.get("goal_profile", "")),
                "last_port": str(port or existing.get("last_port", "")),
                "last_protocol": str(protocol or existing.get("last_protocol", "")),
                "last_service": str(service_name or existing.get("last_service", "")),
                "hostname": self._sanitize_ai_hostname(existing.get("hostname", "")),
                "hostname_confidence": self._ai_confidence_value(existing.get("hostname_confidence", 0.0)),
                "os_match": str(existing.get("os_match", "") or ""),
                "os_confidence": self._ai_confidence_value(existing.get("os_confidence", 0.0)),
                "next_phase": str(existing.get("next_phase", "") or ""),
                "technologies": existing_technologies,
                "findings": existing_findings,
                "manual_tests": merged_manual,
                "raw": raw_payload,
            }
            upsert_host_ai_state(project.database, int(host_id), state_payload)
            self._persist_shared_target_state(
                host_id=int(host_id),
                host_ip=str(host_ip or existing.get("host_ip", "")),
                port=str(port or existing.get("last_port", "")),
                protocol=str(protocol or existing.get("last_protocol", "tcp") or "tcp"),
                service_name=str(service_name or existing.get("last_service", "")),
                scheduler_mode="ai",
                goal_profile=str(goal_profile or existing.get("goal_profile", "")),
                engagement_preset=str(existing.get("engagement_preset", "") or ""),
                provider=str(payload.get("provider", "") or existing.get("provider", "")),
                hostname=self._sanitize_ai_hostname(existing.get("hostname", "")),
                hostname_confidence=self._ai_confidence_value(existing.get("hostname_confidence", 0.0)),
                os_match=str(existing.get("os_match", "") or ""),
                os_confidence=self._ai_confidence_value(existing.get("os_confidence", 0.0)),
                next_phase=str(existing.get("next_phase", "") or ""),
                technologies=None,
                findings=None,
                manual_tests=manual_tests or None,
                raw=raw_payload,
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
            if self._runner_type_for_approval_item(item) == "manual":
                manual_reason = "approved for operator execution"
                update_pending_approval(
                    project.database,
                    int(approval_id),
                    status="approved",
                    decision_reason=manual_reason,
                )
                update_scheduler_decision_for_approval(
                    project.database,
                    int(approval_id),
                    approved=True,
                    executed=False,
                    reason=manual_reason,
                )
                return {
                    "approval_id": int(approval_id),
                    "executed": False,
                    "reason": "manual runner requires operator execution",
                    "process_id": 0,
                }
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

        decision = ScheduledAction.from_legacy_fields(
            tool_id=str(item.get("tool_id", "")),
            label=str(item.get("label", "")),
            command_template=str(item.get("command_template", "")),
            protocol=str(item.get("protocol", "tcp") or "tcp"),
            score=100.0,
            rationale=str(item.get("rationale", "")),
            mode=str(item.get("scheduler_mode", "ai") or "ai"),
            goal_profile=str(item.get("goal_profile", "") or ""),
            family_id=str(item.get("command_family_id", "")),
            danger_categories=self._split_csv(
                str(item.get("risk_tags", "") or item.get("danger_categories", ""))
            ),
            requires_approval=False,
            target_ref={
                "host_ip": str(item.get("host_ip", "")),
                "port": str(item.get("port", "")),
                "service": str(item.get("service", "")),
                "protocol": str(item.get("protocol", "tcp") or "tcp"),
            },
            approval_state="not_required",
            policy_reason=str(item.get("policy_reason", "")),
            risk_summary=str(item.get("risk_summary", "")),
            safer_alternative=str(item.get("safer_alternative", "")),
            family_policy_state=str(item.get("family_policy_state", "")),
        )
        decision.linked_evidence_refs = self._split_csv(str(item.get("evidence_refs", "")))

        execution_result = self._execute_scheduler_decision(
            decision,
            host_ip=str(item.get("host_ip", "")),
            port=str(item.get("port", "")),
            protocol=str(item.get("protocol", "tcp") or "tcp"),
            service_name=str(item.get("service", "")),
            command_template=str(item.get("command_template", "")),
            timeout=300,
            job_id=int(job_id or 0),
            capture_metadata=True,
            approval_id=int(approval_id),
        )
        executed = bool(execution_result.get("executed", False))
        reason = str(execution_result.get("reason", "") or "")
        process_id = int(execution_result.get("process_id", 0) or 0)
        execution_record = execution_result.get("execution_record")

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

        self._persist_scheduler_execution_record(
            decision,
            execution_record,
            host_ip=str(item.get("host_ip", "")),
            port=str(item.get("port", "")),
            protocol=str(item.get("protocol", "")),
            service_name=str(item.get("service", "")),
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
            capture_metadata: bool = False,
            approval_id: int = 0,
            runner_preference: str = "",
            runner_settings: Optional[Dict[str, Any]] = None,
    ) -> Any:
        normalized_runner_settings = normalize_runner_settings(runner_settings or {})
        project = self._require_active_project()
        request = RunnerExecutionRequest(
            decision=decision,
            tool_id=str(decision.tool_id or ""),
            command_template=str(command_template or ""),
            host_ip=str(host_ip or ""),
            hostname=str(self._hostname_for_ip(host_ip) or ""),
            port=str(port or ""),
            protocol=str(protocol or "tcp"),
            service_name=str(service_name or ""),
            timeout=int(timeout or 300),
            job_id=int(job_id or 0),
            approval_id=int(approval_id or 0),
            declared_runner_type=str(getattr(getattr(decision, "action", None), "runner_type", "local") or "local"),
        )

        def _build_command(request_payload):
            return self._build_command(
                str(request_payload.command_template or ""),
                str(request_payload.host_ip or ""),
                str(request_payload.port or ""),
                str(request_payload.protocol or "tcp"),
                str(request_payload.tool_id or ""),
                str(getattr(request_payload, "service_name", "") or ""),
            )

        def _execute_local_command(*, request, rendered_command, outputfile, runner_type):
            tab_title = f"{request.tool_id} ({request.port}/{request.protocol})"
            command_result = self._run_command_with_tracking(
                tool_name=request.tool_id,
                tab_title=tab_title,
                host_ip=request.host_ip,
                port=request.port,
                protocol=request.protocol,
                command=rendered_command,
                outputfile=outputfile,
                timeout=int(request.timeout or 300),
                job_id=int(request.job_id or 0),
                return_metadata=True,
            )
            executed, reason, process_id, metadata = command_result
            return RunnerExecutionResult(
                executed=bool(executed),
                reason=str(reason or ""),
                runner_type=str(runner_type or "local"),
                process_id=int(process_id or 0),
                started_at=str(metadata.get("started_at", "") or ""),
                finished_at=str(metadata.get("finished_at", "") or ""),
                stdout_ref=str(metadata.get("stdout_ref", "") or ""),
                stderr_ref=str(metadata.get("stderr_ref", "") or ""),
                artifact_refs=list(metadata.get("artifact_refs", []) or []),
            )

        def _execute_browser_action(*, request, browser_settings, runner_type):
            started_at = getTimestamp(True)
            executed, reason, artifact_refs = self._take_screenshot(
                str(request.host_ip or ""),
                str(request.port or ""),
                service_name=str(request.service_name or ""),
                return_artifacts=True,
                browser_settings=browser_settings,
            )
            return RunnerExecutionResult(
                executed=bool(executed),
                reason=str(reason or ""),
                runner_type=str(runner_type or "browser"),
                started_at=started_at,
                finished_at=getTimestamp(True),
                artifact_refs=list(artifact_refs or []),
            )

        allow_optional_runners = True
        scheduler_config = getattr(self, "scheduler_config", None)
        if scheduler_config is not None and hasattr(scheduler_config, "is_feature_enabled"):
            allow_optional_runners = bool(scheduler_config.is_feature_enabled("optional_runners"))

        runner_result = execute_runner_request(
            request,
            runner_preference=str(runner_preference or ""),
            runner_settings=normalized_runner_settings,
            allow_optional_runners=allow_optional_runners,
            build_command=_build_command,
            execute_local_command=_execute_local_command,
            execute_browser_action=_execute_browser_action,
            mount_paths=[
                getattr(project.properties, "runningFolder", ""),
                getattr(project.properties, "outputFolder", ""),
                os.getcwd(),
            ],
            workdir=os.getcwd(),
        )
        if not capture_metadata:
            return bool(runner_result.executed), str(runner_result.reason or ""), int(runner_result.process_id or 0)

        fallback_timestamp = getTimestamp(True)
        execution_record = ExecutionRecord.from_plan_step(
            decision,
            started_at=str(runner_result.started_at or fallback_timestamp),
            finished_at=str(runner_result.finished_at or fallback_timestamp),
            exit_status=str(runner_result.reason or ""),
            runner_type=str(runner_result.runner_type or "local"),
            stdout_ref=str(runner_result.stdout_ref or ""),
            stderr_ref=str(runner_result.stderr_ref or ""),
            artifact_refs=list(runner_result.artifact_refs or []),
            approval_id=str(approval_id or ""),
        )
        return {
            "executed": bool(runner_result.executed),
            "reason": str(runner_result.reason or ""),
            "process_id": int(runner_result.process_id or 0),
            "execution_record": execution_record,
        }

    @staticmethod
    def _is_rdp_service(service_name: str) -> bool:
        value = str(service_name or "").strip().rstrip("?").lower()
        return value in {"rdp", "ms-wbt-server", "vmrdp", "ms-term-serv"}

    @staticmethod
    def _is_vnc_service(service_name: str) -> bool:
        value = str(service_name or "").strip().rstrip("?").lower()
        return value in {"vnc", "vnc-http", "rfb"}

    @staticmethod
    def _port_sort_key(port_value: str) -> Tuple[int, str]:
        token = str(port_value or "").strip()
        try:
            return 0, f"{int(token):08d}"
        except (TypeError, ValueError):
            return 1, token

    @classmethod
    def _is_web_screenshot_target(cls, port: str, protocol: str, service_name: str) -> bool:
        if str(protocol or "").strip().lower() != "tcp":
            return False
        service_lower = str(service_name or "").strip().rstrip("?").lower()
        if (
                service_lower in SchedulerPlanner.WEB_SERVICE_IDS
                or service_lower.startswith("http")
                or "https" in service_lower
                or service_lower.endswith("http")
                or service_lower.endswith("https")
                or service_lower in {"soap", "ssl/http", "ssl|http", "webcache", "www"}
        ):
            return True
        return str(port or "").strip() in {
            "80",
            "81",
            "82",
            "88",
            "443",
            "591",
            "593",
            "8000",
            "8008",
            "8080",
            "8081",
            "8088",
            "8443",
            "8888",
            "9000",
            "9090",
            "9443",
        }

    def _collect_host_screenshot_targets(self, host_id: int) -> List[Dict[str, str]]:
        resolved_host_id = int(host_id or 0)
        with self._lock:
            project = self._require_active_project()
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            repo_container = getattr(project, "repositoryContainer", None)
            port_repo = getattr(repo_container, "portRepository", None)
            service_repo = getattr(repo_container, "serviceRepository", None)
            port_rows = list(port_repo.getPortsByHostId(host.id)) if port_repo else []

        targets: List[Dict[str, str]] = []
        seen = set()
        for port_row in port_rows:
            port_value = str(getattr(port_row, "portId", "") or "").strip()
            protocol = str(getattr(port_row, "protocol", "tcp") or "tcp").strip().lower() or "tcp"
            state = str(getattr(port_row, "state", "") or "").strip().lower()
            if not port_value or protocol != "tcp":
                continue
            if state and "open" not in state:
                continue
            service_name = ""
            service_id = getattr(port_row, "serviceId", None)
            if service_id and service_repo:
                try:
                    service_obj = service_repo.getServiceById(service_id)
                except Exception:
                    service_obj = None
                service_name = str(getattr(service_obj, "name", "") or "") if service_obj else ""
            if not self._is_web_screenshot_target(port_value, protocol, service_name):
                continue
            dedupe_key = (port_value, protocol)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            targets.append({
                "port": port_value,
                "protocol": protocol,
                "service_name": service_name,
            })
        targets.sort(key=lambda item: (self._port_sort_key(item.get("port", "")), item.get("protocol", "")))
        return targets

    def _run_host_screenshot_refresh(self, *, host_id: int, job_id: int = 0) -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        with self._lock:
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            hostname = str(getattr(host, "hostname", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")

        targets = self._collect_host_screenshot_targets(resolved_host_id)
        if not targets:
            return {
                "host_id": resolved_host_id,
                "host_ip": host_ip,
                "hostname": hostname,
                "target_count": 0,
                "completed": 0,
                "results": [],
                "screenshots": [],
            }

        results = []
        completed = 0
        for target in targets:
            if int(job_id or 0) > 0 and self.jobs.is_cancel_requested(int(job_id)):
                break
            executed, reason, artifact_refs = self._take_screenshot(
                host_ip,
                str(target.get("port", "") or ""),
                service_name=str(target.get("service_name", "") or ""),
                return_artifacts=True,
            )
            if executed:
                completed += 1
            results.append({
                "port": str(target.get("port", "") or ""),
                "protocol": str(target.get("protocol", "tcp") or "tcp"),
                "service_name": str(target.get("service_name", "") or ""),
                "executed": bool(executed),
                "reason": str(reason or ""),
                "artifact_refs": list(artifact_refs or []),
            })

        with self._lock:
            project = self._require_active_project()
            screenshots = self._list_screenshots_for_host(project, host_ip)

        try:
            self.get_host_workspace(resolved_host_id)
        except Exception:
            pass

        self._emit_ui_invalidation("graph", "hosts", "services")

        return {
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "hostname": hostname,
            "target_count": len(targets),
            "completed": int(completed),
            "results": results,
            "screenshots": screenshots,
        }

    def _run_graph_screenshot_refresh(
            self,
            *,
            host_id: int,
            port: str,
            protocol: str = "tcp",
            job_id: int = 0,
    ) -> Dict[str, Any]:
        resolved_host_id = int(host_id or 0)
        resolved_port = str(port or "").strip()
        resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        with self._lock:
            host = self._resolve_host(resolved_host_id)
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_ip = str(getattr(host, "ip", "") or "").strip()
            hostname = str(getattr(host, "hostname", "") or "").strip()
            if not host_ip:
                raise ValueError(f"Host {host_id} does not have a valid IP.")
            service_name = self._service_name_for_target(host_ip, resolved_port, resolved_protocol)

        if int(job_id or 0) > 0 and self.jobs.is_cancel_requested(int(job_id)):
            return {
                "host_id": resolved_host_id,
                "host_ip": host_ip,
                "hostname": hostname,
                "port": resolved_port,
                "protocol": resolved_protocol,
                "executed": False,
                "reason": "cancelled",
                "artifact_refs": [],
                "screenshots": [],
            }

        executed, reason, artifact_refs = self._take_screenshot(
            host_ip,
            resolved_port,
            service_name=str(service_name or ""),
            return_artifacts=True,
        )
        with self._lock:
            project = self._require_active_project()
            screenshots = self._list_screenshots_for_host(project, host_ip)

        try:
            self.get_host_workspace(resolved_host_id)
        except Exception:
            pass

        self._emit_ui_invalidation("graph", "hosts", "services")

        return {
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "hostname": hostname,
            "port": resolved_port,
            "protocol": resolved_protocol,
            "service_name": str(service_name or ""),
            "executed": bool(executed),
            "reason": str(reason or ""),
            "artifact_refs": list(artifact_refs or []),
            "screenshots": screenshots,
        }

    def _take_screenshot(
            self,
            host_ip: str,
            port: str,
            service_name: str = "",
            return_artifacts: bool = False,
            browser_settings: Optional[Dict[str, Any]] = None,
    ) -> Any:
        normalized_service = str(service_name or "").strip().rstrip("?").lower()
        if self._is_rdp_service(normalized_service) or self._is_vnc_service(normalized_service):
            return self._take_remote_service_screenshot(
                host_ip=host_ip,
                port=port,
                service_name=normalized_service,
                return_artifacts=return_artifacts,
                browser_settings=browser_settings,
            )

        with self._lock:
            project = self._require_active_project()
            screenshots_dir = os.path.join(project.properties.outputFolder, "screenshots")
            os.makedirs(screenshots_dir, exist_ok=True)

        normalized_browser = normalize_runner_settings({"browser": browser_settings or {}}).get("browser", {})

        target_host = choose_preferred_screenshot_host(self._hostname_for_ip(host_ip), host_ip)
        host_port = f"{target_host}:{port}"
        prefer_https = bool(isHttps(target_host, port))
        url_candidates = [
            f"https://{host_port}",
            f"http://{host_port}",
        ] if prefer_https else [
            f"http://{host_port}",
            f"https://{host_port}",
        ]

        capture = None
        failure_capture = None
        captured_url = ""
        for url in url_candidates:
            current_capture = run_eyewitness_capture(
                url=url,
                output_parent_dir=screenshots_dir,
                delay=int(normalized_browser.get("delay", 5) or 5),
                use_xvfb=bool(normalized_browser.get("use_xvfb", True)),
                timeout=int(normalized_browser.get("timeout", 180) or 180),
            )
            if current_capture.get("ok"):
                capture = current_capture
                captured_url = url
                break
            failure_capture = current_capture
            if str(current_capture.get("reason", "") or "") == "eyewitness missing":
                break

        if not capture:
            failed = failure_capture or {}
            reason = str(failed.get("reason", "") or "")
            if reason == "eyewitness missing":
                if return_artifacts:
                    return False, "skipped: eyewitness missing", []
                return False, "skipped: eyewitness missing"
            detail = summarize_eyewitness_failure(failed.get("attempts", []))
            if detail:
                if return_artifacts:
                    return False, f"skipped: screenshot png missing ({detail})", []
                return False, f"skipped: screenshot png missing ({detail})"
            if return_artifacts:
                return False, "skipped: screenshot png missing", []
            return False, "skipped: screenshot png missing"

        src_path = str(capture.get("screenshot_path", "") or "")
        if not src_path or not os.path.isfile(src_path):
            if return_artifacts:
                return False, "skipped: screenshot output missing", []
            return False, "skipped: screenshot output missing"

        deterministic_name = f"{host_ip}-{port}-screenshot.png"
        dst_path = os.path.join(screenshots_dir, deterministic_name)
        shutil.copy2(src_path, dst_path)
        capture_reason = "completed"
        returncode = int(capture.get("returncode", 0) or 0)
        if returncode != 0:
            capture_reason = f"completed (eyewitness exited {returncode})"
        metadata_path = write_screenshot_metadata(
            dst_path,
            build_screenshot_metadata(
                screenshot_path=dst_path,
                host_ip=host_ip,
                hostname=self._hostname_for_ip(host_ip) if hasattr(self, "_hostname_for_ip") else "",
                port=port,
                protocol="tcp",
                service_name=normalized_service or str(service_name or ""),
                target_url=captured_url,
                capture_engine=str(capture.get("executable", "") or "eyewitness"),
                capture_reason=capture_reason,
                captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                capture_returncode=returncode,
            ),
        )
        artifact_refs = [dst_path]
        if metadata_path:
            artifact_refs.append(metadata_path)
        if returncode != 0:
            if return_artifacts:
                return True, capture_reason, artifact_refs
            return True, capture_reason
        if return_artifacts:
            return True, "completed", artifact_refs
        return True, "completed"

    def _take_remote_service_screenshot(
            self,
            *,
            host_ip: str,
            port: str,
            service_name: str,
            return_artifacts: bool = False,
            browser_settings: Optional[Dict[str, Any]] = None,
    ) -> Any:
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
        metadata_path = screenshot_metadata_path(dst_path)
        if metadata_path and os.path.isfile(metadata_path):
            try:
                os.remove(metadata_path)
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
        normalized_browser = normalize_runner_settings({"browser": browser_settings or {}}).get("browser", {})
        timeout = max(30, min(int(normalized_browser.get("timeout", 180) or 180), 300))
        for command in commands:
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                    env=build_tool_execution_env(),
                )
                output = self._truncate_scheduler_text(result.stdout or "", 260)
                attempts.append({
                    "command": " ".join(command),
                    "returncode": int(result.returncode),
                    "output": output,
                })
                if result.returncode == 0 and os.path.isfile(dst_path) and os.path.getsize(dst_path) > 0:
                    metadata_path = write_screenshot_metadata(
                        dst_path,
                        build_screenshot_metadata(
                            screenshot_path=dst_path,
                            host_ip=host_ip,
                            hostname=self._hostname_for_ip(host_ip) if hasattr(self, "_hostname_for_ip") else "",
                            port=port,
                            protocol="tcp",
                            service_name=service_name,
                            capture_engine=str(command[0] if command else ""),
                            capture_reason="completed",
                            captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            capture_returncode=int(result.returncode),
                        ),
                    )
                    artifact_refs = [dst_path]
                    if metadata_path:
                        artifact_refs.append(metadata_path)
                    if return_artifacts:
                        return True, "completed", artifact_refs
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
            reason = "skipped: remote screenshot missing (" + " | ".join(detail_parts) + ")"
            if return_artifacts:
                return False, reason, []
            return False, reason
        if return_artifacts:
            return False, "skipped: remote screenshot missing", []
        return False, "skipped: remote screenshot missing"

    def _tool_execution_profile(self, tool_name: Any) -> Dict[str, Any]:
        tool_id = str(tool_name or "").strip().lower()
        profiles = normalize_tool_execution_profiles(DEFAULT_TOOL_EXECUTION_PROFILES)
        scheduler_config = getattr(self, "scheduler_config", None)
        if scheduler_config is not None and hasattr(scheduler_config, "load"):
            try:
                loaded = scheduler_config.load()
            except Exception:
                loaded = {}
            if isinstance(loaded, dict):
                profiles = normalize_tool_execution_profiles(loaded.get("tool_execution_profiles", profiles))
        return dict(profiles.get(tool_id, {}))

    def _resolve_process_timeout_policy(self, tool_name: Any, requested_timeout: Any) -> Dict[str, Any]:
        try:
            default_timeout = max(1, int(requested_timeout or 300))
        except (TypeError, ValueError):
            default_timeout = 300
        profile = self._tool_execution_profile(tool_name)
        quiet_long_running = bool(profile.get("quiet_long_running", False))
        if not quiet_long_running:
            return {
                "quiet_long_running": False,
                "inactivity_timeout_seconds": int(default_timeout),
                "hard_timeout_seconds": 0,
            }
        try:
            inactivity_timeout = int(profile.get("activity_timeout_seconds", default_timeout) or default_timeout)
        except (TypeError, ValueError):
            inactivity_timeout = default_timeout
        try:
            hard_timeout = int(profile.get("hard_timeout_seconds", 0) or 0)
        except (TypeError, ValueError):
            hard_timeout = 0
        return {
            "quiet_long_running": True,
            "inactivity_timeout_seconds": max(30, int(inactivity_timeout or 1800)),
            "hard_timeout_seconds": max(0, int(hard_timeout or 0)),
        }

    @staticmethod
    def _sample_process_tree_activity(proc: Optional[subprocess.Popen]) -> Optional[Tuple[float, int]]:
        if proc is None or int(getattr(proc, "pid", 0) or 0) <= 0:
            return None
        try:
            root = psutil.Process(int(proc.pid))
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, ValueError):
            return None

        cpu_total = 0.0
        io_total = 0
        seen_pids = set()
        processes = [root]
        try:
            processes.extend(root.children(recursive=True))
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass

        for current in processes:
            try:
                pid = int(current.pid)
            except Exception:
                continue
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            try:
                cpu_times = current.cpu_times()
                cpu_total += float(getattr(cpu_times, "user", 0.0) or 0.0)
                cpu_total += float(getattr(cpu_times, "system", 0.0) or 0.0)
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                pass
            try:
                io_counters = current.io_counters()
                if io_counters is not None:
                    read_chars = getattr(io_counters, "read_chars", None)
                    write_chars = getattr(io_counters, "write_chars", None)
                    if read_chars is not None or write_chars is not None:
                        io_total += int(read_chars or 0) + int(write_chars or 0)
                    else:
                        io_total += int(getattr(io_counters, "read_bytes", 0) or 0)
                        io_total += int(getattr(io_counters, "write_bytes", 0) or 0)
            except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, AttributeError):
                pass
        return round(cpu_total, 4), int(io_total)

    @staticmethod
    def _process_tree_activity_changed(
            previous: Optional[Tuple[float, int]],
            current: Optional[Tuple[float, int]],
    ) -> bool:
        if previous is None or current is None:
            return False
        try:
            prev_cpu, prev_io = previous
            cur_cpu, cur_io = current
        except Exception:
            return False
        return (
            float(cur_cpu) > float(prev_cpu)
            or int(cur_io) > int(prev_io)
        )

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
            return_metadata: bool = False,
    ) -> Any:
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
            self._register_job_process(resolved_job_id, int(process_id))
            if self.jobs.is_cancel_requested(resolved_job_id):
                process_repo.storeProcessCancelStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
                process_repo.storeProcessOutput(str(process_id), "[cancelled before start]")
                self._unregister_job_process(int(process_id))
                cancelled_result = (False, "killed", int(process_id))
                if not return_metadata:
                    return cancelled_result
                return cancelled_result + ({
                    "started_at": start_time,
                    "finished_at": getTimestamp(True),
                    "stdout_ref": f"process_output:{int(process_id)}",
                    "stderr_ref": "",
                    "artifact_refs": self._collect_command_artifacts(outputfile),
                },)
        self._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)

        proc: Optional[subprocess.Popen] = None
        output_parts: List[str] = []
        output_queue: queue.Queue = queue.Queue()
        reader_done = threading.Event()
        started_at = time.monotonic()
        timeout_policy = self._resolve_process_timeout_policy(tool_name, timeout)
        quiet_long_running = bool(timeout_policy.get("quiet_long_running", False))
        inactivity_timeout_seconds = max(1, int(timeout_policy.get("inactivity_timeout_seconds", timeout) or timeout or 300))
        hard_timeout_seconds = max(0, int(timeout_policy.get("hard_timeout_seconds", 0) or 0))
        progress_state = {
            "adapter": self._process_progress_adapter_for_command(str(tool_name), str(command)),
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

            signal_terminated = code < 0 or 128 <= code <= 192
            if signal_terminated and float(runtime_seconds) >= float(_PROCESS_CRASH_MIN_RUNTIME_SECONDS):
                return "Crashed"
            return "Problem"

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
                "artifact_refs": self._collect_command_artifacts(outputfile),
            },)

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=(os.name != "nt"),
                env=build_tool_execution_env(),
            )
            process_repo.storeProcessRunningStatus(str(process_id), str(proc.pid))
            with self._process_runtime_lock:
                self._active_processes[int(process_id)] = proc
                self._kill_requests.discard(int(process_id))
            if quiet_long_running:
                last_process_activity = self._sample_process_tree_activity(proc)

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
                        self._update_process_progress(
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
                    self._write_process_output_partial(int(process_id), "".join(output_parts))
                    flush_due_at = now + 0.5

                if quiet_long_running and now >= activity_sample_due_at and proc.poll() is None:
                    current_activity = self._sample_process_tree_activity(proc)
                    if self._process_tree_activity_changed(last_process_activity, current_activity):
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

                if proc.poll() is None:
                    if hard_timeout_seconds > 0 and (now - started_at) > int(hard_timeout_seconds):
                        timed_out = True
                        timeout_reason = f"timeout after {int(hard_timeout_seconds)}s total runtime"
                        self._signal_process_tree(proc, force=True)
                    elif quiet_long_running and (now - last_activity_at) > int(inactivity_timeout_seconds):
                        timed_out = True
                        timeout_reason = f"timeout after {int(inactivity_timeout_seconds)}s without CPU/IO activity"
                        self._signal_process_tree(proc, force=True)
                    elif (not quiet_long_running) and (now - last_output_at) > int(inactivity_timeout_seconds):
                        timed_out = True
                        timeout_reason = f"timeout after {int(inactivity_timeout_seconds)}s without output"
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
            runtime_seconds = max(0.0, float((process_exited_at or time.monotonic()) - started_at))
            allowed_exit_codes = AppSettings.allowed_nonzero_exit_codes(str(tool_name or ""))
            if timed_out:
                combined_output += f"\n[{timeout_reason}]"
                process_repo.storeProcessProblemStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
                process_repo.storeProcessOutput(str(process_id), combined_output)
                return _build_result(False, f"failed: {timeout_reason}", int(process_id))

            if killed:
                process_repo.storeProcessKillStatus(str(process_id))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
                process_repo.storeProcessOutput(str(process_id), combined_output)
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
                return _build_result(True, f"completed (allowed exit {int(proc.returncode or 0)})", int(process_id))

            if int(proc.returncode or 0) != 0:
                _store_failure_status(_classify_nonzero_exit(proc.returncode, runtime_seconds))
                process_repo.storeProcessProgress(str(process_id), estimated_remaining=None)
                process_repo.storeProcessOutput(str(process_id), combined_output)
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
            with self._process_runtime_lock:
                self._active_processes.pop(int(process_id), None)
                self._kill_requests.discard(int(process_id))
            self._unregister_job_process(int(process_id))
            self._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)

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
            approval_id = queue_pending_approval(project.database, {
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
                "risk_tags": ",".join(decision.risk_tags),
                "scheduler_mode": str(decision.mode),
                "goal_profile": str(decision.goal_profile),
                "engagement_preset": str(decision.engagement_preset),
                "rationale": str(decision.rationale),
                "policy_decision": str(decision.policy_decision),
                "policy_reason": str(decision.policy_reason),
                "risk_summary": str(decision.risk_summary),
                "safer_alternative": str(decision.safer_alternative),
                "family_policy_state": str(decision.family_policy_state),
                "evidence_refs": ",".join(str(item) for item in list(decision.linked_evidence_refs or []) if str(item).strip()),
                "decision_reason": "pending approval",
                "execution_job_id": "",
            })
        self._emit_ui_invalidation("approvals", "overview")
        return approval_id

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
                "engagement_preset": str(decision.engagement_preset),
                "tool_id": str(decision.tool_id),
                "label": str(decision.label),
                "command_family_id": str(decision.family_id),
                "danger_categories": ",".join(decision.danger_categories),
                "risk_tags": ",".join(decision.risk_tags),
                "requires_approval": "True" if decision.requires_approval else "False",
                "policy_decision": str(decision.policy_decision),
                "policy_reason": str(decision.policy_reason),
                "risk_summary": str(decision.risk_summary),
                "safer_alternative": str(decision.safer_alternative),
                "family_policy_state": str(decision.family_policy_state),
                "approved": "True" if approved else "False",
                "executed": "True" if executed else "False",
                "reason": str(reason),
                "rationale": str(decision.rationale),
                "approval_id": str(approval_id or ""),
            })
        self._emit_ui_invalidation("decisions")

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

    @staticmethod
    def _normalize_restore_compare_path(path: str) -> str:
        token = str(path or "").strip()
        if not token:
            return ""
        normalized = os.path.normpath(token.replace("\\", "/"))
        if normalized == ".":
            return ""
        return normalized.rstrip("/")

    @classmethod
    def _looks_like_absolute_path(cls, value: str) -> bool:
        token = cls._normalize_restore_compare_path(value)
        if not token:
            return False
        return bool(token.startswith("/") or re.match(r"^[A-Za-z]:/", token))

    @classmethod
    def _path_tail(cls, path: str, depth: int = 2) -> str:
        token = cls._normalize_restore_compare_path(path)
        if not token:
            return ""
        parts = [part for part in token.split("/") if part]
        return "/".join(parts[-max(1, int(depth or 2)):])

    @classmethod
    def _build_restore_root_mappings(
            cls,
            *,
            manifest: Dict[str, Any],
            project_path: str,
            output_folder: str,
            running_folder: str,
    ) -> List[Tuple[str, str]]:
        candidates: List[Tuple[str, str]] = []
        old_output_folder = str(manifest.get("output_folder", "") or "").strip()
        old_running_folder = str(manifest.get("running_folder", "") or "").strip()
        for old_root, new_root in (
                (old_output_folder, output_folder),
                (old_running_folder, running_folder),
        ):
            old_norm = cls._normalize_restore_compare_path(old_root)
            new_norm = cls._normalize_restore_compare_path(os.path.abspath(str(new_root or "").strip()))
            if not old_norm or not new_norm:
                continue
            candidates.append((old_norm, new_norm))

        deduped: List[Tuple[str, str]] = []
        seen = set()
        for old_root, new_root in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
            key = (old_root, new_root)
            if key in seen:
                continue
            seen.add(key)
            deduped.append((old_root, new_root))
        return deduped

    @classmethod
    def _build_restore_text_replacements(cls, root_mappings: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        replacements: List[Tuple[str, str]] = []
        seen = set()
        for old_root, new_root in list(root_mappings or []):
            paired_variants = [
                (str(old_root or "").strip(), str(new_root or "").strip()),
                (
                    str(old_root or "").strip().replace("/", "\\"),
                    str(new_root or "").strip().replace("/", "\\"),
                ),
            ]
            for old_variant, new_variant in paired_variants:
                pair = (old_variant, new_variant)
                if not old_variant or pair in seen:
                    continue
                seen.add(pair)
                replacements.append(pair)
        replacements.sort(key=lambda item: len(item[0]), reverse=True)
        return replacements

    @classmethod
    def _replace_restore_roots_in_text(cls, value: str, text_replacements: List[Tuple[str, str]]) -> str:
        result = str(value or "")
        for old_root, new_root in list(text_replacements or []):
            if old_root and old_root in result:
                result = result.replace(old_root, new_root)
        return result

    @classmethod
    def _build_restore_basename_index(cls, roots: List[str]) -> Dict[str, List[str]]:
        index: Dict[str, List[str]] = {}
        for root in list(roots or []):
            normalized_root = os.path.abspath(str(root or "").strip())
            if not normalized_root or not os.path.isdir(normalized_root):
                continue
            for base, _dirs, files in os.walk(normalized_root):
                for file_name in files:
                    full_path = os.path.normpath(os.path.join(base, file_name)).replace("\\", "/")
                    key = str(file_name or "").strip().lower()
                    if not key:
                        continue
                    index.setdefault(key, [])
                    if full_path not in index[key]:
                        index[key].append(full_path)
        return index

    @classmethod
    def _match_rebased_candidate(cls, raw_value: str, candidates: List[str]) -> str:
        if not candidates:
            return str(raw_value or "")
        if len(candidates) == 1:
            return str(candidates[0])
        for depth in (3, 2):
            tail = cls._path_tail(raw_value, depth=depth)
            if not tail:
                continue
            matches = [candidate for candidate in list(candidates) if cls._path_tail(candidate, depth=depth) == tail]
            if len(matches) == 1:
                return str(matches[0])
        return str(raw_value or "")

    @classmethod
    def _rebase_restored_file_reference(
            cls,
            value: str,
            *,
            root_mappings: List[Tuple[str, str]],
            text_replacements: List[Tuple[str, str]],
            basename_index: Dict[str, List[str]],
    ) -> str:
        raw_value = str(value or "").strip()
        if not raw_value or raw_value.startswith("process_output:"):
            return raw_value
        if raw_value.startswith(("http://", "https://", "data:")):
            return raw_value

        replaced = cls._replace_restore_roots_in_text(raw_value, text_replacements)
        replaced_norm = cls._normalize_restore_compare_path(replaced)
        if replaced_norm and replaced != raw_value and cls._looks_like_absolute_path(replaced_norm):
            return replaced_norm

        normalized_raw = cls._normalize_restore_compare_path(raw_value)
        if not cls._looks_like_absolute_path(normalized_raw):
            return replaced if replaced != raw_value else raw_value

        basename = os.path.basename(normalized_raw)
        if not basename:
            return replaced if replaced != raw_value else raw_value

        candidates = basename_index.get(str(basename or "").strip().lower(), [])
        matched = cls._match_rebased_candidate(normalized_raw, candidates)
        return matched if matched != normalized_raw else (replaced if replaced != raw_value else raw_value)

    @classmethod
    def _rewrite_restored_json_value(
            cls,
            value: Any,
            *,
            root_mappings: List[Tuple[str, str]],
            text_replacements: List[Tuple[str, str]],
            basename_index: Dict[str, List[str]],
            key_name: str = "",
    ) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._rewrite_restored_json_value(
                    item,
                    root_mappings=root_mappings,
                    text_replacements=text_replacements,
                    basename_index=basename_index,
                    key_name=str(key or ""),
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                cls._rewrite_restored_json_value(
                    item,
                    root_mappings=root_mappings,
                    text_replacements=text_replacements,
                    basename_index=basename_index,
                    key_name=str(key_name or ""),
                )
                for item in value
            ]
        if not isinstance(value, str):
            return value

        key_token = str(key_name or "").strip().lower()
        if key_token in {
            "artifact_ref",
            "ref",
            "stdout_ref",
            "stderr_ref",
            "source_ref",
            "outputfile",
            "path",
            "screenshot_path",
        }:
            return cls._rebase_restored_file_reference(
                value,
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
        if key_token in {"command", "command_template", "evidence_refs"}:
            return cls._replace_restore_roots_in_text(value, text_replacements)

        replaced = cls._replace_restore_roots_in_text(value, text_replacements)
        if replaced != value:
            replaced_norm = cls._normalize_restore_compare_path(replaced)
            if replaced_norm and cls._looks_like_absolute_path(replaced_norm):
                return replaced_norm
            return replaced
        if cls._looks_like_absolute_path(value):
            return cls._rebase_restored_file_reference(
                value,
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
        return value

    @staticmethod
    def _sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> List[str]:
        try:
            rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        except Exception:
            return []
        return [str(row[1]) for row in rows if len(row) > 1]

    @classmethod
    def _rewrite_restored_json_text(
            cls,
            raw_json: Any,
            *,
            root_mappings: List[Tuple[str, str]],
            text_replacements: List[Tuple[str, str]],
            basename_index: Dict[str, List[str]],
    ) -> Any:
        token = str(raw_json or "").strip()
        if not token:
            return str(raw_json or "")
        try:
            parsed = json.loads(token)
        except Exception:
            return cls._replace_restore_roots_in_text(token, text_replacements)
        rewritten = cls._rewrite_restored_json_value(
            parsed,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        try:
            return json.dumps(rewritten, ensure_ascii=False)
        except Exception:
            return token

    @classmethod
    def _rewrite_sqlite_table_rows(
            cls,
            connection: sqlite3.Connection,
            table_name: str,
            column_modes: Dict[str, str],
            *,
            root_mappings: List[Tuple[str, str]],
            text_replacements: List[Tuple[str, str]],
            basename_index: Dict[str, List[str]],
    ) -> None:
        available_columns = set(cls._sqlite_table_columns(connection, table_name))
        target_columns = [column for column in list(column_modes or {}) if column in available_columns]
        if not target_columns:
            return
        quoted_columns = ", ".join(f'"{column}"' for column in target_columns)
        try:
            rows = connection.execute(f'SELECT rowid, {quoted_columns} FROM "{table_name}"').fetchall()
        except Exception:
            return

        for row in rows:
            rowid = row[0]
            updates: Dict[str, Any] = {}
            for index, column_name in enumerate(target_columns, start=1):
                original = row[index]
                mode = str(column_modes.get(column_name, "text") or "text").strip().lower()
                if mode == "json":
                    rewritten = cls._rewrite_restored_json_text(
                        original,
                        root_mappings=root_mappings,
                        text_replacements=text_replacements,
                        basename_index=basename_index,
                    )
                elif mode == "path":
                    rewritten = cls._rebase_restored_file_reference(
                        str(original or ""),
                        root_mappings=root_mappings,
                        text_replacements=text_replacements,
                        basename_index=basename_index,
                    )
                else:
                    rewritten = cls._replace_restore_roots_in_text(str(original or ""), text_replacements)
                if rewritten != original:
                    updates[column_name] = rewritten
            if not updates:
                continue
            assignments = ", ".join(f'"{column}" = ?' for column in updates)
            params = list(updates.values()) + [rowid]
            connection.execute(f'UPDATE "{table_name}" SET {assignments} WHERE rowid = ?', params)

    @classmethod
    def _rebase_restored_project_paths(
            cls,
            *,
            project_path: str,
            manifest: Dict[str, Any],
            output_folder: str,
            running_folder: str,
    ) -> None:
        root_mappings = cls._build_restore_root_mappings(
            manifest=manifest,
            project_path=project_path,
            output_folder=output_folder,
            running_folder=running_folder,
        )
        if not root_mappings:
            return
        text_replacements = cls._build_restore_text_replacements(root_mappings)
        basename_index = cls._build_restore_basename_index([output_folder, running_folder])
        connection = sqlite3.connect(str(project_path))
        try:
            cls._rewrite_sqlite_table_rows(
                connection,
                "process",
                {"outputfile": "path", "command": "text"},
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "scheduler_pending_approval",
                {"command_template": "text", "evidence_refs": "text"},
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "scheduler_execution_record",
                {
                    "stdout_ref": "path",
                    "stderr_ref": "path",
                    "artifact_refs_json": "json",
                    "observations_created_json": "json",
                    "graph_mutations_json": "json",
                },
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "scheduler_target_state",
                {
                    "technologies_json": "json",
                    "findings_json": "json",
                    "manual_tests_json": "json",
                    "service_inventory_json": "json",
                    "urls_json": "json",
                    "coverage_gaps_json": "json",
                    "attempted_actions_json": "json",
                    "credentials_json": "json",
                    "sessions_json": "json",
                    "screenshots_json": "json",
                    "artifacts_json": "json",
                    "raw_json": "json",
                },
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "scheduler_host_ai_state",
                {
                    "technologies_json": "json",
                    "findings_json": "json",
                    "manual_tests_json": "json",
                    "raw_json": "json",
                },
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "graph_node",
                {"source_ref": "path", "properties_json": "json"},
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "graph_edge",
                {"source_ref": "path", "properties_json": "json"},
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            cls._rewrite_sqlite_table_rows(
                connection,
                "graph_evidence_ref",
                {"evidence_ref": "text"},
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
            )
            connection.commit()
        finally:
            connection.close()

    def _attach_restored_running_folder_locked(self, running_folder: str) -> None:
        project = getattr(self.logic, "activeProject", None)
        if project is None:
            return
        restored_running_folder = os.path.abspath(str(running_folder or "").strip())
        if not restored_running_folder:
            return
        os.makedirs(restored_running_folder, exist_ok=True)
        current_running_folder = str(getattr(project.properties, "runningFolder", "") or "").strip()
        if current_running_folder and os.path.abspath(current_running_folder) != restored_running_folder:
            try:
                shutil.rmtree(current_running_folder, ignore_errors=True)
            except Exception:
                pass
        if hasattr(project.properties, "_replace"):
            project.properties = project.properties._replace(runningFolder=restored_running_folder)

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

    def _hosts(self, limit: Optional[int] = None, include_down: bool = False) -> List[Dict[str, Any]]:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return []

        repo_container = project.repositoryContainer
        host_repo = repo_container.hostRepository
        port_repo = repo_container.portRepository
        service_repo = getattr(repo_container, "serviceRepository", None)

        hosts = list(host_repo.getAllHostObjs())
        if not bool(include_down):
            hosts = [host for host in hosts if not self._host_is_down(getattr(host, "status", ""))]
        if limit is not None:
            try:
                normalized_limit = int(limit)
            except (TypeError, ValueError):
                normalized_limit = 0
            if normalized_limit > 0:
                hosts = hosts[:normalized_limit]
        return [self._build_workspace_host_row(host, port_repo, service_repo) for host in hosts]

    @staticmethod
    def _coerce_float(value: Any) -> Optional[float]:
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _format_duration_label(total_seconds: Any) -> str:
        try:
            parsed = int(float(total_seconds))
        except (TypeError, ValueError):
            return ""
        if parsed <= 0:
            return ""
        hours = parsed // 3600
        minutes = (parsed % 3600) // 60
        seconds = parsed % 60
        if hours > 0:
            return f"{hours}h {minutes:02d}m {seconds:02d}s"
        return f"{minutes}m {seconds:02d}s"

    @staticmethod
    def _normalize_progress_source_label(value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        lowered = raw.lower()
        if lowered == "nmap":
            return "Nmap"
        if lowered == "nuclei":
            return "Nuclei"
        return raw

    @classmethod
    def _build_process_progress_payload(
            cls,
            *,
            status: Any = "",
            percent: Any = "",
            estimated_remaining: Any = None,
            elapsed: Any = 0,
            progress_message: Any = "",
            progress_source: Any = "",
            progress_updated_at: Any = "",
    ) -> Dict[str, Any]:
        percent_numeric = cls._coerce_float(percent)
        percent_display = f"{percent_numeric:.1f}%" if percent_numeric is not None else ""
        eta_seconds = None
        try:
            if estimated_remaining not in ("", None):
                eta_seconds = max(0, int(float(estimated_remaining)))
        except (TypeError, ValueError):
            eta_seconds = None
        elapsed_seconds = None
        try:
            if elapsed not in ("", None):
                elapsed_seconds = max(0, int(float(elapsed)))
        except (TypeError, ValueError):
            elapsed_seconds = None
        message_text = str(progress_message or "").strip()
        source_text = cls._normalize_progress_source_label(progress_source)
        updated_at_text = str(progress_updated_at or "").strip()
        summary_parts = []
        if percent_display:
            summary_parts.append(percent_display)
        eta_label = cls._format_duration_label(eta_seconds)
        if eta_label:
            summary_parts.append(f"ETA {eta_label}")
        if message_text:
            summary_parts.append(message_text)
        elif elapsed_seconds and str(status or "").strip().lower() == "running":
            elapsed_label = cls._format_duration_label(elapsed_seconds)
            if elapsed_label:
                summary_parts.append(f"Elapsed {elapsed_label}")
        return {
            "active": bool(summary_parts or source_text or updated_at_text),
            "summary": " | ".join(summary_parts),
            "percent": f"{percent_numeric:.1f}" if percent_numeric is not None else "",
            "percent_display": percent_display,
            "estimated_remaining": eta_seconds,
            "estimated_remaining_display": eta_label,
            "elapsed": elapsed_seconds,
            "elapsed_display": cls._format_duration_label(elapsed_seconds),
            "message": message_text,
            "source": source_text,
            "updated_at": updated_at_text,
        }

    def _processes(self, limit: int = 75) -> List[Dict[str, Any]]:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return []

        self._ensure_process_tables()
        process_repo = project.repositoryContainer.processRepository
        rows = process_repo.getProcesses({}, showProcesses='True', sort='desc', ncol='id')
        trimmed = rows[:limit]
        results = []

        for row in trimmed:
            status = str(row.get("status", "") or "")
            status_lower = status.strip().lower()
            terminal = status_lower in {"finished", "crashed", "problem", "cancelled", "killed", "failed"}
            estimated_remaining = row.get("estimatedRemaining")
            if terminal:
                estimated_remaining = None

            percent_value = str(row.get("percent", "") or "")
            if status_lower == "finished":
                numeric = self._coerce_float(percent_value)
                if numeric is None or numeric <= 0.0:
                    percent_value = "100"

            elapsed_value = row.get("elapsed", 0)
            progress_message = row.get("progressMessage", "")
            progress_source = row.get("progressSource", "")
            progress_updated_at = row.get("progressUpdatedAt", "")

            results.append({
                "id": row.get("id", ""),
                "name": row.get("name", ""),
                "hostIp": row.get("hostIp", ""),
                "port": row.get("port", ""),
                "protocol": row.get("protocol", ""),
                "status": status,
                "startTime": row.get("startTime", ""),
                "elapsed": elapsed_value,
                "percent": percent_value,
                "estimatedRemaining": estimated_remaining,
                "progressMessage": progress_message,
                "progressSource": progress_source,
                "progressUpdatedAt": progress_updated_at,
                "progress": self._build_process_progress_payload(
                    status=status,
                    percent=percent_value,
                    estimated_remaining=estimated_remaining,
                    elapsed=elapsed_value,
                    progress_message=progress_message,
                    progress_source=progress_source,
                    progress_updated_at=progress_updated_at,
                ),
            })
        return results

    @staticmethod
    def _process_history_records(project, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        if not project:
            return []

        session = project.database.session()
        try:
            query = (
                "SELECT "
                "process.id AS id, "
                "COALESCE(process.pid, '') AS pid, "
                "COALESCE(process.display, '') AS display, "
                "COALESCE(process.name, '') AS name, "
                "COALESCE(process.tabTitle, '') AS tabTitle, "
                "COALESCE(process.hostIp, '') AS hostIp, "
                "COALESCE(process.port, '') AS port, "
                "COALESCE(process.protocol, '') AS protocol, "
                "COALESCE(process.command, '') AS command, "
                "COALESCE(process.startTime, '') AS startTime, "
                "COALESCE(process.endTime, '') AS endTime, "
                "process.estimatedRemaining AS estimatedRemaining, "
                "COALESCE(process.elapsed, 0) AS elapsed, "
                "COALESCE(process.outputfile, '') AS outputfile, "
                "COALESCE(process.status, '') AS status, "
                "COALESCE(process.closed, '') AS closed, "
                "COALESCE(process.percent, '') AS percent, "
                "COALESCE(process.progressMessage, '') AS progressMessage, "
                "COALESCE(process.progressSource, '') AS progressSource, "
                "COALESCE(process.progressUpdatedAt, '') AS progressUpdatedAt, "
                "CASE "
                "WHEN EXISTS ("
                "    SELECT 1 FROM process_output AS output "
                "    WHERE output.processId = process.id "
                "    AND COALESCE(output.output, '') != ''"
                ") THEN 1 ELSE 0 END AS hasOutput "
                "FROM process AS process "
                "ORDER BY process.id DESC"
            )
            params: Dict[str, Any] = {}
            if limit is not None:
                resolved_limit = max(1, int(limit or 0))
                query = f"{query} LIMIT :limit"
                params["limit"] = resolved_limit
            result = session.execute(text(query), params)
            rows = result.fetchall()
            keys = result.keys()
            records: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(zip(keys, row))
                item["startTimeUtc"] = WebRuntime._normalize_process_timestamp_to_utc(item.get("startTime", ""))
                item["endTimeUtc"] = WebRuntime._normalize_process_timestamp_to_utc(item.get("endTime", ""))
                item["progressUpdatedAtUtc"] = WebRuntime._normalize_process_timestamp_to_utc(item.get("progressUpdatedAt", ""))
                records.append(item)
            return records
        finally:
            session.close()

    @staticmethod
    def _normalize_process_timestamp_to_utc(value: Any) -> str:
        text_value = str(value or "").strip()
        if not text_value:
            return ""

        parsed: Optional[datetime.datetime] = None
        try:
            iso_candidate = f"{text_value[:-1]}+00:00" if text_value.endswith("Z") else text_value
            parsed = datetime.datetime.fromisoformat(iso_candidate)
        except ValueError:
            parsed = None

        if parsed is None:
            for fmt in ("%d %b %Y %H:%M:%S.%f", "%d %b %Y %H:%M:%S"):
                try:
                    parsed = datetime.datetime.strptime(text_value, fmt)
                    break
                except ValueError:
                    continue

        if parsed is None:
            return ""

        if parsed.tzinfo is None:
            local_tz = datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc
            parsed = parsed.replace(tzinfo=local_tz)

        return parsed.astimezone(datetime.timezone.utc).isoformat()

    @staticmethod
    def _sanitize_provider_config(provider_cfg: Dict[str, Any]) -> Dict[str, Any]:
        value = dict(provider_cfg)
        api_key = str(value.get("api_key", "") or "")
        value["api_key"] = ""
        value["api_key_configured"] = bool(api_key)
        return value

    def _scheduler_preferences(self) -> Dict[str, Any]:
        config = self.scheduler_config.load()
        engagement_policy = self._load_engagement_policy_locked(persist_if_missing=True)
        providers = config.get("providers", {})
        sanitized_providers = {}
        for name, provider_cfg in providers.items():
            sanitized_providers[name] = self._sanitize_provider_config(provider_cfg)
        return {
            "mode": config.get("mode", "deterministic"),
            "available_modes": ["deterministic", "ai"],
            "goal_profile": str(engagement_policy.get("legacy_goal_profile", config.get("goal_profile", "internal_asset_discovery"))),
            "goal_profiles": [
                {"id": "internal_asset_discovery", "name": "Internal Asset Discovery"},
                {"id": "external_pentest", "name": "External Pentest"},
            ],
            "engagement_policy": engagement_policy,
            "engagement_presets": list_engagement_presets(),
            "provider": config.get("provider", "none"),
            "max_concurrency": self._scheduler_max_concurrency(config),
            "max_host_concurrency": self._scheduler_max_host_concurrency(config),
            "max_jobs": self._scheduler_max_jobs(config),
            "job_workers": int(getattr(self.jobs, "worker_count", 1) or 1),
            "job_max": int(getattr(self.jobs, "max_jobs", 200) or 200),
            "providers": sanitized_providers,
            "feature_flags": self.scheduler_config.get_feature_flags(),
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
        ensure_scheduler_engagement_policy_table(project.database)
        ensure_scan_submission_table(project.database)

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
            def _ensure_column(table_name: str, column_name: str, column_type: str):
                rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
                existing = {str(row[1]) for row in rows if len(row) > 1}
                if str(column_name) in existing:
                    return
                session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))

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
                "percent TEXT,"
                "progressMessage TEXT,"
                "progressSource TEXT,"
                "progressUpdatedAt TEXT"
                ")"
            ))
            session.execute(text(
                "CREATE TABLE IF NOT EXISTS process_output ("
                "processId INTEGER,"
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "output TEXT"
                ")"
            ))
            for column_name, column_type in (
                    ("progressMessage", "TEXT"),
                    ("progressSource", "TEXT"),
                    ("progressUpdatedAt", "TEXT"),
            ):
                _ensure_column("process", column_name, column_type)
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
        raw = row.get("raw", {}) if isinstance(row.get("raw", {}), dict) else {}
        stored_technologies = row.get("technologies", [])
        stored_findings = row.get("findings", [])
        manual_tests = row.get("manual_tests", [])
        reflection = raw.get("reflection", {}) if isinstance(raw.get("reflection", {}), dict) else {}
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
            "reflection": reflection,
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
            screenshot_path = os.path.join(screenshot_dir, filename)
            metadata = load_screenshot_metadata(screenshot_path)
            row = {
                "filename": filename,
                "artifact_ref": f"/api/screenshots/{filename}",
                "port": str(metadata.get("port", "") or port or ""),
                "url": f"/api/screenshots/{filename}",
            }
            for field in ("target_url", "capture_engine", "capture_reason", "captured_at", "service_name", "hostname"):
                value = str(metadata.get(field, "") or "").strip()
                if value:
                    row[field] = value
            rows.append(row)
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

    def _runner_type_for_tool(self, tool_id: str, command_template: str = "") -> str:
        normalized_tool = str(tool_id or "").strip().lower()
        if not normalized_tool and not str(command_template or "").strip():
            return "local"
        try:
            registry = SchedulerPlanner.build_action_registry(self._get_settings(), dangerous_categories=[])
            spec = registry.get_by_tool_id(normalized_tool)
            if spec is not None and str(getattr(spec, "runner_type", "") or "").strip():
                return str(spec.runner_type).strip().lower()
        except Exception:
            pass
        if normalized_tool in {"screenshooter", "x11screen"}:
            return "browser"
        if normalized_tool in {"responder", "ntlmrelayx"}:
            return "manual"
        text = " ".join([normalized_tool, str(command_template or "")]).lower()
        if any(token in text for token in ("manual", "operator", "clipboard")):
            return "manual"
        return "local"

    def _runner_type_for_approval_item(self, item: Optional[Dict[str, Any]]) -> str:
        payload = item if isinstance(item, dict) else {}
        return self._runner_type_for_tool(
            str(payload.get("tool_id", "") or ""),
            str(payload.get("command_template", "") or ""),
        )

    def _hostname_for_ip(self, host_ip: str) -> str:
        try:
            project = self._require_active_project()
            host_repo = getattr(getattr(project, "repositoryContainer", None), "hostRepository", None)
            host_obj = host_repo.getHostByIP(str(host_ip)) if host_repo else None
            return str(getattr(host_obj, "hostname", "") or "")
        except Exception:
            return ""

    def _service_name_for_target(self, host_ip: str, port: str, protocol: str) -> str:
        try:
            project = self._require_active_project()
            host_repo = getattr(getattr(project, "repositoryContainer", None), "hostRepository", None)
            host_obj = host_repo.getHostByIP(str(host_ip)) if host_repo else None
            host_id = int(getattr(host_obj, "id", 0) or 0)
            if host_id <= 0:
                return ""

            session = project.database.session()
            try:
                result = session.execute(text(
                    "SELECT COALESCE(s.name, '') "
                    "FROM portObj AS p "
                    "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                    "WHERE p.hostId = :host_id "
                    "AND COALESCE(p.portId, '') = :port "
                    "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                    "ORDER BY p.id DESC LIMIT 1"
                ), {
                    "host_id": host_id,
                    "port": str(port or ""),
                    "protocol": str(protocol or "tcp"),
                }).fetchone()
                return str(result[0] or "") if result else ""
            finally:
                session.close()
        except Exception:
            return ""

    @staticmethod
    def _normalize_command_signature_source(command_text: str) -> str:
        normalized = str(command_text or "").strip().lower()
        if not normalized:
            return ""
        replacements = (
            (r"(?i)(-oA\s+)(?:\"[^\"]+\"|'[^']+'|\S+)", r"\1[OUTPUT]"),
            (r"(?i)(-o\s+)(?:\"[^\"]+\"|'[^']+'|\S+)", r"\1[OUTPUT]"),
            (r"(?i)(--output(?:-dir)?\s+)(?:\"[^\"]+\"|'[^']+'|\S+)", r"\1[OUTPUT]"),
            (r"(?i)(--resume\s+)(?:\"[^\"]+\"|'[^']+'|\S+)", r"\1[OUTPUT]"),
            (r"(?i)(>\s*)(?:\"[^\"]+\"|'[^']+'|\S+)", r"\1[OUTPUT]"),
        )
        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)
        normalized = re.sub(r"\s{2,}", " ", normalized).strip()
        return normalized

    def _command_signature_for_target(self, command_text: str, protocol: str) -> str:
        normalized = self._normalize_command_signature_source(command_text)
        if not normalized:
            return ""
        return SchedulerPlanner._command_signature(str(protocol or "tcp"), normalized)

    @staticmethod
    def _target_attempt_matches(item: Dict[str, Any], port: str, protocol: str) -> bool:
        entry_port = str(item.get("port", "") or "").strip()
        entry_protocol = str(item.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
        target_port = str(port or "").strip()
        target_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        if entry_port and target_port and entry_port != target_port:
            return False
        return entry_protocol == target_protocol

    def _build_command(
            self,
            template: str,
            host_ip: str,
            port: str,
            protocol: str,
            tool_id: str,
            service_name: str = "",
    ) -> Tuple[str, str]:
        project = self._require_active_project()
        running_folder = project.properties.runningFolder
        outputfile = os.path.join(running_folder, f"{getTimestamp()}-{tool_id}-{host_ip}-{port}")
        outputfile = os.path.normpath(outputfile).replace("\\", "/")

        command = str(template or "")
        normalized_tool = str(tool_id or "").strip().lower()
        resolved_service_name = str(service_name or "").strip() or self._service_name_for_target(host_ip, port, protocol)
        if normalized_tool == "banner":
            command = AppSettings._ensure_banner_command(command)
        if normalized_tool == "nuclei-web":
            command = AppSettings._ensure_nuclei_auto_scan(command)
        elif "nuclei" in normalized_tool or "nuclei" in str(command).lower():
            command = AppSettings._ensure_nuclei_command(command, automatic_scan=False)
        if str(tool_id or "").strip().lower() == "web-content-discovery":
            command = AppSettings._ensure_web_content_discovery_command(command)
        if normalized_tool == "httpx":
            command = AppSettings._ensure_httpx_command(command)
        if normalized_tool == "nikto":
            command = AppSettings._ensure_nikto_command(command)
        if normalized_tool == "wpscan":
            command = AppSettings._ensure_wpscan_command(command)
        if "wapiti" in str(command).lower():
            normalized_tool = str(tool_id or "").strip().lower()
            scheme = "https" if "https-wapiti" in normalized_tool else "http"
            command = AppSettings._ensure_wapiti_command(command, scheme=scheme)
        command = AppSettings._canonicalize_web_target_placeholders(command)
        if "nmap" in str(command).lower():
            command = AppSettings._ensure_nmap_stats_every(command)
        command, target_host = apply_preferred_target_placeholders(
            command,
            hostname=self._hostname_for_ip(host_ip),
            ip=str(host_ip),
            port=str(port),
            output=outputfile,
            service_name=resolved_service_name,
        )
        command = AppSettings._collapse_redundant_fallbacks(command)
        command = AppSettings._ensure_nmap_hostname_target_support(command, target_host)
        command = AppSettings._ensure_nmap_output_argument(command, outputfile)
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
    def _contains_nmap_verbose(args: List[str]) -> bool:
        for token in args:
            value = str(token or "").strip().lower()
            if value in {"-v", "-vv", "-vvv", "--verbose"}:
                return True
        return False

    @staticmethod
    def _append_nmap_stats_every(args: List[str], interval: str = "15s") -> List[str]:
        values = [str(item) for item in list(args or [])]
        if not WebRuntime._contains_nmap_stats_every(values):
            values = values + ["--stats-every", str(interval or "15s")]
        if WebRuntime._contains_nmap_stats_every(values) and not WebRuntime._contains_nmap_verbose(values):
            values = values + ["-vv"]
        return values

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
    def _summarize_scan_scope(targets: List[str]) -> str:
        subnets: List[str] = []
        hosts: List[str] = []
        ranges: List[str] = []
        domains: List[str] = []
        for item in list(targets or []):
            token = str(item or "").strip()
            if not token:
                continue
            if "/" in token:
                try:
                    subnet = str(ipaddress.ip_network(token, strict=False))
                except ValueError:
                    subnet = ""
                if subnet and subnet not in subnets:
                    subnets.append(subnet)
                    continue
            if "-" in token and token not in ranges:
                ranges.append(token)
                continue
            try:
                host_value = str(ipaddress.ip_address(token))
            except ValueError:
                host_value = ""
            if host_value:
                if host_value not in hosts:
                    hosts.append(host_value)
                continue
            if token not in domains:
                domains.append(token)

        parts: List[str] = []
        if subnets:
            parts.append(f"subnets: {', '.join(subnets[:4])}" + (" ..." if len(subnets) > 4 else ""))
        if ranges:
            parts.append(f"ranges: {', '.join(ranges[:3])}" + (" ..." if len(ranges) > 3 else ""))
        if hosts:
            host_summary = ", ".join(hosts[:4])
            if len(hosts) > 4:
                host_summary = f"{host_summary} ... ({len(hosts)} hosts)"
            parts.append(f"hosts: {host_summary}")
        if domains:
            parts.append(f"domains: {', '.join(domains[:4])}" + (" ..." if len(domains) > 4 else ""))
        return " | ".join(parts[:4])

    def _record_scan_submission(
            self,
            *,
            submission_kind: str,
            job_id: int,
            targets: Optional[List[str]] = None,
            source_path: str = "",
            discovery: bool = False,
            staged: bool = False,
            run_actions: bool = False,
            nmap_path: str = "",
            nmap_args: str = "",
            scan_mode: str = "",
            scan_options: Optional[Dict[str, Any]] = None,
            result_summary: str = "",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if project is None:
                return None
            ensure_scan_submission_table(project.database)
            normalized_targets = [str(item or "").strip() for item in list(targets or []) if str(item or "").strip()]
            record = record_scan_submission(project.database, {
                "job_id": str(int(job_id or 0) or ""),
                "submission_kind": str(submission_kind or ""),
                "status": "submitted",
                "target_summary": self._compact_targets(normalized_targets),
                "scope_summary": self._summarize_scan_scope(normalized_targets),
                "targets": normalized_targets,
                "source_path": str(source_path or ""),
                "scan_mode": str(scan_mode or ""),
                "discovery": bool(discovery),
                "staged": bool(staged),
                "run_actions": bool(run_actions),
                "nmap_path": str(nmap_path or ""),
                "nmap_args": str(nmap_args or ""),
                "scan_options": dict(scan_options or {}),
                "result_summary": str(result_summary or ""),
            })
        self._emit_ui_invalidation("scan_history")
        return record

    def _update_scan_submission_status(
            self,
            *,
            job_id: int,
            status: str,
            result_summary: str = "",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            project = getattr(self.logic, "activeProject", None)
            if project is None:
                return None
            ensure_scan_submission_table(project.database)
            record = update_scan_submission(
                project.database,
                job_id=int(job_id or 0),
                status=str(status or ""),
                result_summary=str(result_summary or ""),
            )
        self._emit_ui_invalidation("scan_history")
        return record

    @staticmethod
    def _record_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return bool(default)
        if isinstance(value, bool):
            return value
        text_value = str(value or "").strip().lower()
        if text_value in {"1", "true", "yes", "on"}:
            return True
        if text_value in {"0", "false", "no", "off"}:
            return False
        return bool(default)

    @staticmethod
    def _normalize_subnet_target(subnet: str) -> str:
        token = str(subnet or "").strip()
        if not token:
            raise ValueError("Subnet is required.")
        try:
            return str(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid subnet: {token}") from exc

    @staticmethod
    def _scan_history_targets(record: Dict[str, Any]) -> List[str]:
        if isinstance(record.get("targets"), list):
            values = [str(item or "").strip() for item in list(record.get("targets", [])) if str(item or "").strip()]
            if values:
                return values
        raw_targets = str(record.get("targets_json", "") or "").strip()
        if raw_targets:
            try:
                parsed = json.loads(raw_targets)
            except Exception:
                parsed = []
            if isinstance(parsed, list):
                values = [str(item or "").strip() for item in parsed if str(item or "").strip()]
                if values:
                    return values
        fallback: List[str] = []
        for source in (record.get("scope_summary", ""), record.get("target_summary", "")):
            for token in re.findall(r"[A-Za-z0-9./:-]+", str(source or "")):
                cleaned = str(token or "").strip(",:")
                if cleaned and cleaned not in fallback:
                    fallback.append(cleaned)
        return fallback

    @classmethod
    def _scan_target_match_score_for_subnet(cls, target: Any, subnet: str) -> int:
        token = str(target or "").strip().strip(",")
        if not token:
            return -1
        subnet_network = ipaddress.ip_network(str(subnet), strict=False)
        try:
            target_ip = ipaddress.ip_address(token)
            return 50 if target_ip in subnet_network else -1
        except ValueError:
            pass
        try:
            target_network = ipaddress.ip_network(token, strict=False)
            if target_network == subnet_network:
                return 100
            if subnet_network.subnet_of(target_network):
                return 90
            if target_network.subnet_of(subnet_network):
                return 80
            if target_network.overlaps(subnet_network):
                return 70
            return -1
        except ValueError:
            pass
        return -1

    @classmethod
    def _best_scan_submission_for_subnet(cls, subnet: str, records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        best_record: Optional[Dict[str, Any]] = None
        best_score = -1
        for record in list(records or []):
            if str(record.get("submission_kind", "") or "").strip() != "nmap_scan":
                continue
            score = -1
            for target in cls._scan_history_targets(record):
                score = max(score, cls._scan_target_match_score_for_subnet(target, subnet))
            if score > best_score:
                best_record = record
                best_score = score
        return best_record if best_score >= 0 else None

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

    @staticmethod
    def _is_nuclei_command(tool_name: str, command: str) -> bool:
        name = str(tool_name or "").strip().lower()
        if name.startswith("nuclei"):
            return True
        command_text = str(command or "").strip().lower()
        return " nuclei " in f" {command_text} " or command_text.startswith("nuclei ")

    @classmethod
    def _process_progress_adapter_for_command(cls, tool_name: str, command: str) -> str:
        if cls._is_nmap_command(tool_name, command):
            return "nmap"
        if cls._is_nuclei_command(tool_name, command):
            return "nuclei"
        return ""

    @staticmethod
    def _estimate_remaining_from_percent(runtime_seconds: float, percent: Optional[float]) -> Optional[int]:
        try:
            elapsed = max(0.0, float(runtime_seconds or 0.0))
        except (TypeError, ValueError):
            elapsed = 0.0
        if elapsed <= 0.0 or percent is None:
            return None
        bounded = max(0.0, min(float(percent), 100.0))
        if bounded <= 0.0 or bounded >= 100.0:
            return None
        fraction = bounded / 100.0
        total = elapsed / fraction
        return max(0, int(total - elapsed))

    @staticmethod
    def _extract_progress_line(text: str, predicate) -> str:
        cleaned = _ANSI_ESCAPE_RE.sub("", str(text or ""))
        for raw_line in reversed(cleaned.splitlines()):
            line = str(raw_line or "").strip()
            if line and predicate(line):
                return line[:240]
        return ""

    @classmethod
    def _extract_nmap_progress_message(cls, text: str) -> str:
        return cls._extract_progress_line(
            text,
            lambda line: bool(
                _NMAP_PROGRESS_PERCENT_RE.search(line)
                or _NMAP_PROGRESS_PERCENT_ATTR_RE.search(line)
                or _NMAP_PROGRESS_REMAINING_PAREN_RE.search(line)
                or _NMAP_PROGRESS_REMAINING_ATTR_RE.search(line)
            ),
        )

    @classmethod
    def _extract_nuclei_progress_from_text(
            cls,
            text: str,
            runtime_seconds: float,
    ) -> Tuple[Optional[float], Optional[int], str]:
        cleaned = _ANSI_ESCAPE_RE.sub("", str(text or ""))
        if not cleaned:
            return None, None, ""

        for raw_line in reversed(cleaned.splitlines()):
            line = str(raw_line or "").strip()
            if not line or "requests:" not in line.lower():
                continue
            requests_match = _NUCLEI_PROGRESS_REQUESTS_RE.search(line)
            if not requests_match:
                continue
            try:
                completed = int(requests_match.group(1))
                total = int(requests_match.group(2))
            except Exception:
                continue
            percent = None
            percent_group = requests_match.group(3)
            if percent_group not in (None, ""):
                try:
                    percent = float(percent_group)
                except Exception:
                    percent = None
            if percent is None and total > 0:
                percent = max(0.0, min((float(completed) / float(total)) * 100.0, 100.0))

            elapsed_seconds = runtime_seconds
            elapsed_match = _NUCLEI_PROGRESS_ELAPSED_RE.search(line)
            if elapsed_match:
                parsed_elapsed = cls._parse_duration_seconds(elapsed_match.group(1))
                if parsed_elapsed is not None:
                    elapsed_seconds = float(parsed_elapsed)
            remaining = cls._estimate_remaining_from_percent(elapsed_seconds, percent)

            parts = [f"Requests {completed}/{total}"]
            rps_match = _NUCLEI_PROGRESS_RPS_RE.search(line)
            if rps_match:
                parts.append(f"RPS {rps_match.group(1)}")
            matched_match = _NUCLEI_PROGRESS_MATCHED_RE.search(line)
            if matched_match:
                parts.append(f"Matches {matched_match.group(1)}")
            errors_match = _NUCLEI_PROGRESS_ERRORS_RE.search(line)
            if errors_match:
                parts.append(f"Errors {errors_match.group(1)}")
            return percent, remaining, " | ".join(parts)[:240]
        return None, None, ""

    def _update_process_progress(
            self,
            process_repo,
            *,
            process_id: int,
            tool_name: str,
            command: str,
            text_chunk: str,
            runtime_seconds: float,
            state: Dict[str, Any],
    ):
        adapter = str(state.get("adapter", "") or "").strip().lower()
        if not adapter:
            return

        raw_chunk = str(text_chunk or "")
        percent = None
        remaining = None
        message = ""
        source = adapter
        clear_remaining_on_partial = False

        if adapter == "nmap":
            percent, remaining = self._extract_nmap_progress_from_text(raw_chunk)
            message = self._extract_nmap_progress_message(raw_chunk)
            clear_remaining_on_partial = bool(
                (_NMAP_PROGRESS_PERCENT_RE.search(raw_chunk) or _NMAP_PROGRESS_PERCENT_ATTR_RE.search(raw_chunk))
                and not (_NMAP_PROGRESS_REMAINING_PAREN_RE.search(raw_chunk) or _NMAP_PROGRESS_REMAINING_ATTR_RE.search(raw_chunk))
            )
        elif adapter == "nuclei":
            percent, remaining, message = self._extract_nuclei_progress_from_text(
                raw_chunk,
                runtime_seconds=runtime_seconds,
            )
        else:
            return

        if percent is None and remaining is None and not message:
            return

        changed = False
        percent_value = state.get("percent")
        remaining_value = state.get("remaining")
        message_value = str(state.get("message", "") or "")
        source_value = str(state.get("source", "") or "")

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
        elif clear_remaining_on_partial and remaining_value is not None:
            remaining_value = None
            state["remaining"] = None
            changed = True

        if message:
            if message != message_value:
                message_value = message
                state["message"] = message
                changed = True

        if source != source_value:
            source_value = source
            state["source"] = source
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
                progress_message=message_value,
                progress_source=source_value,
                progress_updated_at=getTimestamp(True),
            )
            state["updated_at"] = now
            self._emit_ui_invalidation("processes", throttle_seconds=5.0)
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
