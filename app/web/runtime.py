import datetime
import ipaddress
import json
import mimetypes
import os
import re
import shlex
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import text

from app.hostsfile import add_temporary_host_alias, registrable_root_domain
from app.httputil.isHttps import isHttps
from app.nmap_enrichment import (
    infer_hostname_from_nmap_data,
    infer_os_from_service_inventory,
    infer_os_from_nmap_scripts,
    is_unknown_hostname,
    is_unknown_os_match,
)
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
from app.scheduler.graph import rebuild_evidence_graph
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
    build_target_urls,
    ensure_scheduler_target_state_table,
    get_target_state,
    upsert_target_state,
)
from app.scheduler.scan_history import list_scan_submissions
from app.screenshot_metadata import (
    build_screenshot_state_row,
    load_screenshot_metadata,
)
from app.scheduler.config import (
    SchedulerConfigManager,
    normalize_device_categories,
)
from app.scheduler.planner import ScheduledAction, SchedulerPlanner
from app.scheduler.providers import (
    determine_scheduler_phase,
    get_provider_logs,
    reflect_on_scheduler_progress,
    test_provider_connection,
)
from app.screenshot_targets import (
    apply_preferred_target_placeholders,
)
from app.settings import AppSettings, Settings
from app.timing import getTimestamp
from app.tooling import (
    audit_legion_tools,
    build_tool_install_plan,
    detect_supported_tool_install_platform,
    execute_tool_install_plan,
    normalize_tool_install_platform,
    tool_audit_summary,
)
from app.web import runtime_artifacts as web_runtime_artifacts
from app.web import runtime_credential_capture as web_runtime_credential_capture
from app.web import runtime_execution as web_runtime_execution
from app.web import runtime_graph as web_runtime_graph
from app.web import runtime_processes as web_runtime_processes
from app.web import runtime_projects as web_runtime_projects
from app.web import runtime_reports as web_runtime_reports
from app.web import runtime_scheduler as web_runtime_scheduler
from app.web import runtime_scans as web_runtime_scans
from app.web import runtime_screenshots as web_runtime_screenshots
from app.web import runtime_status as web_runtime_status
from app.web import runtime_tools as web_runtime_tools
from app.web import runtime_workspace as web_runtime_workspace
from app.web.jobs import WebJobManager
from db.entities.host import hostObj


_NMAP_PROGRESS_PERCENT_RE = re.compile(r"About\s+([0-9]+(?:\.[0-9]+)?)%\s+done", flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_PAREN_RE = re.compile(r"\(([^)]*?)\s+remaining\)", flags=re.IGNORECASE)
_NMAP_PROGRESS_PERCENT_ATTR_RE = re.compile(r'percent=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_ATTR_RE = re.compile(r'remaining=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NUCLEI_PROGRESS_ELAPSED_RE = re.compile(r"^\[([0-9:]+)\]", flags=re.IGNORECASE)
_TSHARK_DURATION_RE = re.compile(r"\bduration:(\d+)\b", flags=re.IGNORECASE)
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
    "true",
    "false",
    "truncated",
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
    INTERNAL_QUICK_RECON_TCP_PORTS = "80,81,88,111,135,139,443,445,515,591,593,623,631,2049,8000,8008,8010,8080,8081,8088,8443,8888,9000,9090,9100,9443,10443"
    RFC1918_COMPREHENSIVE_TCP_PORTS = "22,25,53,80,81,88,110,111,123,135,139,143,389,443,445,465,500,515,587,591,593,623,631,636,993,995,1025,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5672,5900,5985,5986,6379,7001,8000,8008,8010,8080,8081,8088,8443,8888,9000,9090,9100,9200,9443,10443,27017"
    RFC1918_SWEEP_CHUNK_PREFIX = 24
    RFC1918_SWEEP_BATCH_SIZE = 2
    RFC1918_SWEEP_MAX_CONCURRENCY = 4
    _COMMAND_SECRET_PATTERNS = (
        re.compile(
            r"(?P<prefix>\b(?:[A-Z][A-Z0-9_]*API_KEY|[A-Z][A-Z0-9_]*TOKEN|AUTHORIZATION)=)"
            r"(?P<value>(?:'[^']*'|\"[^\"]*\"|[^\s;&|)]+))"
        ),
        re.compile(
            r"(?P<prefix>\B--api-key\s+)(?P<value>(?:'[^']*'|\"[^\"]*\"|[^\s;&|)]+))",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?P<prefix>\B--?(?:access-)?token\s+)(?P<value>(?:'[^']*'|\"[^\"]*\"|[^\s;&|)]+))",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+\\/-]+)",
            re.IGNORECASE,
        ),
    )

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
        if job_type in {
            "nmap-scan",
            "import-nmap-xml",
            "scheduler-run",
            "scheduler-approval-execute",
            "scheduler-dig-deeper",
            "tool-run",
            "process-retry",
            "credential-capture-session",
        }:
            channels.add("processes")
        if job_type in {"credential-capture-session"}:
            channels.add("credential_capture")
        if job_type in {"nmap-scan", "import-nmap-xml", "project-restore-zip"}:
            channels.update({"scan_history", "hosts", "services", "graph"})
        self._emit_ui_invalidation(*sorted(channels))

    def get_workspace_overview(self) -> Dict[str, Any]:
        return web_runtime_workspace.get_workspace_overview(self)

    def get_workspace_processes(self, limit: int = 75) -> List[Dict[str, Any]]:
        return web_runtime_status.get_workspace_processes(self, limit=limit)

    def get_snapshot(self) -> Dict[str, Any]:
        return web_runtime_status.get_snapshot(self)

    def get_scheduler_preferences(self) -> Dict[str, Any]:
        return web_runtime_scheduler.get_scheduler_preferences(self)

    def get_credential_capture_state(self, *, include_captures: bool = False) -> Dict[str, Any]:
        with self._lock:
            return web_runtime_credential_capture.credential_capture_state_locked(
                self,
                include_captures=include_captures,
            )

    def get_workspace_credential_captures(self, limit: Optional[int] = None) -> Dict[str, Any]:
        return web_runtime_credential_capture.get_workspace_credential_captures(self, limit=limit)

    @staticmethod
    def _merge_engagement_policy_payload(
            current_policy: Optional[Dict[str, Any]],
            updates: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return web_runtime_scheduler.merge_engagement_policy_payload(current_policy, updates)

    def _load_engagement_policy_locked(self, *, persist_if_missing: bool = True) -> Dict[str, Any]:
        return web_runtime_scheduler.load_engagement_policy_locked(self, persist_if_missing=persist_if_missing)

    def get_engagement_policy(self) -> Dict[str, Any]:
        return web_runtime_scheduler.get_engagement_policy(self)

    def set_engagement_policy(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_scheduler.set_engagement_policy(self, updates)

    def apply_scheduler_preferences(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_scheduler.apply_scheduler_preferences(self, updates)

    def test_scheduler_provider(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_scheduler.test_scheduler_provider(self, updates)

    def get_scheduler_provider_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.get_scheduler_provider_logs(self, limit=limit)

    def get_scheduler_decisions(self, limit: int = 80) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.get_scheduler_decisions(self, limit=limit)

    def get_scheduler_approvals(self, limit: int = 200, status: Optional[str] = None) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.get_scheduler_approvals(self, limit=limit, status=status)

    def _scheduler_family_policy_metadata(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return web_runtime_scheduler.scheduler_family_policy_metadata(self, item)

    def _apply_family_policy_action(self, item: Dict[str, Any], family_action: str, *, reason: str = "") -> str:
        return web_runtime_scheduler.apply_family_policy_action(
            self,
            item,
            family_action,
            reason=reason,
        )

    def get_scheduler_execution_records(self, limit: int = 200) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.get_scheduler_execution_records(self, limit=limit)

    def get_scheduler_rationale_feed(self, limit: int = 18) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.get_scheduler_rationale_feed(self, limit=limit)

    def _scheduler_rationale_feed_locked(self, limit: int = 18) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.scheduler_rationale_feed_locked(self, limit=limit)

    @staticmethod
    def _safe_json_loads(value: Any) -> Any:
        return web_runtime_scheduler.safe_json_loads(value)

    @staticmethod
    def _dedupe_text_tokens(values: Any, *, limit: int = 12) -> List[str]:
        return web_runtime_scheduler.dedupe_text_tokens(values, limit=limit)

    @staticmethod
    def _truncate_rationale_text(value: Any, max_chars: int = 180) -> str:
        return web_runtime_scheduler.truncate_rationale_text(value, max_chars=max_chars)

    @classmethod
    def _scheduler_event_timestamp_epoch(cls, value: Any) -> float:
        return web_runtime_scheduler.scheduler_event_timestamp_epoch(cls, value)

    @staticmethod
    def _strip_json_fences(value: Any) -> str:
        return web_runtime_scheduler.strip_json_fences(value)

    @classmethod
    def _extract_prompt_text_from_provider_request(cls, request_body: Any) -> str:
        return web_runtime_scheduler.extract_prompt_text_from_provider_request(cls, request_body)

    @staticmethod
    def _extract_scheduler_target_fields_from_prompt(prompt_text: Any) -> Dict[str, str]:
        return web_runtime_scheduler.extract_scheduler_target_fields_from_prompt(prompt_text)

    @classmethod
    def _extract_provider_response_payload(cls, response_body: Any) -> Dict[str, Any]:
        return web_runtime_scheduler.extract_provider_response_payload(cls, response_body)

    @staticmethod
    def _rationale_list_text(values: Any, *, limit: int = 6) -> str:
        return web_runtime_scheduler.rationale_list_text(values, limit=limit)

    @staticmethod
    def _rationale_tag_label(value: Any) -> str:
        return web_runtime_scheduler.rationale_tag_label(value)

    @classmethod
    def _index_scheduler_rows_by_target_tool(
            cls,
            rows: List[Dict[str, Any]],
            *,
            timestamp_field: str,
    ) -> Dict[Tuple[str, str, str, str], List[Dict[str, Any]]]:
        return web_runtime_scheduler.index_scheduler_rows_by_target_tool(
            cls,
            rows,
            timestamp_field=timestamp_field,
        )

    @staticmethod
    def _nearest_scheduler_row(rows: List[Dict[str, Any]], event_ts: float) -> Optional[Dict[str, Any]]:
        return web_runtime_scheduler.nearest_scheduler_row(rows, event_ts)

    @classmethod
    def _manual_test_lines(cls, manual_tests: Any, *, limit: int = 2) -> List[str]:
        return web_runtime_scheduler.manual_test_lines(cls, manual_tests, limit=limit)

    @classmethod
    def _findings_line(cls, findings: Any) -> str:
        return web_runtime_scheduler.findings_line(cls, findings)

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
        return web_runtime_scheduler.match_rationale_outcomes(
            cls,
            decision_index,
            execution_index,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            tool_ids=tool_ids,
            event_ts=event_ts,
        )

    @classmethod
    def _build_provider_rationale_entry(
            cls,
            log_row: Dict[str, Any],
            *,
            decision_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
            execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        return web_runtime_scheduler.build_provider_rationale_entry(
            cls,
            log_row,
            decision_index=decision_index,
            execution_index=execution_index,
        )

    @classmethod
    def _build_audit_rationale_entry(
            cls,
            decision_row: Dict[str, Any],
            *,
            execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        return web_runtime_scheduler.build_audit_rationale_entry(
            cls,
            decision_row,
            execution_index=execution_index,
        )

    @classmethod
    def _build_scheduler_rationale_feed_items(
            cls,
            provider_logs: List[Dict[str, Any]],
            decisions: List[Dict[str, Any]],
            executions: List[Dict[str, Any]],
            *,
            limit: int = 18,
    ) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.build_scheduler_rationale_feed_items(
            cls,
            provider_logs,
            decisions,
            executions,
            limit=limit,
        )

    def get_scan_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.get_scan_history(self, limit=limit)

    @staticmethod
    def _project_listing_row(path: str, *, source: str, current_path: str = "") -> Dict[str, Any]:
        return web_runtime_projects.project_listing_row(
            path,
            source=source,
            current_path=current_path,
        )

    def list_projects(self, limit: int = 500) -> List[Dict[str, Any]]:
        return web_runtime_projects.list_projects(self, limit=limit)

    def _serialize_plan_step_preview(self, step: ScheduledAction) -> Dict[str, Any]:
        return web_runtime_scheduler.serialize_plan_step_preview(step)

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
        return web_runtime_scheduler.get_scheduler_plan_preview(
            self,
            host_id=host_id,
            host_ip=host_ip,
            service=service,
            port=port,
            protocol=protocol,
            mode=mode,
            limit_targets=limit_targets,
            limit_actions=limit_actions,
        )

    def get_target_state_view(self, host_id: int = 0, limit: int = 500) -> Dict[str, Any]:
        return web_runtime_workspace.get_target_state_view(self, host_id=host_id, limit=limit)

    def get_findings(self, host_id: int = 0, limit_hosts: int = 500, limit_findings: int = 1000) -> Dict[str, Any]:
        return web_runtime_workspace.get_findings(
            self,
            host_id=host_id,
            limit_hosts=limit_hosts,
            limit_findings=limit_findings,
        )

    @staticmethod
    def _read_text_excerpt(path: str, max_chars: int = 4000) -> str:
        return web_runtime_scheduler.read_text_excerpt(path, max_chars=max_chars)

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
        return web_runtime_scheduler.get_scheduler_execution_traces(
            self,
            limit=limit,
            host_id=host_id,
            host_ip=host_ip,
            tool_id=tool_id,
            include_output=include_output,
            output_max_chars=output_max_chars,
        )

    def get_scheduler_execution_trace(self, execution_id: str, output_max_chars: int = 4000) -> Dict[str, Any]:
        return web_runtime_scheduler.get_scheduler_execution_trace(
            self,
            execution_id,
            output_max_chars=output_max_chars,
        )

    def get_evidence_graph(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_graph.get_evidence_graph(self, filters)

    @staticmethod
    def _path_within(base_path: str, candidate_path: str) -> bool:
        return web_runtime_artifacts.path_within(base_path, candidate_path)

    def _is_project_artifact_path(self, project, path: str) -> bool:
        return web_runtime_artifacts.is_project_artifact_path(self, project, path)

    def _get_graph_snapshot_locked(self) -> Dict[str, Any]:
        return web_runtime_graph.get_graph_snapshot_locked(self)

    def get_graph_related_content(self, node_id: str, *, max_chars: int = 12000) -> Dict[str, Any]:
        return web_runtime_graph.get_graph_related_content(self, node_id, max_chars=max_chars)

    def get_graph_content(self, node_id: str, *, download: bool = False, max_chars: int = 12000) -> Dict[str, Any]:
        return web_runtime_graph.get_graph_content(self, node_id, download=download, max_chars=max_chars)

    def rebuild_evidence_graph(self, host_id: Optional[int] = None) -> Dict[str, Any]:
        return web_runtime_graph.rebuild_evidence_graph_for_runtime(self, host_id)

    def export_evidence_graph_json(self, *, rebuild: bool = False) -> Dict[str, Any]:
        return web_runtime_graph.export_evidence_graph_json_for_runtime(self, rebuild=rebuild)

    def export_evidence_graph_graphml(self, *, rebuild: bool = False) -> str:
        return web_runtime_graph.export_evidence_graph_graphml_for_runtime(self, rebuild=rebuild)

    def get_evidence_graph_layouts(self) -> List[Dict[str, Any]]:
        return web_runtime_graph.get_evidence_graph_layouts(self)

    def save_evidence_graph_layout(
            self,
            *,
            view_id: str,
            name: str,
            layout_state: Dict[str, Any],
            layout_id: str = "",
    ) -> Dict[str, Any]:
        return web_runtime_graph.save_evidence_graph_layout(
            self,
            view_id=view_id,
            name=name,
            layout_state=layout_state,
            layout_id=layout_id,
        )

    def get_evidence_graph_annotations(self, *, target_ref: str = "", target_kind: str = "") -> List[Dict[str, Any]]:
        return web_runtime_graph.get_evidence_graph_annotations(self, target_ref=target_ref, target_kind=target_kind)

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
        return web_runtime_graph.save_evidence_graph_annotation(
            self,
            target_kind=target_kind,
            target_ref=target_ref,
            body=body,
            created_by=created_by,
            source_ref=source_ref,
            annotation_id=annotation_id,
        )

    @staticmethod
    def _collect_command_artifacts(outputfile: str) -> List[str]:
        return web_runtime_artifacts.collect_command_artifacts(outputfile)

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
        return web_runtime_scheduler.persist_scheduler_execution_record(
            self,
            decision,
            execution_record,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            service_name=service_name,
        )

    def approve_scheduler_approval(
            self,
            approval_id: int,
            approve_family: bool = False,
            run_now: bool = True,
            family_action: str = "",
    ):
        return web_runtime_scheduler.approve_scheduler_approval(
            self,
            approval_id,
            approve_family=approve_family,
            run_now=run_now,
            family_action=family_action,
            ensure_scheduler_approval_table_fn=ensure_scheduler_approval_table,
            get_pending_approval_fn=get_pending_approval,
            update_pending_approval_fn=update_pending_approval,
            update_scheduler_decision_for_approval_fn=update_scheduler_decision_for_approval,
        )

    def reject_scheduler_approval(self, approval_id: int, reason: str = "rejected via web", family_action: str = ""):
        return web_runtime_scheduler.reject_scheduler_approval(
            self,
            approval_id,
            reason=reason,
            family_action=family_action,
            ensure_scheduler_approval_table_fn=ensure_scheduler_approval_table,
            get_pending_approval_fn=get_pending_approval,
            update_pending_approval_fn=update_pending_approval,
            update_scheduler_decision_for_approval_fn=update_scheduler_decision_for_approval,
        )

    def get_project_details(self) -> Dict[str, Any]:
        return web_runtime_projects.get_project_details(self)

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
        return web_runtime_scheduler.scheduler_tool_audit_snapshot(self)

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
        return web_runtime_processes.register_job_process(self, job_id, process_id)

    def _unregister_job_process(self, process_id: int):
        return web_runtime_processes.unregister_job_process(self, process_id)

    def _job_active_process_ids(self, job_id: int) -> List[int]:
        return web_runtime_processes.job_active_process_ids(self, job_id)

    def create_new_temporary_project(self) -> Dict[str, Any]:
        return web_runtime_projects.create_new_temporary_project(self)

    def open_project(self, path: str) -> Dict[str, Any]:
        return web_runtime_projects.open_project(self, path)

    def start_save_project_as_job(self, path: str, replace: bool = True) -> Dict[str, Any]:
        return web_runtime_projects.start_save_project_as_job(self, path, replace=replace)

    def save_project_as(self, path: str, replace: bool = True) -> Dict[str, Any]:
        return web_runtime_projects.save_project_as(self, path, replace=replace)

    def build_project_bundle_zip(self) -> Tuple[str, str]:
        return web_runtime_projects.build_project_bundle_zip(self)

    def start_restore_project_zip_job(self, path: str) -> Dict[str, Any]:
        return web_runtime_projects.start_restore_project_zip_job(self, path)

    def restore_project_bundle_zip(self, path: str) -> Dict[str, Any]:
        return web_runtime_projects.restore_project_bundle_zip(self, path)

    def _restore_project_bundle_zip_job(self, zip_path: str, cleanup_source: bool) -> Dict[str, Any]:
        return web_runtime_projects.restore_project_bundle_zip_job(
            self,
            zip_path,
            cleanup_source=cleanup_source,
        )

    def _restore_project_bundle_zip(self, zip_path: str) -> Dict[str, Any]:
        return web_runtime_projects.restore_project_bundle_zip_impl(self, zip_path)

    def _save_project_as(self, project_path: str, replace: bool = True) -> Dict[str, Any]:
        return web_runtime_projects.save_project_as_impl(self, project_path, replace=replace)

    def _count_running_scan_jobs(self, include_queued: bool = True) -> int:
        return web_runtime_projects.count_running_scan_jobs(self, include_queued=include_queued)

    def _has_running_autosave_job(self) -> bool:
        return web_runtime_projects.has_running_autosave_job(self)

    def _get_autosave_interval_seconds(self) -> int:
        return web_runtime_projects.get_autosave_interval_seconds(self)

    def _resolve_autosave_target_path(self, project) -> str:
        return web_runtime_projects.resolve_autosave_target_path(project)

    def _run_project_autosave(self, target_path: str) -> Dict[str, Any]:
        return web_runtime_projects.run_project_autosave(self, target_path)

    def _maybe_schedule_autosave_locked(self):
        return web_runtime_projects.maybe_schedule_autosave_locked(self)

    def start_targets_import_job(self, path: str) -> Dict[str, Any]:
        return web_runtime_scans.start_targets_import_job(self, path)

    def start_nmap_xml_import_job(self, path: str, run_actions: bool = False) -> Dict[str, Any]:
        return web_runtime_scans.start_nmap_xml_import_job(self, path, run_actions=run_actions)

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
        return web_runtime_scans.start_nmap_scan_job(
            self,
            targets,
            discovery=discovery,
            staged=staged,
            run_actions=run_actions,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            scan_mode=scan_mode,
            scan_options=scan_options,
        )

    def start_scheduler_run_job(self) -> Dict[str, Any]:
        return web_runtime_scheduler.start_scheduler_run_job(self)

    def run_governed_discovery(self, target: str, *, run_actions: bool = False) -> Dict[str, Any]:
        return web_runtime_scans.run_governed_discovery(
            self,
            target,
            run_actions=run_actions,
        )

    def start_host_rescan_job(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_scans.start_host_rescan_job(self, host_id)

    def start_subnet_rescan_job(self, subnet: str) -> Dict[str, Any]:
        return web_runtime_scans.start_subnet_rescan_job(self, subnet)

    @classmethod
    def _apply_engagement_scan_profile(
            cls,
            scan_options: Dict[str, Any],
            *,
            engagement_policy: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = dict(scan_options or {})
        preset = str((engagement_policy or {}).get("preset", "") or "").strip().lower()
        if preset == "internal_quick_recon":
            options["explicit_ports"] = cls.INTERNAL_QUICK_RECON_TCP_PORTS
            options["top_ports"] = 0
        return options

    @staticmethod
    def _preferred_capture_interface_sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
        return web_runtime_scans.preferred_capture_interface_sort_key(item)

    def list_capture_interfaces(self) -> List[Dict[str, Any]]:
        return web_runtime_scans.list_capture_interfaces(self)

    def get_capture_interface_inventory(self) -> Dict[str, Any]:
        return web_runtime_scans.get_capture_interface_inventory(self)

    def start_passive_capture_scan_job(
            self,
            *,
            interface_name: str,
            duration_minutes: int,
            run_actions: bool = False,
    ) -> Dict[str, Any]:
        return web_runtime_scans.start_passive_capture_scan_job(
            self,
            interface_name=interface_name,
            duration_minutes=duration_minutes,
            run_actions=run_actions,
        )

    def start_host_dig_deeper_job(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_scheduler.start_host_dig_deeper_job(self, host_id)

    def start_host_screenshot_refresh_job(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_screenshots.start_host_screenshot_refresh_job(self, host_id)

    def start_graph_screenshot_refresh_job(self, host_id: int, port: str, protocol: str = "tcp") -> Dict[str, Any]:
        return web_runtime_screenshots.start_graph_screenshot_refresh_job(
            self,
            host_id,
            port,
            protocol=protocol,
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
        return web_runtime_artifacts.delete_graph_screenshot(
            self,
            host_id=host_id,
            artifact_ref=artifact_ref,
            filename=filename,
            port=port,
            protocol=protocol,
        )

    @staticmethod
    def _host_target_item_matches_port(item: Any, port: str, protocol: str) -> bool:
        return web_runtime_artifacts.host_target_item_matches_port(item, port, protocol)

    def _delete_project_artifact_refs(self, project, *, screenshots: List[Dict[str, Any]], artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        return web_runtime_artifacts.delete_project_artifact_refs(
            self,
            project,
            screenshots=screenshots,
            artifacts=artifacts,
        )

    def _prune_target_state_for_port(self, *, project, host_id: int, host_ip: str, hostname: str, port: str, protocol: str) -> Dict[str, Any]:
        return web_runtime_artifacts.prune_target_state_for_port(
            self,
            project=project,
            host_id=host_id,
            host_ip=host_ip,
            hostname=hostname,
            port=port,
            protocol=protocol,
        )

    def delete_workspace_port(self, *, host_id: int, port: str, protocol: str = "tcp") -> Dict[str, Any]:
        return web_runtime_artifacts.delete_workspace_port(
            self,
            host_id=host_id,
            port=port,
            protocol=protocol,
        )

    def delete_workspace_service(
            self,
            *,
            host_id: int,
            port: str,
            protocol: str = "tcp",
            service: str = "",
    ) -> Dict[str, Any]:
        return web_runtime_artifacts.delete_workspace_service(
            self,
            host_id=host_id,
            port=port,
            protocol=protocol,
            service=service,
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
        return web_runtime_tools.start_tool_run_job(
            self,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            tool_id=tool_id,
            command_override=command_override,
            timeout=timeout,
        )

    @staticmethod
    def _host_is_down(status: Any) -> bool:
        return web_runtime_workspace.host_is_down(status)

    @staticmethod
    def _workspace_host_services(port_rows: List[Any], service_repo: Any) -> List[str]:
        return web_runtime_workspace.workspace_host_services(None, port_rows, service_repo)

    def _resolve_host_device_categories(
            self,
            project: Any,
            host: Any,
            *,
            target_state: Optional[Dict[str, Any]] = None,
            service_inventory: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        return web_runtime_workspace.resolve_host_device_categories(
            self,
            project,
            host,
            target_state=target_state,
            service_inventory=service_inventory,
        )

    def _build_workspace_host_row(self, host: Any, port_repo: Any, service_repo: Any, project: Any) -> Dict[str, Any]:
        return web_runtime_workspace.build_workspace_host_row(self, host, port_repo, service_repo, project)

    def get_workspace_hosts(
            self,
            limit: Optional[int] = None,
            include_down: bool = False,
            service: str = "",
            category: str = "",
    ) -> List[Dict[str, Any]]:
        return web_runtime_workspace.get_workspace_hosts(
            self,
            limit=limit,
            include_down=include_down,
            service=service,
            category=category,
        )

    def get_workspace_services(self, limit: int = 300, host_id: int = 0, category: str = "") -> List[Dict[str, Any]]:
        return web_runtime_workspace.get_workspace_services(self, limit=limit, host_id=host_id, category=category)

    def _workspace_tools_rows(self, service: str = "") -> List[Dict[str, Any]]:
        return web_runtime_tools.workspace_tools_rows(self, service=service)

    def get_workspace_tool_targets(
            self,
            *,
            host_id: int = 0,
            service: str = "",
            limit: int = 500,
    ) -> List[Dict[str, Any]]:
        return web_runtime_tools.get_workspace_tool_targets(
            self,
            host_id=host_id,
            service=service,
            limit=limit,
        )

    def get_workspace_tools_page(
            self,
            service: str = "",
            limit: int = 300,
            offset: int = 0,
    ) -> Dict[str, Any]:
        return web_runtime_tools.get_workspace_tools_page(
            self,
            service=service,
            limit=limit,
            offset=offset,
        )

    def get_workspace_tools(self, service: str = "", limit: int = 300, offset: int = 0) -> List[Dict[str, Any]]:
        return web_runtime_tools.get_workspace_tools(
            self,
            service=service,
            limit=limit,
            offset=offset,
        )

    @staticmethod
    def _strip_nmap_preamble(output_text: str) -> str:
        return web_runtime_workspace.strip_nmap_preamble(output_text)

    @classmethod
    def _host_detail_script_preview(cls, script_id: str, output_text: str, max_chars: int = 220) -> str:
        return web_runtime_workspace.host_detail_script_preview(
            script_id,
            output_text,
            max_chars=max_chars,
        )

    def get_host_workspace(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_workspace.get_host_workspace(self, host_id)

    def get_host_ai_report(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_reports.get_host_ai_report(self, host_id)

    def render_host_ai_report_markdown(self, report: Dict[str, Any]) -> str:
        return web_runtime_reports.render_host_ai_report_markdown(report)

    def get_host_report(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_reports.get_host_report(self, host_id)

    def render_host_report_markdown(self, report: Dict[str, Any]) -> str:
        return web_runtime_reports.render_host_report_markdown(report)

    def build_host_ai_reports_zip(self) -> Tuple[str, str]:
        return web_runtime_reports.build_host_ai_reports_zip(self)

    def get_project_ai_report(self) -> Dict[str, Any]:
        return web_runtime_reports.get_project_ai_report(self)

    def render_project_ai_report_markdown(self, report: Dict[str, Any]) -> str:
        return web_runtime_reports.render_project_ai_report_markdown(report)

    def get_project_report(self) -> Dict[str, Any]:
        return web_runtime_reports.get_project_report(self)

    def render_project_report_markdown(self, report: Dict[str, Any]) -> str:
        return web_runtime_reports.render_project_report_markdown(report)

    def _push_project_report_common(
            self,
            *,
            report: Dict[str, Any],
            markdown_renderer,
            overrides: Optional[Dict[str, Any]] = None,
            report_label: str = "project report",
    ) -> Dict[str, Any]:
        return web_runtime_reports.push_project_report_common(
            self,
            report=report,
            markdown_renderer=markdown_renderer,
            overrides=overrides,
            report_label=report_label,
        )

    def push_project_ai_report(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_reports.push_project_ai_report(self, overrides=overrides)

    def push_project_report(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_reports.push_project_report(self, overrides=overrides)

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
        return web_runtime_workspace.update_host_note(self, host_id, text_value)

    def update_host_categories(
            self,
            host_id: int,
            *,
            manual_categories: Any = None,
            override_auto: bool = False,
    ) -> Dict[str, Any]:
        return web_runtime_workspace.update_host_categories(
            self,
            host_id,
            manual_categories=manual_categories,
            override_auto=override_auto,
        )

    def delete_host_workspace(self, host_id: int) -> Dict[str, Any]:
        return web_runtime_workspace.delete_host_workspace(self, host_id)

    def create_script_entry(
            self,
            host_id: int,
            port: str,
            protocol: str,
            script_id: str,
            output: str,
    ) -> Dict[str, Any]:
        return web_runtime_workspace.create_script_entry(self, host_id, port, protocol, script_id, output)

    def delete_script_entry(self, script_db_id: int) -> Dict[str, Any]:
        return web_runtime_workspace.delete_script_entry(self, script_db_id)

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
        return web_runtime_workspace.create_cve_entry(
            self,
            host_id,
            name,
            url=url,
            severity=severity,
            source=source,
            product=product,
            version=version,
            exploit_id=exploit_id,
            exploit=exploit,
            exploit_url=exploit_url,
        )

    def delete_cve_entry(self, cve_id: int) -> Dict[str, Any]:
        return web_runtime_workspace.delete_cve_entry(self, cve_id)

    def start_process_retry_job(self, process_id: int, timeout: int = 300) -> Dict[str, Any]:
        return web_runtime_processes.start_process_retry_job(self, process_id, timeout=timeout)

    def retry_process(self, process_id: int, timeout: int = 300, job_id: int = 0) -> Dict[str, Any]:
        return web_runtime_processes.retry_process(self, process_id, timeout=timeout, job_id=job_id)

    def _build_process_retry_plan(
            self,
            *,
            tool_name: str,
            host_ip: str,
            port: str,
            protocol: str,
    ) -> Dict[str, Any]:
        return web_runtime_processes.build_process_retry_plan(
            self,
            tool_name=tool_name,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
        )

    @staticmethod
    def _split_process_retry_targets(value: str) -> List[str]:
        return web_runtime_processes.split_process_retry_targets(value)

    @staticmethod
    def _signal_process_tree(proc: Optional[subprocess.Popen], *, force: bool = False):
        return web_runtime_processes.signal_process_tree(proc, force=force)

    def kill_process(self, process_id: int) -> Dict[str, Any]:
        return web_runtime_processes.kill_process(self, process_id)

    def clear_processes(self, reset_all: bool = False) -> Dict[str, Any]:
        return web_runtime_processes.clear_processes(self, reset_all=reset_all)

    def close_process(self, process_id: int) -> Dict[str, Any]:
        return web_runtime_processes.close_process(self, process_id)

    def get_process_output(self, process_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
        return web_runtime_processes.get_process_output(self, process_id, offset=offset, max_chars=max_chars)

    def get_script_output(self, script_db_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
        return web_runtime_workspace.get_script_output(self, script_db_id, offset=offset, max_chars=max_chars)

    def get_screenshot_file(self, filename: str) -> str:
        return web_runtime_artifacts.get_screenshot_file(self, filename)

    def list_jobs(self, limit: int = 80) -> List[Dict[str, Any]]:
        return web_runtime_processes.list_jobs(self, limit=limit)

    def get_job(self, job_id: int) -> Dict[str, Any]:
        return web_runtime_processes.get_job(self, job_id)

    def stop_job(self, job_id: int) -> Dict[str, Any]:
        return web_runtime_processes.stop_job(self, job_id)

    def _import_targets_from_file(self, file_path: str) -> Dict[str, Any]:
        return web_runtime_scans.import_targets_from_file(self, file_path)

    def _import_discovered_hosts_into_project(self, discovered_hosts: List[str]) -> List[str]:
        return web_runtime_scans.import_discovered_hosts_into_project(self, discovered_hosts)

    def _queue_discovered_host_followup_scan(self, targets: List[str]) -> Dict[str, Any]:
        return web_runtime_scans.queue_discovered_host_followup_scan(self, targets)

    def _resolve_host_by_token(self, host_token: str):
        return web_runtime_scans.resolve_host_by_token(self, host_token)

    def _mark_discovered_host_origin(self, host_tokens: List[str], *, source_tool_id: str = ""):
        return web_runtime_scans.mark_discovered_host_origin(
            self,
            host_tokens,
            source_tool_id=source_tool_id,
        )

    def start_httpx_bootstrap_job(self, targets: List[str]) -> Dict[str, Any]:
        return web_runtime_scans.start_httpx_bootstrap_job(self, targets)

    @staticmethod
    def _httpx_bootstrap_command(targets_file: str, output_prefix: str) -> str:
        return web_runtime_scans.httpx_bootstrap_command(targets_file, output_prefix)

    def _materialize_httpx_urls_as_web_targets(
            self,
            *,
            host_id: int,
            host_ip: str,
            hostname: str,
            host_token: str,
            observed_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        return web_runtime_scans.materialize_httpx_urls_as_web_targets(
            self,
            host_id=host_id,
            host_ip=host_ip,
            hostname=hostname,
            host_token=host_token,
            observed_payload=observed_payload,
        )

    def _run_httpx_bootstrap(self, targets: List[str], *, job_id: int = 0) -> Dict[str, Any]:
        return web_runtime_scans.run_httpx_bootstrap(self, targets, job_id=job_id)

    def _ingest_discovered_hosts(self, discovered_hosts: List[str], *, source_tool_id: str = "") -> Dict[str, Any]:
        return web_runtime_scans.ingest_discovered_hosts(
            self,
            discovered_hosts,
            source_tool_id=source_tool_id,
        )

    def _import_nmap_xml(self, xml_path: str, run_actions: bool = False, job_id: int = 0) -> Dict[str, Any]:
        return web_runtime_scans.import_nmap_xml(
            self,
            xml_path,
            run_actions=run_actions,
            job_id=job_id,
        )

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
        return web_runtime_scans.run_nmap_scan_and_import(
            self,
            targets,
            discovery=discovery,
            staged=staged,
            run_actions=run_actions,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            scan_mode=scan_mode,
            scan_options=scan_options,
            job_id=job_id,
        )

    def _run_rfc1918_chunked_scan_and_import(
            self,
            *,
            targets: List[str],
            discovery: bool,
            run_actions: bool,
            nmap_path: str,
            nmap_args: str,
            scan_options: Dict[str, Any],
            job_id: int,
            output_prefix: str,
            host_count_before: int,
    ) -> Dict[str, Any]:
        return web_runtime_scans.run_rfc1918_chunked_scan_and_import(
            self,
            targets=targets,
            discovery=discovery,
            run_actions=run_actions,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            scan_options=scan_options,
            job_id=job_id,
            output_prefix=output_prefix,
            host_count_before=host_count_before,
        )

    def _connected_ipv4_networks_for_interface(self, interface_name: str) -> List[ipaddress.IPv4Network]:
        return web_runtime_scans.connected_ipv4_networks_for_interface(self, interface_name)

    @staticmethod
    def _passive_capture_filter() -> str:
        return web_runtime_scans.passive_capture_filter()

    @staticmethod
    def _parse_tshark_field_blob(value: str) -> List[str]:
        return web_runtime_scans.parse_tshark_field_blob(value)

    @staticmethod
    def _classify_passive_protocols(protocol_blob: str, udp_ports: List[str], query_name: str) -> Set[str]:
        return web_runtime_scans.classify_passive_protocols(protocol_blob, udp_ports, query_name)

    def _analyze_passive_capture(
            self,
            *,
            interface_name: str,
            capture_path: str,
            analysis_path: str,
    ) -> Dict[str, Any]:
        return web_runtime_scans.analyze_passive_capture(
            self,
            interface_name=interface_name,
            capture_path=capture_path,
            analysis_path=analysis_path,
        )

    def _run_passive_capture_scan(
            self,
            *,
            interface_name: str,
            duration_minutes: int,
            run_actions: bool,
            job_id: int = 0,
    ) -> Dict[str, Any]:
        return web_runtime_scans.run_passive_capture_scan(
            self,
            interface_name=interface_name,
            duration_minutes=duration_minutes,
            run_actions=run_actions,
            job_id=job_id,
        )

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
        return web_runtime_tools.run_manual_tool(
            self,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            tool_id=tool_id,
            command_override=command_override,
            timeout=timeout,
            job_id=job_id,
        )

    def _run_scheduler_actions_web(
            self,
            *,
            host_ids: Optional[set] = None,
            dig_deeper: bool = False,
            job_id: int = 0,
    ) -> Dict[str, Any]:
        return web_runtime_scheduler.run_scheduler_actions_web(
            self,
            host_ids=host_ids,
            dig_deeper=dig_deeper,
            job_id=job_id,
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
        return web_runtime_scheduler.run_scheduler_targets(
            self,
            settings=settings,
            targets=targets,
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

    @staticmethod
    def _group_scheduler_targets_by_host(targets) -> List[List[Any]]:
        return web_runtime_scheduler.group_scheduler_targets_by_host(targets)

    @staticmethod
    def _merge_scheduler_run_summaries(
            summaries: Optional[List[Dict[str, Any]]] = None,
            *,
            target_count: int = 0,
            dig_deeper: bool = False,
    ) -> Dict[str, Any]:
        return web_runtime_scheduler.merge_scheduler_run_summaries(
            summaries,
            target_count=target_count,
            dig_deeper=dig_deeper,
        )

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
        return web_runtime_scheduler.scheduler_max_concurrency(preferences)

    @staticmethod
    def _scheduler_max_host_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
        return web_runtime_scheduler.scheduler_max_host_concurrency(preferences)

    @staticmethod
    def _scheduler_max_jobs(preferences: Optional[Dict[str, Any]] = None) -> int:
        return web_runtime_scheduler.scheduler_max_jobs(preferences)

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
        return web_runtime_scheduler.execute_scheduler_task_batch(
            self,
            tasks,
            max_concurrency=max_concurrency,
        )

    def _execute_scheduler_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return web_runtime_scheduler.execute_scheduler_task(self, task)

    @staticmethod
    def _scheduler_feedback_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_scheduler.scheduler_feedback_config(preferences)

    @staticmethod
    def _is_host_scoped_scheduler_tool(tool_id: str) -> bool:
        return web_runtime_scheduler.is_host_scoped_scheduler_tool(tool_id)

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
                    if not isinstance(item, dict):
                        continue
                    tool = str(item.get("tool_id", "") or "").strip().lower()
                    if not (
                            self._target_attempt_matches(item, port, protocol)
                            or self._is_host_scoped_scheduler_tool(tool)
                    ):
                        continue
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

                if str(host_ip or "").strip():
                    host_process_result = session.execute(text(
                        "SELECT COALESCE(p.name, '') AS tool_id, "
                        "COALESCE(p.command, '') AS command_text "
                        "FROM process AS p "
                        "WHERE COALESCE(p.hostIp, '') = :host_ip "
                        "ORDER BY p.id DESC LIMIT 200"
                    ), {
                        "host_ip": str(host_ip or ""),
                    })
                    for row in host_process_result.fetchall():
                        tool = str(row[0] or "").strip().lower()
                        if not self._is_host_scoped_scheduler_tool(tool):
                            continue
                        attempted["tool_ids"].add(tool)
                        command_signature = self._command_signature_for_target(str(row[1] or ""), protocol)
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

                if str(host_ip or "").strip():
                    host_approval_result = session.execute(text(
                        "SELECT COALESCE(tool_id, '') AS tool_id, "
                        "COALESCE(command_template, '') AS command_template, "
                        "COALESCE(command_family_id, '') AS command_family_id "
                        "FROM scheduler_pending_approval "
                        "WHERE COALESCE(host_ip, '') = :host_ip "
                        "AND LOWER(COALESCE(status, '')) IN ('pending', 'approved', 'running', 'executed') "
                        "ORDER BY id DESC LIMIT 120"
                    ), {
                        "host_ip": str(host_ip or ""),
                    })
                    for row in host_approval_result.fetchall():
                        tool = str(row[0] or "").strip().lower()
                        if not self._is_host_scoped_scheduler_tool(tool):
                            continue
                        command_template = str(row[1] or "")
                        family_id = str(row[2] or "").strip().lower()
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
            engagement_preset: str = "",
            attempted_tool_ids: set,
            attempted_family_ids: Optional[set] = None,
            attempted_command_signatures: Optional[set] = None,
            recent_output_chars: int,
            analysis_mode: str = "standard",
    ) -> Dict[str, Any]:
        return web_runtime_scheduler.build_scheduler_target_context(
            self,
            host_id=host_id,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            service_name=service_name,
            goal_profile=goal_profile,
            engagement_preset=engagement_preset,
            attempted_tool_ids=attempted_tool_ids,
            attempted_family_ids=attempted_family_ids,
            attempted_command_signatures=attempted_command_signatures,
            recent_output_chars=recent_output_chars,
            analysis_mode=analysis_mode,
        )

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
        return web_runtime_scheduler.build_scheduler_context_summary(
            target=target,
            analysis_mode=analysis_mode,
            coverage=coverage,
            signals=signals,
            current_phase=current_phase,
            attempted_tool_ids=attempted_tool_ids,
            attempted_family_ids=attempted_family_ids,
            summary_technologies=summary_technologies,
            host_cves=host_cves,
            host_ai_state=host_ai_state,
            recent_processes=recent_processes,
            target_recent_processes=target_recent_processes,
        )

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
        return web_runtime_scheduler.build_scheduler_coverage_summary(
            service_name=service_name,
            signals=signals,
            observed_tool_ids=observed_tool_ids,
            host_cves=host_cves,
            inferred_technologies=inferred_technologies,
            analysis_mode=analysis_mode,
        )

    @staticmethod
    def _scheduler_banner_from_evidence(source_id: Any, text_value: Any) -> str:
        return web_runtime_scheduler.scheduler_banner_from_evidence(source_id, text_value)

    @staticmethod
    def _scheduler_service_banner_fallback(*, service_name: str, product: str, version: str, extrainfo: str) -> str:
        return web_runtime_scheduler.scheduler_service_banner_fallback(
            service_name=service_name,
            product=product,
            version=version,
            extrainfo=extrainfo,
        )

    @staticmethod
    def _truncate_scheduler_text(value: Any, max_chars: int) -> str:
        return web_runtime_scheduler.truncate_scheduler_text(value, max_chars)

    @staticmethod
    def _scheduler_output_lines(value: Any, *, max_line_chars: int = 240, max_lines: int = 320) -> List[str]:
        return web_runtime_scheduler.scheduler_output_lines(
            value,
            max_line_chars=max_line_chars,
            max_lines=max_lines,
        )

    @staticmethod
    def _scheduler_line_signal_score(value: Any) -> int:
        return web_runtime_scheduler.scheduler_line_signal_score(value)

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
        return web_runtime_scheduler.build_scheduler_excerpt(
            value,
            max_chars,
            multiline=multiline,
            head_lines=head_lines,
            signal_lines=signal_lines,
            tail_lines=tail_lines,
            max_line_chars=max_line_chars,
        )

    @classmethod
    def _build_scheduler_prompt_excerpt(cls, value: Any, max_chars: int) -> str:
        return web_runtime_scheduler.build_scheduler_prompt_excerpt(value, max_chars)

    @classmethod
    def _build_scheduler_analysis_excerpt(cls, value: Any, max_chars: int) -> str:
        return web_runtime_scheduler.build_scheduler_analysis_excerpt(value, max_chars)

    @staticmethod
    def _scheduler_tool_alias_tokens(tool_id: Any) -> Set[str]:
        return web_runtime_scheduler.scheduler_tool_alias_tokens(tool_id)

    @staticmethod
    def _extract_unavailable_tool_tokens(text: Any) -> Set[str]:
        return web_runtime_scheduler.extract_unavailable_tool_tokens(text)

    @staticmethod
    def _extract_missing_nse_script_tokens(text: Any) -> Set[str]:
        return web_runtime_scheduler.extract_missing_nse_script_tokens(text)

    @staticmethod
    def _looks_like_local_tool_dependency_failure(text: Any) -> bool:
        return web_runtime_scheduler.looks_like_local_tool_dependency_failure(text)

    def _extract_scheduler_signals(
            self,
            *,
            service_name: str,
            scripts: List[Dict[str, Any]],
            recent_processes: List[Dict[str, Any]],
            target: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return web_runtime_scheduler.extract_scheduler_signals(
            self,
            service_name=service_name,
            scripts=scripts,
            recent_processes=recent_processes,
            target=target,
        )

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
    def _is_placeholder_scheduler_text(value: Any) -> bool:
        return web_runtime_scheduler.is_placeholder_scheduler_text(value)

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
        return web_runtime_scheduler.infer_technologies_from_observations(
            self,
            service_records=service_records,
            script_records=script_records,
            process_records=process_records,
            limit=limit,
        )

    def _infer_host_technologies(self, project, host_id: int, host_ip: str = "") -> List[Dict[str, str]]:
        return web_runtime_scheduler.infer_host_technologies(self, project, host_id, host_ip)

    def _normalize_ai_technologies(self, items: Any) -> List[Dict[str, str]]:
        return web_runtime_scheduler.normalize_ai_technologies(self, items)

    def _merge_technologies(
            self,
            *,
            existing: Any,
            incoming: Any,
            limit: int = 220,
    ) -> List[Dict[str, str]]:
        return web_runtime_scheduler.merge_technologies(
            self,
            existing=existing,
            incoming=incoming,
            limit=limit,
        )

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
        return web_runtime_scheduler.infer_findings_from_observations(
            self,
            host_cves_raw=host_cves_raw,
            script_records=script_records,
            process_records=process_records,
            limit=limit,
        )

    def _infer_host_findings(
            self,
            project,
            *,
            host_id: int,
            host_ip: str,
            host_cves_raw: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.infer_host_findings(
            self,
            project,
            host_id=host_id,
            host_ip=host_ip,
            host_cves_raw=host_cves_raw,
        )

    def _infer_urls_from_observations(
            self,
            *,
            script_records: List[Dict[str, Any]],
            process_records: List[Dict[str, Any]],
            limit: int = 160,
    ) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.infer_urls_from_observations(
            self,
            script_records=script_records,
            process_records=process_records,
            limit=limit,
        )

    def _infer_host_urls(self, project, *, host_id: int, host_ip: str = "") -> List[Dict[str, Any]]:
        return web_runtime_scheduler.infer_host_urls(
            self,
            project,
            host_id=host_id,
            host_ip=host_ip,
        )

    def _normalize_ai_findings(self, items: Any) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.normalize_ai_findings(self, items)

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
        return web_runtime_scheduler.normalize_ai_manual_tests(self, items)

    @staticmethod
    def _merge_ai_items(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], *, key_fields: List[str], limit: int) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.merge_ai_items(
            existing,
            incoming,
            key_fields=key_fields,
            limit=limit,
        )

    @staticmethod
    def _coverage_gaps_from_summary(coverage: Any) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.coverage_gaps_from_summary(coverage)

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
        return web_runtime_scheduler.persist_shared_target_state(
            self,
            host_id=host_id,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            service_name=service_name,
            scheduler_mode=scheduler_mode,
            goal_profile=goal_profile,
            engagement_preset=engagement_preset,
            provider=provider,
            hostname=hostname,
            hostname_confidence=hostname_confidence,
            os_match=os_match,
            os_confidence=os_confidence,
            next_phase=next_phase,
            technologies=technologies,
            findings=findings,
            manual_tests=manual_tests,
            service_inventory=service_inventory,
            urls=urls,
            coverage=coverage,
            attempted_action=attempted_action,
            artifact_refs=artifact_refs,
            screenshots=screenshots,
            raw=raw,
        )

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
        return web_runtime_scheduler.persist_scheduler_ai_analysis(
            self,
            host_id=host_id,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            service_name=service_name,
            goal_profile=goal_profile,
            provider_payload=provider_payload,
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
        return web_runtime_scheduler.persist_scheduler_reflection_analysis(
            self,
            host_id=host_id,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            service_name=service_name,
            goal_profile=goal_profile,
            reflection_payload=reflection_payload,
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
        return web_runtime_scheduler.apply_ai_host_updates(
            self,
            host_id=host_id,
            host_ip=host_ip,
            hostname=hostname,
            hostname_confidence=hostname_confidence,
            os_match=os_match,
            os_confidence=os_confidence,
        )

    def _enrich_host_from_observed_results(self, *, host_ip: str, port: str, protocol: str):
        return web_runtime_scheduler.enrich_host_from_observed_results(
            self,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
        )

    def _execute_approved_scheduler_item(self, approval_id: int, job_id: int = 0) -> Dict[str, Any]:
        return web_runtime_scheduler.execute_approved_scheduler_item(
            self,
            approval_id,
            job_id=job_id,
            get_pending_approval_fn=get_pending_approval,
            update_pending_approval_fn=update_pending_approval,
            update_scheduler_decision_for_approval_fn=update_scheduler_decision_for_approval,
        )

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
        return web_runtime_scheduler.execute_scheduler_decision(
            self,
            decision,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            service_name=service_name,
            command_template=command_template,
            timeout=timeout,
            job_id=job_id,
            capture_metadata=capture_metadata,
            approval_id=approval_id,
            runner_preference=runner_preference,
            runner_settings=runner_settings,
        )

    @staticmethod
    def _is_rdp_service(service_name: str) -> bool:
        return web_runtime_screenshots.is_rdp_service(service_name)

    @staticmethod
    def _is_vnc_service(service_name: str) -> bool:
        return web_runtime_screenshots.is_vnc_service(service_name)

    @staticmethod
    def _port_sort_key(port_value: str) -> Tuple[int, str]:
        return web_runtime_screenshots.port_sort_key(port_value)

    @classmethod
    def _is_web_screenshot_target(cls, port: str, protocol: str, service_name: str) -> bool:
        return web_runtime_screenshots.is_web_screenshot_target(port, protocol, service_name)

    def _collect_host_screenshot_targets(self, host_id: int) -> List[Dict[str, str]]:
        return web_runtime_screenshots.collect_host_screenshot_targets(self, host_id)

    def _run_host_screenshot_refresh(self, *, host_id: int, job_id: int = 0) -> Dict[str, Any]:
        return web_runtime_screenshots.run_host_screenshot_refresh(self, host_id=host_id, job_id=job_id)

    def _run_graph_screenshot_refresh(
            self,
            *,
            host_id: int,
            port: str,
            protocol: str = "tcp",
            job_id: int = 0,
    ) -> Dict[str, Any]:
        return web_runtime_screenshots.run_graph_screenshot_refresh(
            self,
            host_id=host_id,
            port=port,
            protocol=protocol,
            job_id=job_id,
        )

    def _take_screenshot(
            self,
            host_ip: str,
            port: str,
            service_name: str = "",
            return_artifacts: bool = False,
            browser_settings: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return web_runtime_screenshots.take_screenshot(
            self,
            host_ip,
            port,
            service_name=service_name,
            return_artifacts=return_artifacts,
            browser_settings=browser_settings,
        )

    def _take_remote_service_screenshot(
            self,
            *,
            host_ip: str,
            port: str,
            service_name: str,
            return_artifacts: bool = False,
            browser_settings: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return web_runtime_screenshots.take_remote_service_screenshot(
            self,
            host_ip=host_ip,
            port=port,
            service_name=service_name,
            return_artifacts=return_artifacts,
            browser_settings=browser_settings,
        )

    def _tool_execution_profile(self, tool_name: Any) -> Dict[str, Any]:
        return web_runtime_processes.tool_execution_profile(self, tool_name)

    def _resolve_process_timeout_policy(self, tool_name: Any, requested_timeout: Any) -> Dict[str, Any]:
        return web_runtime_processes.resolve_process_timeout_policy(self, tool_name, requested_timeout)

    @staticmethod
    def _sample_process_tree_activity(proc: Optional[subprocess.Popen]) -> Optional[Tuple[float, int]]:
        return web_runtime_processes.sample_process_tree_activity(proc)

    @staticmethod
    def _process_tree_activity_changed(
            previous: Optional[Tuple[float, int]],
            current: Optional[Tuple[float, int]],
    ) -> bool:
        return web_runtime_processes.process_tree_activity_changed(previous, current)

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
        return web_runtime_execution.run_command_with_tracking(
            self,
            tool_name=tool_name,
            tab_title=tab_title,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            command=command,
            outputfile=outputfile,
            timeout=timeout,
            job_id=job_id,
            return_metadata=return_metadata,
        )

    def _write_process_output_partial(self, process_id: int, output_text: str):
        return web_runtime_execution.write_process_output_partial(self, process_id, output_text)

    def _save_script_result_if_missing(self, host_ip: str, port: str, protocol: str, tool_id: str, process_id: int):
        return web_runtime_execution.save_script_result_if_missing(
            self,
            host_ip,
            port,
            protocol,
            tool_id,
            process_id,
        )

    def _queue_scheduler_approval(
            self,
            decision: ScheduledAction,
            host_ip: str,
            port: str,
            protocol: str,
            service_name: str,
            command_template: str,
    ) -> int:
        return web_runtime_scheduler.queue_scheduler_approval(
            self,
            decision,
            host_ip,
            port,
            protocol,
            service_name,
            command_template,
        )

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
        return web_runtime_scheduler.record_scheduler_decision(
            self,
            decision,
            host_ip,
            port,
            protocol,
            service_name,
            approved=approved,
            executed=executed,
            reason=reason,
            approval_id=approval_id,
        )

    def _project_metadata(self) -> Dict[str, Any]:
        return web_runtime_projects.project_metadata(self)

    @staticmethod
    def _normalize_restore_compare_path(path: str) -> str:
        return web_runtime_projects.normalize_restore_compare_path(path)

    @classmethod
    def _looks_like_absolute_path(cls, value: str) -> bool:
        _ = cls
        return web_runtime_projects.looks_like_absolute_path(value)

    @classmethod
    def _path_tail(cls, path: str, depth: int = 2) -> str:
        _ = cls
        return web_runtime_projects.path_tail(path, depth=depth)

    @classmethod
    def _build_restore_root_mappings(
            cls,
            *,
            manifest: Dict[str, Any],
            project_path: str,
            output_folder: str,
            running_folder: str,
    ) -> List[Tuple[str, str]]:
        _ = cls
        return web_runtime_projects.build_restore_root_mappings(
            manifest=manifest,
            project_path=project_path,
            output_folder=output_folder,
            running_folder=running_folder,
        )

    @classmethod
    def _build_restore_text_replacements(cls, root_mappings: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        _ = cls
        return web_runtime_projects.build_restore_text_replacements(root_mappings)

    @classmethod
    def _replace_restore_roots_in_text(cls, value: str, text_replacements: List[Tuple[str, str]]) -> str:
        _ = cls
        return web_runtime_projects.replace_restore_roots_in_text(value, text_replacements)

    @classmethod
    def _build_restore_basename_index(cls, roots: List[str]) -> Dict[str, List[str]]:
        _ = cls
        return web_runtime_projects.build_restore_basename_index(roots)

    @classmethod
    def _match_rebased_candidate(cls, raw_value: str, candidates: List[str]) -> str:
        _ = cls
        return web_runtime_projects.match_rebased_candidate(raw_value, candidates)

    @classmethod
    def _rebase_restored_file_reference(
            cls,
            value: str,
            *,
            root_mappings: List[Tuple[str, str]],
            text_replacements: List[Tuple[str, str]],
            basename_index: Dict[str, List[str]],
    ) -> str:
        _ = cls
        return web_runtime_projects.rebase_restored_file_reference(
            value,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )

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
        _ = cls
        return web_runtime_projects.rewrite_restored_json_value(
            value,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
            key_name=key_name,
        )

    @staticmethod
    def _sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> List[str]:
        return web_runtime_projects.sqlite_table_columns(connection, table_name)

    @classmethod
    def _rewrite_restored_json_text(
            cls,
            raw_json: Any,
            *,
            root_mappings: List[Tuple[str, str]],
            text_replacements: List[Tuple[str, str]],
            basename_index: Dict[str, List[str]],
    ) -> Any:
        _ = cls
        return web_runtime_projects.rewrite_restored_json_text(
            raw_json,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )

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
        _ = cls
        return web_runtime_projects.rewrite_sqlite_table_rows(
            connection,
            table_name,
            column_modes,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )

    @classmethod
    def _rebase_restored_project_paths(
            cls,
            *,
            project_path: str,
            manifest: Dict[str, Any],
            output_folder: str,
            running_folder: str,
    ) -> None:
        _ = cls
        return web_runtime_projects.rebase_restored_project_paths(
            project_path=project_path,
            manifest=manifest,
            output_folder=output_folder,
            running_folder=running_folder,
        )

    def _attach_restored_running_folder_locked(self, running_folder: str) -> None:
        return web_runtime_projects.attach_restored_running_folder_locked(self, running_folder)

    def _summary(self) -> Dict[str, int]:
        return web_runtime_workspace.summary(self)

    @staticmethod
    def _count_running_or_waiting_processes(project) -> int:
        return web_runtime_projects.count_running_or_waiting_processes(project)

    @staticmethod
    def _zip_add_file_if_exists(archive: zipfile.ZipFile, src_path: str, arc_path: str):
        return web_runtime_projects.zip_add_file_if_exists(archive, src_path, arc_path)

    @staticmethod
    def _zip_add_dir_if_exists(archive: zipfile.ZipFile, src_dir: str, arc_root: str):
        return web_runtime_projects.zip_add_dir_if_exists(archive, src_dir, arc_root)

    @staticmethod
    def _bundle_prefix(root_prefix: str, leaf: str) -> str:
        return web_runtime_projects.bundle_prefix(root_prefix, leaf)

    @staticmethod
    def _safe_bundle_filename(name: str, fallback: str = "restored.legion") -> str:
        return web_runtime_projects.safe_bundle_filename(name, fallback=fallback)

    @staticmethod
    def _safe_bundle_relative_path(path: str) -> str:
        return web_runtime_projects.safe_bundle_relative_path(path)

    def _read_bundle_manifest(self, archive: zipfile.ZipFile) -> Tuple[str, str, Dict[str, Any]]:
        return web_runtime_projects.read_bundle_manifest(archive)

    def _locate_bundle_session_member(self, archive: zipfile.ZipFile, root_prefix: str, manifest: Dict[str, Any]) -> str:
        _ = self
        return web_runtime_projects.locate_bundle_session_member(
            archive,
            root_prefix,
            manifest,
        )

    def _extract_zip_member_to_file(self, archive: zipfile.ZipFile, member_name: str, destination_path: str):
        return web_runtime_projects.extract_zip_member_to_file(archive, member_name, destination_path)

    def _extract_zip_prefix_to_dir(self, archive: zipfile.ZipFile, prefix: str, destination_dir: str):
        _ = self
        return web_runtime_projects.extract_zip_prefix_to_dir(archive, prefix, destination_dir)

    def _hosts(self, limit: Optional[int] = None, include_down: bool = False) -> List[Dict[str, Any]]:
        return web_runtime_workspace.hosts(self, limit=limit, include_down=include_down)

    @staticmethod
    def _coerce_float(value: Any) -> Optional[float]:
        return web_runtime_processes.coerce_float(value)

    @staticmethod
    def _format_duration_label(total_seconds: Any) -> str:
        return web_runtime_processes.format_duration_label(total_seconds)

    @classmethod
    def _redact_command_secrets(cls, value: Any) -> str:
        text_value = str(value or "")
        if not text_value:
            return ""

        def _replace(match: re.Match) -> str:
            prefix = str(match.group("prefix") or "")
            secret_value = str(match.group("value") or "")
            stripped = secret_value.strip()
            lowered = stripped.lower()
            if not stripped:
                return match.group(0)
            if "***redacted***" in lowered:
                return match.group(0)
            if stripped.startswith("[") and stripped.endswith("]"):
                return match.group(0)
            return f"{prefix}***redacted***"

        redacted = text_value
        for pattern in cls._COMMAND_SECRET_PATTERNS:
            redacted = pattern.sub(_replace, redacted)
        return redacted

    @staticmethod
    def _normalize_progress_source_label(value: Any) -> str:
        return web_runtime_processes.normalize_progress_source_label(value)

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
        _ = cls
        return web_runtime_processes.build_process_progress_payload(
            status=status,
            percent=percent,
            estimated_remaining=estimated_remaining,
            elapsed=elapsed,
            progress_message=progress_message,
            progress_source=progress_source,
            progress_updated_at=progress_updated_at,
        )

    def _processes(self, limit: int = 75) -> List[Dict[str, Any]]:
        return web_runtime_processes.list_processes(self, limit=limit)

    @staticmethod
    def _process_history_records(project, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        return web_runtime_processes.process_history_records(
            project,
            limit=limit,
            redact_command=WebRuntime._redact_command_secrets,
        )

    @staticmethod
    def _normalize_process_timestamp_to_utc(value: Any, *, prefer_utc_naive: bool = False) -> str:
        return web_runtime_processes.normalize_process_timestamp_to_utc(
            value,
            prefer_utc_naive=prefer_utc_naive,
        )

    @staticmethod
    def _process_timestamp_utc_candidates(
            value: Any,
            *,
            prefer_utc_naive: bool = False,
    ) -> List[tuple]:
        return web_runtime_processes.process_timestamp_utc_candidates(
            value,
            prefer_utc_naive=prefer_utc_naive,
        )

    @staticmethod
    def _normalize_process_time_range_to_utc(start_value: Any, end_value: Any) -> tuple:
        return web_runtime_processes.normalize_process_time_range_to_utc(start_value, end_value)

    @staticmethod
    def _sanitize_provider_config(provider_cfg: Dict[str, Any]) -> Dict[str, Any]:
        return web_runtime_scheduler.sanitize_provider_config(provider_cfg)

    @staticmethod
    def _sanitize_integration_config(integration_cfg: Dict[str, Any]) -> Dict[str, Any]:
        return web_runtime_scheduler.sanitize_integration_config(integration_cfg)

    @staticmethod
    def _scheduler_integration_api_key(
            integration_name: str,
            preferences: Optional[Dict[str, Any]] = None,
    ) -> str:
        return web_runtime_scheduler.scheduler_integration_api_key(integration_name, preferences)

    def _shodan_integration_enabled(self, preferences: Optional[Dict[str, Any]] = None) -> bool:
        config = preferences if isinstance(preferences, dict) else self.scheduler_config.load()
        api_key = self._scheduler_integration_api_key("shodan", config)
        return bool(api_key and api_key.lower() not in {"yourkeygoeshere", "changeme"})

    def _grayhatwarfare_integration_enabled(self, preferences: Optional[Dict[str, Any]] = None) -> bool:
        config = preferences if isinstance(preferences, dict) else self.scheduler_config.load()
        api_key = self._scheduler_integration_api_key("grayhatwarfare", config)
        return bool(api_key and api_key.lower() not in {"yourkeygoeshere", "changeme"})

    def _scheduler_command_placeholders(
            self,
            *,
            host_ip: str,
            hostname: str,
            preferences: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        return web_runtime_scheduler.scheduler_command_placeholders(
            self,
            host_ip=host_ip,
            hostname=hostname,
            preferences=preferences,
        )

    def _scheduler_preferences(self) -> Dict[str, Any]:
        return web_runtime_scheduler.scheduler_preferences(self)

    def _device_category_options(self) -> List[Dict[str, Any]]:
        from app.device_categories import device_category_options

        return device_category_options(self.scheduler_config.get_device_categories())

    @staticmethod
    def _built_in_device_category_options() -> List[Dict[str, Any]]:
        from app.device_categories import built_in_device_category_rules

        return [
            {"id": str(item.get("id", "") or ""), "name": str(item.get("name", "") or ""), "built_in": True}
            for item in built_in_device_category_rules()
        ]

    def _ensure_scheduler_table(self):
        return web_runtime_scheduler.ensure_scheduler_table(self)

    def _ensure_scheduler_approval_store(self):
        return web_runtime_scheduler.ensure_scheduler_approval_store(self)

    def _ensure_process_tables(self):
        return web_runtime_processes.ensure_process_tables(self)

    def _ensure_workspace_settings_table(self):
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return
        session = project.database.session()
        try:
            session.execute(text(
                "CREATE TABLE IF NOT EXISTS workspace_setting ("
                "key TEXT PRIMARY KEY,"
                "value_json TEXT"
                ")"
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _get_workspace_setting_locked(self, key: str, default: Any = None) -> Any:
        project = self._require_active_project()
        self._ensure_workspace_settings_table()
        session = project.database.session()
        try:
            row = session.execute(text(
                "SELECT value_json FROM workspace_setting WHERE key = :key LIMIT 1"
            ), {"key": str(key or "")}).fetchone()
            if not row or row[0] in (None, ""):
                return default
            try:
                return json.loads(str(row[0] or ""))
            except Exception:
                return default
        finally:
            session.close()

    def _set_workspace_setting_locked(self, key: str, value: Any):
        project = self._require_active_project()
        self._ensure_workspace_settings_table()
        session = project.database.session()
        try:
            encoded = json.dumps(value, sort_keys=True)
            session.execute(text(
                "INSERT INTO workspace_setting (key, value_json) VALUES (:key, :value_json) "
                "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json"
            ), {
                "key": str(key or ""),
                "value_json": encoded,
            })
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _default_credential_capture_config() -> Dict[str, Any]:
        return web_runtime_credential_capture.default_credential_capture_config()

    @classmethod
    def _normalize_credential_capture_config(cls, value: Any) -> Dict[str, Any]:
        _ = cls
        return web_runtime_credential_capture.normalize_credential_capture_config(value)

    @staticmethod
    def _dedupe_credential_hashes(captures: List[Dict[str, Any]]) -> List[str]:
        return web_runtime_credential_capture.dedupe_credential_hashes(captures)

    @staticmethod
    def _extract_credential_data(line: Any) -> Tuple[str, str]:
        return web_runtime_credential_capture.extract_credential_data(line)

    @staticmethod
    def _normalize_credential_capture_source(source: Any) -> str:
        return web_runtime_credential_capture.normalize_credential_capture_source(source)

    @staticmethod
    def _split_credential_principal(value: Any) -> Tuple[str, str]:
        return web_runtime_credential_capture.split_credential_principal(value)

    @staticmethod
    def _extract_cleartext_password(details: Any) -> str:
        return web_runtime_credential_capture.extract_cleartext_password(details)

    @classmethod
    def _build_scheduler_credential_row(cls, tool_name: str, capture: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return web_runtime_scheduler.build_scheduler_credential_row(cls, tool_name, capture)

    @classmethod
    def _build_scheduler_session_row(cls, tool_name: str, capture: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return web_runtime_scheduler.build_scheduler_session_row(cls, tool_name, capture)

    @classmethod
    def _extract_credential_capture_entries(
            cls,
            tool_name: str,
            line: Any,
            *,
            default_source: str = "",
            context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        return web_runtime_scheduler.extract_credential_capture_entries(
            cls,
            tool_name,
            line,
            default_source=default_source,
            context=context,
        )

    def _persist_credential_captures_to_scheduler(
            self,
            captures: List[Dict[str, Any]],
            *,
            tool_name: str = "",
            default_source: str = "",
    ):
        return web_runtime_scheduler.persist_credential_captures_to_scheduler(
            self,
            captures,
            tool_name=tool_name,
            default_source=default_source,
        )

    def _persist_credential_capture_output(self, *, tool_name: str, output_text: str, default_source: str = ""):
        return web_runtime_scheduler.persist_credential_capture_output(
            self,
            tool_name=tool_name,
            output_text=output_text,
            default_source=default_source,
        )

    def _latest_credential_capture_session_locked(self, tool_name: str) -> Dict[str, Any]:
        return web_runtime_credential_capture.latest_credential_capture_session_locked(self, tool_name)

    def _credential_capture_state_locked(self, *, include_captures: bool = False) -> Dict[str, Any]:
        return web_runtime_credential_capture.credential_capture_state_locked(
            self,
            include_captures=include_captures,
        )

    def save_credential_capture_config(self, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return web_runtime_credential_capture.save_credential_capture_config(self, updates)

    def start_credential_capture_session_job(self, tool_id: str) -> Dict[str, Any]:
        return web_runtime_credential_capture.start_credential_capture_session_job(self, tool_id)

    def stop_credential_capture_session(self, tool_id: str) -> Dict[str, Any]:
        return web_runtime_credential_capture.stop_credential_capture_session(self, tool_id)

    def get_credential_capture_log_payload(self, tool_id: str) -> Dict[str, Any]:
        return web_runtime_credential_capture.get_credential_capture_log_payload(self, tool_id)

    def _run_credential_capture_session(self, *, tool_id: str, job_id: int = 0) -> Dict[str, Any]:
        return web_runtime_credential_capture.run_credential_capture_session(
            self,
            tool_id=tool_id,
            job_id=job_id,
        )

    def _build_credential_capture_command(self, tool_id: str, config: Dict[str, Any]) -> Tuple[str, str]:
        return web_runtime_credential_capture.build_credential_capture_command(self, tool_id, config)

    @staticmethod
    def _credential_capture_target_label(tool_id: str, config: Dict[str, Any]) -> str:
        return web_runtime_credential_capture.credential_capture_target_label(tool_id, config)

    def _close_active_project(self):
        return web_runtime_projects.close_active_project(self)

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
        return web_runtime_scheduler.load_host_ai_analysis(self, project, host_id, host_ip)

    def _list_screenshots_for_host(self, project, host_ip: str) -> List[Dict[str, Any]]:
        return web_runtime_screenshots.list_screenshots_for_host(self, project, host_ip)

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
        if entry_protocol != target_protocol:
            return False
        if target_port:
            return entry_port == target_port
        return not entry_port

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
        scheduler_preferences = self.scheduler_config.load()
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
            extra_placeholders=self._scheduler_command_placeholders(
                host_ip=str(host_ip),
                hostname=self._hostname_for_ip(host_ip),
                preferences=scheduler_preferences,
            ),
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
        return web_runtime_scans.build_nmap_scan_plan(
            self,
            targets=targets,
            discovery=discovery,
            staged=staged,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            output_prefix=output_prefix,
            scan_mode=scan_mode,
            scan_options=scan_options,
        )

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
        return web_runtime_scans.build_single_scan_plan(
            self,
            targets=targets,
            nmap_path=nmap_path,
            output_prefix=output_prefix,
            mode=mode,
            options=options,
            extra_args=extra_args,
        )

    @staticmethod
    def _normalize_scan_options(options: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
        return web_runtime_scans.normalize_scan_options(options, defaults)

    @staticmethod
    def _normalize_timing(raw: str) -> str:
        return web_runtime_scans.normalize_timing(raw)

    @staticmethod
    def _normalize_top_ports(raw: Any) -> int:
        return web_runtime_scans.normalize_top_ports(raw)

    @staticmethod
    def _normalize_explicit_ports(raw: Any) -> str:
        return web_runtime_scans.normalize_explicit_ports(raw)

    @staticmethod
    def _contains_nmap_stats_every(args: List[str]) -> bool:
        return web_runtime_scans.contains_nmap_stats_every(args)

    @staticmethod
    def _contains_nmap_verbose(args: List[str]) -> bool:
        return web_runtime_scans.contains_nmap_verbose(args)

    @staticmethod
    def _append_nmap_stats_every(args: List[str], interval: str = "15s") -> List[str]:
        return web_runtime_scans.append_nmap_stats_every(args, interval=interval)

    @staticmethod
    def _nmap_output_prefix_for_command(output_prefix: str, nmap_path: str) -> str:
        return web_runtime_scans.nmap_output_prefix_for_command(output_prefix, nmap_path)

    @staticmethod
    def _join_shell_tokens(tokens: List[str]) -> str:
        return web_runtime_scans.join_shell_tokens(tokens)

    @staticmethod
    def _compact_targets(targets: List[str]) -> str:
        return web_runtime_scans.compact_targets(targets)

    @staticmethod
    def _summarize_scan_scope(targets: List[str]) -> str:
        return web_runtime_scans.summarize_scan_scope(targets)

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
            target_summary: str = "",
            scope_summary: str = "",
            result_summary: str = "",
    ) -> Optional[Dict[str, Any]]:
        return web_runtime_scans.record_scan_submission(
            self,
            submission_kind=submission_kind,
            job_id=job_id,
            targets=targets,
            source_path=source_path,
            discovery=discovery,
            staged=staged,
            run_actions=run_actions,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            scan_mode=scan_mode,
            scan_options=scan_options,
            target_summary=target_summary,
            scope_summary=scope_summary,
            result_summary=result_summary,
        )

    def _update_scan_submission_status(
            self,
            *,
            job_id: int,
            status: str,
            result_summary: str = "",
    ) -> Optional[Dict[str, Any]]:
        return web_runtime_scans.update_scan_submission_status(
            self,
            job_id=job_id,
            status=status,
            result_summary=result_summary,
        )

    @staticmethod
    def _record_bool(value: Any, default: bool = False) -> bool:
        return web_runtime_scans.record_bool(value, default=default)

    @staticmethod
    def _normalize_subnet_target(subnet: str) -> str:
        return web_runtime_scans.normalize_subnet_target(subnet)

    @classmethod
    def _count_rfc1918_scan_batches(cls, targets: List[str]) -> int:
        return web_runtime_scans.count_rfc1918_scan_batches(cls, targets)

    @classmethod
    def _iter_rfc1918_scan_batches(cls, targets: List[str]):
        yield from web_runtime_scans.iter_rfc1918_scan_batches(cls, targets)

    @classmethod
    def _normalize_rfc_chunk_concurrency(cls, raw: Any) -> int:
        return web_runtime_scans.normalize_rfc_chunk_concurrency(cls, raw)

    @staticmethod
    def _scan_history_targets(record: Dict[str, Any]) -> List[str]:
        return web_runtime_scans.scan_history_targets(record)

    @classmethod
    def _scan_target_match_score_for_subnet(cls, target: Any, subnet: str) -> int:
        _ = cls
        return web_runtime_scans.scan_target_match_score_for_subnet(target, subnet)

    @classmethod
    def _best_scan_submission_for_subnet(cls, subnet: str, records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return web_runtime_scans.best_scan_submission_for_subnet(cls, subnet, records)

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

    @staticmethod
    def _is_tshark_passive_capture_command(tool_name: str, command: str) -> bool:
        name = str(tool_name or "").strip().lower()
        if name == "tshark-passive-capture":
            return True
        command_text = str(command or "").strip().lower()
        if not command_text:
            return False
        return (
            (" tshark " in f" {command_text} " or command_text.startswith("tshark "))
            and bool(_TSHARK_DURATION_RE.search(command_text))
        )

    @classmethod
    def _process_progress_adapter_for_command(cls, tool_name: str, command: str) -> str:
        return web_runtime_processes.process_progress_adapter_for_command(cls, tool_name, command)

    @staticmethod
    def _estimate_remaining_from_percent(runtime_seconds: float, percent: Optional[float]) -> Optional[int]:
        return web_runtime_processes.estimate_remaining_from_percent(runtime_seconds, percent)

    @staticmethod
    def _extract_progress_line(text: str, predicate) -> str:
        return web_runtime_processes.extract_progress_line(text, predicate)

    @classmethod
    def _extract_nmap_progress_message(cls, text: str) -> str:
        return web_runtime_processes.extract_nmap_progress_message(text)

    @classmethod
    def _extract_nuclei_progress_from_text(
            cls,
            text: str,
            runtime_seconds: float,
    ) -> Tuple[Optional[float], Optional[int], str]:
        return web_runtime_processes.extract_nuclei_progress_from_text(text, runtime_seconds)

    @classmethod
    def _extract_tshark_passive_progress(
            cls,
            command: str,
            runtime_seconds: float,
    ) -> Tuple[Optional[float], Optional[int], str]:
        return web_runtime_processes.extract_tshark_passive_progress(command, runtime_seconds)

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
        return web_runtime_processes.update_process_progress(
            self,
            process_repo,
            process_id=process_id,
            tool_name=tool_name,
            command=command,
            text_chunk=text_chunk,
            runtime_seconds=runtime_seconds,
            state=state,
        )

    def _update_nmap_process_progress(
            self,
            process_repo,
            *,
            process_id: int,
            text_chunk: str,
            state: Dict[str, Any],
    ):
        return web_runtime_processes.update_nmap_process_progress(
            self,
            process_repo,
            process_id=process_id,
            text_chunk=text_chunk,
            state=state,
        )

    @staticmethod
    def _extract_nmap_progress_from_text(text: str) -> Tuple[Optional[float], Optional[int]]:
        return web_runtime_processes.extract_nmap_progress_from_text(text)

    @staticmethod
    def _parse_duration_seconds(raw: str) -> Optional[int]:
        return web_runtime_processes.parse_duration_seconds(raw)

    def _is_temp_project(self) -> bool:
        project = getattr(self.logic, "activeProject", None)
        if not project:
            return False
        return bool(getattr(project.properties, "isTemporary", False))

    @staticmethod
    def _normalize_project_path(path: str) -> str:
        return web_runtime_projects.normalize_project_path(path)

    @staticmethod
    def _normalize_existing_file(path: str) -> str:
        return web_runtime_projects.normalize_existing_file(path)

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
