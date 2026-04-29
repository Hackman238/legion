import ipaddress
import re
import sqlite3
import subprocess
import sys
import threading
import zipfile
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import text

from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    update_pending_approval,
)
from app.scheduler.audit import (
    update_scheduler_decision_for_approval,
)
from app.scheduler.models import ExecutionRecord
from app.scheduler.orchestrator import SchedulerOrchestrator
from app.scheduler.config import SchedulerConfigManager
from app.scheduler.planner import ScheduledAction, SchedulerPlanner
from app.settings import AppSettings, Settings
from app.web import runtime_artifacts as web_runtime_artifacts
from app.web import runtime_credential_capture as web_runtime_credential_capture
from app.web import runtime_execution as web_runtime_execution
from app.web import runtime_graph as web_runtime_graph
from app.web import runtime_jobs as web_runtime_jobs
from app.web import runtime_processes as web_runtime_processes
from app.web import runtime_projects as web_runtime_projects
from app.web import runtime_reports as web_runtime_reports
from app.web import runtime_scheduler as web_runtime_scheduler
from app.web import runtime_scheduler_state as web_runtime_scheduler_state
from app.web import runtime_scans as web_runtime_scans
from app.web import runtime_screenshots as web_runtime_screenshots
from app.web import runtime_settings as web_runtime_settings
from app.web import runtime_status as web_runtime_status
from app.web import runtime_tools as web_runtime_tools
from app.web import runtime_workspace as web_runtime_workspace
from app.web.jobs import WebJobManager


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
_PROCESS_READER_EXIT_GRACE_SECONDS = 2.0
_PROCESS_CRASH_MIN_RUNTIME_SECONDS = 5.0


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
        return web_runtime_jobs.emit_ui_invalidation(
            self,
            *channels,
            throttle_seconds=throttle_seconds,
        )

    def wait_for_ui_event(self, after_seq: int = 0, timeout_seconds: float = 30.0) -> Dict[str, Any]:
        return web_runtime_jobs.wait_for_ui_event(
            self,
            after_seq=after_seq,
            timeout_seconds=timeout_seconds,
        )

    def _handle_job_change(self, job: Dict[str, Any], event_name: str):
        return web_runtime_jobs.handle_job_change(self, job, event_name)

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
        return web_runtime_settings.get_tool_audit(self)

    @staticmethod
    def _tool_audit_availability(entries: Any) -> Dict[str, List[str]]:
        return web_runtime_settings.tool_audit_availability(entries)

    def _scheduler_tool_audit_snapshot(self) -> Dict[str, List[str]]:
        return web_runtime_scheduler.scheduler_tool_audit_snapshot(self)

    def get_tool_install_plan(
            self,
            *,
            platform: str = "kali",
            scope: str = "missing",
            tool_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return web_runtime_settings.get_tool_install_plan(
            self,
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
        return web_runtime_jobs.start_job(
            self,
            job_type,
            runner_with_job_id,
            payload=payload,
            queue_front=queue_front,
            exclusive=exclusive,
        )

    def start_tool_install_job(
            self,
            *,
            platform: str = "kali",
            scope: str = "missing",
            tool_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return web_runtime_settings.start_tool_install_job(
            self,
            platform=platform,
            scope=scope,
            tool_keys=tool_keys,
        )

    def _run_tool_install_job(
            self,
            *,
            platform: str = "kali",
            scope: str = "missing",
            tool_keys: Optional[List[str]] = None,
            job_id: int = 0,
    ) -> Dict[str, Any]:
        return web_runtime_settings.run_tool_install_job(
            self,
            platform=platform,
            scope=scope,
            tool_keys=tool_keys,
            job_id=job_id,
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
        return web_runtime_scans.apply_engagement_scan_profile(
            cls,
            scan_options,
            engagement_policy=engagement_policy,
        )

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
        return web_runtime_jobs.find_active_job(self, job_type=job_type, host_id=host_id)

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
        return web_runtime_scheduler.normalize_project_report_headers(headers)

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
        return web_runtime_scheduler.job_worker_count(preferences)

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
        return web_runtime_scheduler.project_report_delivery_config(preferences)

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
        return web_runtime_scheduler_state.existing_attempt_summary_for_target(
            self,
            host_id,
            host_ip,
            port,
            protocol,
        )

    def _existing_tool_attempts_for_target(self, host_id: int, host_ip: str, port: str, protocol: str) -> set:
        return web_runtime_scheduler_state.existing_tool_attempts_for_target(
            self,
            host_id,
            host_ip,
            port,
            protocol,
        )

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
        return web_runtime_scheduler_state.ai_confidence_value(value)

    @staticmethod
    def _sanitize_ai_hostname(value: Any) -> str:
        return web_runtime_scheduler_state.sanitize_ai_hostname(value)

    @staticmethod
    def _extract_cpe_tokens(value: Any, limit: int = 8) -> List[str]:
        return web_runtime_scheduler_state.extract_cpe_tokens(value, limit=limit)

    @staticmethod
    def _extract_version_token(value: Any) -> str:
        return web_runtime_scheduler_state.extract_version_token(value)

    @staticmethod
    def _is_ipv4_like(value: Any) -> bool:
        return web_runtime_scheduler_state.is_ipv4_like(value)

    @staticmethod
    def _sanitize_technology_version(value: Any) -> str:
        return web_runtime_scheduler_state.sanitize_technology_version(value)

    @staticmethod
    def _sanitize_technology_version_for_tech(
            *,
            name: Any,
            version: Any,
            cpe: Any = "",
            evidence: Any = "",
    ) -> str:
        return web_runtime_scheduler_state.sanitize_technology_version_for_tech(
            name=name,
            version=version,
            cpe=cpe,
            evidence=evidence,
        )

    @staticmethod
    def _technology_hint_source_text(source_id: Any, output_text: Any) -> str:
        return web_runtime_scheduler_state.technology_hint_source_text(
            source_id,
            output_text,
            strip_nmap_preamble_fn=web_runtime_workspace.strip_nmap_preamble,
        )

    @staticmethod
    def _observation_text_for_analysis(source_id: Any, output_text: Any) -> str:
        return web_runtime_scheduler_state.observation_text_for_analysis(
            source_id,
            output_text,
            strip_nmap_preamble_fn=web_runtime_workspace.strip_nmap_preamble,
        )

    @staticmethod
    def _cve_evidence_lines(source_id: Any, output_text: Any, limit: int = 24) -> List[Tuple[str, str]]:
        return web_runtime_scheduler_state.cve_evidence_lines(
            source_id,
            output_text,
            limit=limit,
            strip_nmap_preamble_fn=web_runtime_workspace.strip_nmap_preamble,
        )

    @staticmethod
    def _extract_version_near_tokens(value: Any, tokens: Any) -> str:
        return web_runtime_scheduler_state.extract_version_near_tokens(value, tokens)

    @staticmethod
    def _normalize_cpe_token(value: Any) -> str:
        return web_runtime_scheduler_state.normalize_cpe_token(value)

    @staticmethod
    def _cpe_base(value: Any) -> str:
        return web_runtime_scheduler_state.cpe_base(value)

    @staticmethod
    def _is_weak_technology_name(value: Any) -> bool:
        return web_runtime_scheduler_state.is_weak_technology_name(value)

    @staticmethod
    def _is_placeholder_scheduler_text(value: Any) -> bool:
        return web_runtime_scheduler.is_placeholder_scheduler_text(value)

    @staticmethod
    def _technology_canonical_key(name: Any, cpe: Any) -> str:
        return web_runtime_scheduler_state.technology_canonical_key(name, cpe)

    @staticmethod
    def _technology_quality_score(*, name: Any, version: Any, cpe: Any, evidence: Any) -> int:
        return web_runtime_scheduler_state.technology_quality_score(
            name=name,
            version=version,
            cpe=cpe,
            evidence=evidence,
        )

    @staticmethod
    def _name_from_cpe(cpe: str) -> str:
        return web_runtime_scheduler_state.name_from_cpe(cpe)

    @staticmethod
    def _version_from_cpe(cpe: str) -> str:
        return web_runtime_scheduler_state.version_from_cpe(cpe)

    @staticmethod
    def _guess_technology_hint(name_or_text: Any, version_hint: Any = "") -> Tuple[str, str]:
        return web_runtime_scheduler_state.guess_technology_hint(name_or_text, version_hint=version_hint)

    @staticmethod
    def _guess_technology_hints(name_or_text: Any, version_hint: Any = "") -> List[Tuple[str, str]]:
        return web_runtime_scheduler_state.guess_technology_hints(name_or_text, version_hint=version_hint)

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
        return web_runtime_scheduler_state.severity_from_text(value)

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
        return web_runtime_scheduler_state.finding_sort_key(item)

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
        _ = cls
        return web_runtime_processes.redact_command_secrets(value)

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
            redact_command=web_runtime_processes.redact_command_secrets,
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
        return web_runtime_scheduler.shodan_integration_enabled(self, preferences)

    def _grayhatwarfare_integration_enabled(self, preferences: Optional[Dict[str, Any]] = None) -> bool:
        return web_runtime_scheduler.grayhatwarfare_integration_enabled(self, preferences)

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
        return web_runtime_scheduler.device_category_options_for_runtime(self)

    @staticmethod
    def _built_in_device_category_options() -> List[Dict[str, Any]]:
        return web_runtime_scheduler.built_in_device_category_options()

    def _ensure_scheduler_table(self):
        return web_runtime_scheduler.ensure_scheduler_table(self)

    def _ensure_scheduler_approval_store(self):
        return web_runtime_scheduler.ensure_scheduler_approval_store(self)

    def _ensure_process_tables(self):
        return web_runtime_processes.ensure_process_tables(self)

    def _ensure_workspace_settings_table(self):
        return web_runtime_workspace.ensure_workspace_settings_table(self)

    def _get_workspace_setting_locked(self, key: str, default: Any = None) -> Any:
        return web_runtime_workspace.get_workspace_setting_locked(self, key, default=default)

    def _set_workspace_setting_locked(self, key: str, value: Any):
        return web_runtime_workspace.set_workspace_setting_locked(self, key, value)

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
        return web_runtime_projects.require_active_project(self)

    def _resolve_host(self, host_id: int):
        return web_runtime_workspace.resolve_host(self, host_id)

    def _load_cves_for_host(self, project, host_id: int) -> List[Dict[str, Any]]:
        return web_runtime_workspace.load_cves_for_host(project, host_id)

    def _load_host_ai_analysis(self, project, host_id: int, host_ip: str) -> Dict[str, Any]:
        return web_runtime_scheduler.load_host_ai_analysis(self, project, host_id, host_ip)

    def _list_screenshots_for_host(self, project, host_ip: str) -> List[Dict[str, Any]]:
        return web_runtime_screenshots.list_screenshots_for_host(self, project, host_ip)

    def _tool_run_stats(self, project) -> Dict[str, Dict[str, Any]]:
        return web_runtime_tools.tool_run_stats(project)

    def _get_settings(self) -> Settings:
        return web_runtime_tools.get_settings(self)

    @staticmethod
    def _find_port_action(settings: Settings, tool_id: str):
        return web_runtime_tools.find_port_action(settings, tool_id)

    def _find_command_template_for_tool(self, settings: Settings, tool_id: str) -> str:
        return web_runtime_tools.find_command_template_for_tool(self, settings, tool_id)

    def _runner_type_for_tool(self, tool_id: str, command_template: str = "") -> str:
        return web_runtime_tools.runner_type_for_tool(self, tool_id, command_template)

    def _runner_type_for_approval_item(self, item: Optional[Dict[str, Any]]) -> str:
        return web_runtime_tools.runner_type_for_approval_item(self, item)

    def _hostname_for_ip(self, host_ip: str) -> str:
        return web_runtime_workspace.hostname_for_ip(self, host_ip)

    def _service_name_for_target(self, host_ip: str, port: str, protocol: str) -> str:
        return web_runtime_workspace.service_name_for_target(self, host_ip, port, protocol)

    @staticmethod
    def _normalize_command_signature_source(command_text: str) -> str:
        return web_runtime_scheduler_state.normalize_command_signature_source(command_text)

    def _command_signature_for_target(self, command_text: str, protocol: str) -> str:
        return web_runtime_scheduler_state.command_signature_for_target(command_text, protocol)

    @staticmethod
    def _target_attempt_matches(item: Dict[str, Any], port: str, protocol: str) -> bool:
        return web_runtime_scheduler_state.target_attempt_matches(item, port, protocol)

    def _build_command(
            self,
            template: str,
            host_ip: str,
            port: str,
            protocol: str,
            tool_id: str,
            service_name: str = "",
    ) -> Tuple[str, str]:
        return web_runtime_tools.build_command(
            self,
            template,
            host_ip,
            port,
            protocol,
            tool_id,
            service_name=service_name,
        )

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
        return web_runtime_processes.is_nmap_command(tool_name, command)

    @staticmethod
    def _is_nuclei_command(tool_name: str, command: str) -> bool:
        return web_runtime_processes.is_nuclei_command(tool_name, command)

    @staticmethod
    def _is_tshark_passive_capture_command(tool_name: str, command: str) -> bool:
        return web_runtime_processes.is_tshark_passive_capture_command(tool_name, command)

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
        return web_runtime_projects.is_temp_project(self)

    @staticmethod
    def _normalize_project_path(path: str) -> str:
        return web_runtime_projects.normalize_project_path(path)

    @staticmethod
    def _normalize_existing_file(path: str) -> str:
        return web_runtime_projects.normalize_existing_file(path)

    @staticmethod
    def _normalize_targets(targets) -> List[str]:
        return web_runtime_scans.normalize_targets(targets)
