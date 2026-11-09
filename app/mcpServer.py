import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# asyncio's default 64 KiB line limit is too small for real requests (e.g. large annotation bodies).
_MAX_REQUEST_LINE_BYTES = 16 * 1024 * 1024


async def _read_request_line(reader: asyncio.StreamReader) -> Optional[bytes]:
    """Read one newline-terminated request: b"" at EOF, None when an over-limit line was skipped."""
    try:
        return await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        return bytes(exc.partial or b"")  # a final unterminated line, or b"" at EOF
    except asyncio.LimitOverrunError as exc:
        consumed = int(exc.consumed)
    # Discard the rest of the oversized line so the next request is read from its start.
    while True:
        try:
            await reader.readexactly(consumed)
            await reader.readuntil(b"\n")
            return None
        except asyncio.LimitOverrunError as exc:
            consumed = int(exc.consumed)
        except asyncio.IncompleteReadError:
            return None


def _int_arg(arguments: Dict[str, Any], key: str, default: int) -> int:
    try:
        return int(arguments.get(key, default) or default)
    except (TypeError, ValueError):
        return int(default)


def _bool_arg(arguments: Dict[str, Any], key: str, default: bool = False) -> bool:
    value = arguments.get(key, default)
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return bool(default)


MCP_PROTOCOL_VERSION = "2025-06-18"


class MCPServer:
    def __init__(self, runtime=None):
        self._runtime = runtime
        self.tools = {
            "list_projects": {
                "description": "List Legion projects available on disk.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.list_projects,
            },
            "open_project": {
                "description": "Open a Legion project file.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "required": ["path"],
                },
                "handler": self.open_project,
            },
            "save_project": {
                "description": "Save the current Legion project to a path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "replace": {"type": "boolean"},
                    },
                    "required": ["path"],
                },
                "handler": self.save_project,
            },
            "run_discovery": {
                "description": "Run a quick discovery scan on a target and optionally invoke the shared scheduler.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "run_actions": {"type": "boolean"},
                    },
                    "required": [],
                },
                "handler": self.run_discovery,
            },
            "get_engagement_policy": {
                "description": "Get the current normalized Legion engagement policy.",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
                "handler": self.get_engagement_policy,
            },
            "set_engagement_policy": {
                "description": "Update the normalized Legion engagement policy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "preset": {"type": "string"},
                        "scope": {"type": "string"},
                        "intent": {"type": "string"},
                        "allow_exploitation": {"type": "boolean"},
                        "allow_lateral_movement": {"type": "boolean"},
                        "credential_attack_mode": {"type": "string"},
                        "lockout_risk_mode": {"type": "string"},
                        "stability_risk_mode": {"type": "string"},
                        "detection_risk_mode": {"type": "string"},
                        "approval_mode": {"type": "string"},
                        "runner_preference": {"type": "string"},
                        "noise_budget": {"type": "string"},
                    },
                    "required": [],
                },
                "handler": self.set_engagement_policy,
            },
            "get_plan_preview": {
                "description": "Preview the next governed plan steps for a target or service.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": {"type": "integer"},
                        "host_ip": {"type": "string"},
                        "service": {"type": "string"},
                        "port": {"type": "string"},
                        "protocol": {"type": "string"},
                        "mode": {"type": "string"},
                        "limit_targets": {"type": "integer"},
                        "limit_actions": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.get_plan_preview,
            },
            "list_approvals": {
                "description": "List pending or historical approval requests.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.list_approvals,
            },
            "approve_approval": {
                "description": "Approve a pending approval request without necessarily executing it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "approval_id": {"type": "integer"},
                        "approve_family": {"type": "boolean"},
                        "run_now": {"type": "boolean"},
                        "family_action": {"type": "string"},
                    },
                    "required": ["approval_id"],
                },
                "handler": self.approve_approval,
            },
            "execute_approved_plan_step": {
                "description": "Approve and execute a pending approval request through the shared approval flow.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "approval_id": {"type": "integer"},
                        "approve_family": {"type": "boolean"},
                        "family_action": {"type": "string"},
                    },
                    "required": ["approval_id"],
                },
                "handler": self.execute_approved_plan_step,
            },
            "reject_approval": {
                "description": "Reject a pending approval request.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "approval_id": {"type": "integer"},
                        "reason": {"type": "string"},
                        "family_action": {"type": "string"},
                    },
                    "required": ["approval_id"],
                },
                "handler": self.reject_approval,
            },
            "query_graph": {
                "description": "Query the project evidence graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node_types": {"type": "array", "items": {"type": "string"}},
                        "edge_types": {"type": "array", "items": {"type": "string"}},
                        "source_kinds": {"type": "array", "items": {"type": "string"}},
                        "min_confidence": {"type": "number"},
                        "search": {"type": "string"},
                        "include_ai_suggested": {"type": "boolean"},
                        "host_id": {"type": "integer"},
                        "limit_nodes": {"type": "integer"},
                        "limit_edges": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.query_graph,
            },
            "query_findings": {
                "description": "Query findings from the shared target state.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.query_findings,
            },
            "query_state": {
                "description": "Query shared target state for one host or the project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.query_state,
            },
            "export_report": {
                "description": "Export a host or project report in JSON or Markdown.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string"},
                        "host_id": {"type": "integer"},
                        "format": {"type": "string"},
                    },
                    "required": [],
                },
                "handler": self.export_report,
            },
            "list_execution_traces": {
                "description": "List execution traces from the normalized execution ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer"},
                        "host_id": {"type": "integer"},
                        "host_ip": {"type": "string"},
                        "tool_id": {"type": "string"},
                        "include_output": {"type": "boolean"},
                    },
                    "required": [],
                },
                "handler": self.list_execution_traces,
            },
            "get_execution_trace": {
                "description": "Fetch a single execution trace and output excerpts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "execution_id": {"type": "string"},
                        "max_chars": {"type": "integer"},
                    },
                    "required": ["execution_id"],
                },
                "handler": self.get_execution_trace,
            },
            "create_annotation": {
                "description": "Create or update a graph annotation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_kind": {"type": "string"},
                        "target_ref": {"type": "string"},
                        "body": {"type": "string"},
                        "created_by": {"type": "string"},
                        "source_ref": {"type": "string"},
                        "annotation_id": {"type": "string"},
                    },
                    "required": ["target_kind", "target_ref", "body"],
                },
                "handler": self.create_annotation,
            },
            "list_hosts": {
                "description": "List hosts in the open project with status, OS, categories and open port counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer"},
                        "filter": {"type": "string", "description": "hide_down (default) or show_all"},
                        "service": {"type": "string", "description": "Only hosts exposing this service name"},
                        "category": {"type": "string", "description": "Only hosts in this device category"},
                    },
                    "required": [],
                },
                "handler": self.list_hosts,
            },
            "get_host": {
                "description": "Full detail for one host: ports, services, scripts, CVEs, notes, screenshots and AI analysis.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"host_id": {"type": "integer"}},
                    "required": ["host_id"],
                },
                "handler": self.get_host,
            },
            "list_services": {
                "description": "Services aggregated across hosts (optionally for one host or category).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer"},
                        "host_id": {"type": "integer"},
                        "category": {"type": "string"},
                    },
                    "required": [],
                },
                "handler": self.list_services,
            },
            "list_tool_catalog": {
                "description": "Tools and pipettes that can be run against a service/port, with their risk categories.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "service": {"type": "string"},
                        "port": {"type": "string"},
                        "protocol": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": [],
                },
                "handler": self.list_tool_catalog,
            },
            "run_tool": {
                "description": (
                    "Run one catalog tool against a host/port as a tracked process. The engagement policy decides "
                    "first: status accepted means it was queued as a job, approval_required means a pending approval "
                    "was created instead (approval_ids) and nothing ran, blocked means the policy refuses it."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_ip": {"type": "string"},
                        "port": {"type": "string"},
                        "protocol": {"type": "string"},
                        "tool_id": {"type": "string"},
                        "timeout": {"type": "integer"},
                        "parameters": {"type": "object"},
                    },
                    "required": ["host_ip", "port", "tool_id"],
                },
                "handler": self.run_tool,
            },
            "start_nmap_scan": {
                "description": "Queue an nmap scan of targets (IPs, CIDRs, hostnames) and import the results.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string"}},
                        "discovery": {"type": "boolean"},
                        "staged": {"type": "boolean"},
                        "run_actions": {"type": "boolean"},
                        "nmap_args": {"type": "string"},
                        "scan_mode": {"type": "string", "description": "easy, hard, legacy or rfc1918_discovery"},
                        "scan_options": {"type": "object"},
                    },
                    "required": ["targets"],
                },
                "handler": self.start_nmap_scan,
            },
            "import_nmap_xml": {
                "description": "Import an nmap XML report that exists on the Legion host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "run_actions": {"type": "boolean"},
                    },
                    "required": ["path"],
                },
                "handler": self.import_nmap_xml,
            },
            "run_scheduler": {
                "description": "Start a governed scheduler run over the open project.",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
                "handler": self.run_scheduler,
            },
            "list_jobs": {
                "description": "Background jobs (scans, imports, tool runs, scheduler runs) with status.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                    "required": [],
                },
                "handler": self.list_jobs,
            },
            "get_job": {
                "description": "Status, error and result of one background job.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"job_id": {"type": "integer"}},
                    "required": ["job_id"],
                },
                "handler": self.get_job,
            },
            "list_processes": {
                "description": "Tracked tool processes (running and finished) with host, port, status and timing.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                    "required": [],
                },
                "handler": self.list_processes,
            },
            "get_process_output": {
                "description": "A slice of a process's captured output.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "process_id": {"type": "integer"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer", "description": "Max characters (default 20000)"},
                    },
                    "required": ["process_id"],
                },
                "handler": self.get_process_output,
            },
            "kill_process": {
                "description": "Stop a running tracked process.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"process_id": {"type": "integer"}},
                    "required": ["process_id"],
                },
                "handler": self.kill_process,
            },
            "list_scan_history": {
                "description": "Submitted scans and imports with their status and result summary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                    "required": [],
                },
                "handler": self.list_scan_history,
            },
        }

    def _ensure_runtime(self):
        if self._runtime is not None:
            return self._runtime

        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.shell.DefaultShell import DefaultShell
        from app.tools.ToolCoordinator import ToolCoordinator
        from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
        from app.web.runtime import WebRuntime
        from db.RepositoryFactory import RepositoryFactory

        shell = DefaultShell()
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(shell, repository_factory, getAppLogger())
        nmap_exporter = DefaultNmapExporter(shell, getAppLogger())
        tool_coordinator = ToolCoordinator(shell, nmap_exporter)
        logic = Logic(shell, project_manager, tool_coordinator)
        if getattr(logic, "activeProject", None) is None:
            logic.createNewTemporaryProject()
            self._own_temporary_project = logic.activeProject
        self._runtime = WebRuntime(logic)
        return self._runtime

    def close(self):
        """Remove the temporary project this server created, if it is still open, still temporary and still empty.

        Every session that makes a tool call starts one; without this each leaves a project file and two
        directories in the temp directory, and list_projects offers them all back. A temporary project that holds
        hosts or tool runs is kept: the agent may simply not have saved yet.
        """
        project = getattr(self, "_own_temporary_project", None)
        runtime = self._runtime
        if project is None or runtime is None:
            return
        try:
            logic = runtime.logic
            if getattr(logic, "activeProject", None) is not project or not project.properties.isTemporary:
                return
            from sqlalchemy import text as sql_text

            session = project.database.session()
            try:
                used = 0
                for table in ("hostObj", "process", "scheduler_pending_approval"):
                    try:
                        used += int(session.execute(sql_text(f'SELECT COUNT(*) FROM "{table}"')).scalar() or 0)
                    except Exception:
                        session.rollback()  # the approval table only exists once something was queued
            finally:
                session.close()
            if used:
                return
            logic.projectManager.closeProject(project)
            project.database.dispose()
            logic.activeProject = None
            self._own_temporary_project = None
        except Exception:
            pass  # best effort at exit; never turn a clean shutdown into a traceback

    async def list_projects(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.project_service import ProjectService

        service = ProjectService(runtime)
        listing = service.list_projects({"limit": _int_arg(arguments, "limit", 500)})
        return {
            "projects": listing.get("projects", []),
            "current_project": runtime.get_project_details(),
        }

    async def open_project(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.project_service import ProjectService

        return ProjectService(runtime).open_project(arguments)

    async def save_project(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.project_service import ProjectService

        body, _status_code = ProjectService(runtime).save_project_as({
            "path": str(arguments.get("path", "") or "").strip(),
            "replace": _bool_arg(arguments, "replace", True),
        }, prefer_async=False)
        return {"project": body.get("project", {})}

    async def run_discovery(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.scan_service import ScanService

        service = ScanService(runtime)
        return service.run_discovery({
            "target": str(arguments.get("target", "localhost") or "localhost"),
            "run_actions": _bool_arg(arguments, "run_actions", False),
        })

    async def get_engagement_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        _ = arguments
        runtime = self._ensure_runtime()
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).get_engagement_policy()

    async def set_engagement_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).update_engagement_policy(arguments or {})

    async def get_plan_preview(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).get_plan_preview(arguments)

    async def list_approvals(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).list_approvals(arguments)

    async def approve_approval(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        approval_id = _int_arg(arguments, "approval_id", 0)
        if approval_id <= 0:
            raise ValueError("approval_id is required")
        from app.web.services.scheduler_service import SchedulerService

        body, _status_code = SchedulerService(runtime).approve_approval(approval_id, {
            "approve_family": _bool_arg(arguments, "approve_family", False),
            "run_now": _bool_arg(arguments, "run_now", False),
            "family_action": str(arguments.get("family_action", "") or ""),
        })
        return {
            "approval": body.get("approval", {}),
            "job": body.get("job"),
        }

    async def execute_approved_plan_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        approval_id = _int_arg(arguments, "approval_id", 0)
        if approval_id <= 0:
            raise ValueError("approval_id is required")
        from app.web.services.scheduler_service import SchedulerService

        body, _status_code = SchedulerService(runtime).approve_approval(approval_id, {
            "approve_family": _bool_arg(arguments, "approve_family", False),
            "run_now": True,
            "family_action": str(arguments.get("family_action", "") or ""),
        })
        return {
            "approval": body.get("approval", {}),
            "job": body.get("job"),
        }

    async def reject_approval(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        approval_id = _int_arg(arguments, "approval_id", 0)
        if approval_id <= 0:
            raise ValueError("approval_id is required")
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).reject_approval(approval_id, {
            "reason": str(arguments.get("reason", "rejected via MCP") or "rejected via MCP"),
            "family_action": str(arguments.get("family_action", "") or ""),
        })

    async def query_graph(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.graph_service import GraphService

        return GraphService(runtime).get_graph(arguments)

    async def query_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.workspace_service import WorkspaceService

        return WorkspaceService(runtime).list_findings({
            "host_id": _int_arg(arguments, "host_id", 0),
            "limit": _int_arg(arguments, "limit", 1000),
        })

    async def query_state(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.workspace_service import WorkspaceService

        return WorkspaceService(runtime).get_host_target_state(
            _int_arg(arguments, "host_id", 0),
            limit=_int_arg(arguments, "limit", 500),
        )

    async def export_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.report_service import ReportService

        return ReportService(runtime).export_report(arguments)

    async def list_execution_traces(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).list_executions(arguments)

    async def get_execution_trace(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        execution_id = str(arguments.get("execution_id", "") or "").strip()
        if not execution_id:
            raise ValueError("execution_id is required")
        from app.web.services.scheduler_service import SchedulerService

        return SchedulerService(runtime).get_execution_trace(execution_id, arguments)

    async def create_annotation(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        from app.web.services.graph_service import GraphService

        return {"annotation": GraphService(runtime).save_annotation(arguments)["annotation"]}

    async def list_hosts(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.workspace_service import WorkspaceService

        return WorkspaceService(self._ensure_runtime()).list_workspace_hosts({
            "limit": _int_arg(arguments, "limit", 500),
            "filter": str(arguments.get("filter", "") or ""),
            "service": str(arguments.get("service", "") or ""),
            "category": str(arguments.get("category", "") or ""),
        })

    async def get_host(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.workspace_service import WorkspaceService

        return WorkspaceService(self._ensure_runtime()).get_host_workspace(_int_arg(arguments, "host_id", 0))

    async def list_services(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.workspace_service import WorkspaceService

        return WorkspaceService(self._ensure_runtime()).list_workspace_services({
            "limit": _int_arg(arguments, "limit", 500),
            "host_id": _int_arg(arguments, "host_id", 0),
            "category": str(arguments.get("category", "") or ""),
        })

    async def list_tool_catalog(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.tool_service import ToolService

        return ToolService(self._ensure_runtime()).list_workspace_tools({
            "service": str(arguments.get("service", "") or ""),
            "port": str(arguments.get("port", "") or ""),
            "protocol": str(arguments.get("protocol", "tcp") or "tcp"),
            "limit": _int_arg(arguments, "limit", 500),
        })

    async def run_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.tool_service import ToolService

        return ToolService(self._ensure_runtime()).start_governed_tool_run(dict(arguments or {}), requested_by="MCP")

    async def start_nmap_scan(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.scan_service import ScanService

        return ScanService(self._ensure_runtime()).nmap_scan(dict(arguments or {}))

    async def import_nmap_xml(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.scan_service import ScanService

        return ScanService(self._ensure_runtime()).import_nmap_xml(dict(arguments or {}))

    async def run_scheduler(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.scheduler_service import SchedulerService

        body, _status = SchedulerService(self._ensure_runtime()).start_run()
        return dict(body or {})

    async def list_jobs(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.runtime_service import RuntimeService

        return RuntimeService(self._ensure_runtime()).list_jobs({"limit": _int_arg(arguments, "limit", 100)})

    async def get_job(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.runtime_service import RuntimeService

        return RuntimeService(self._ensure_runtime()).get_job(_int_arg(arguments, "job_id", 0))

    async def list_processes(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.runtime_service import RuntimeService

        return RuntimeService(self._ensure_runtime()).list_processes({"limit": _int_arg(arguments, "limit", 200)})

    async def get_process_output(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.process_service import ProcessService

        return ProcessService(self._ensure_runtime()).get_process_output(
            _int_arg(arguments, "process_id", 0),
            {"offset": _int_arg(arguments, "offset", 0), "limit": _int_arg(arguments, "limit", 20000)},
        )

    async def kill_process(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.process_service import ProcessService

        return ProcessService(self._ensure_runtime()).kill_process(_int_arg(arguments, "process_id", 0))

    async def list_scan_history(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from app.web.services.scan_service import ScanService

        return ScanService(self._ensure_runtime()).scan_history(_int_arg(arguments, "limit", 200))

    def _tool_listing(self):
        return [
            {"name": name, "description": tool["description"], "inputSchema": tool["inputSchema"]}
            for name, tool in self.tools.items()
        ]

    @staticmethod
    def _jsonrpc_result(request: Dict[str, Any], result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}

    @staticmethod
    def _jsonrpc_error(request: Dict[str, Any], code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": int(code), "message": str(message)}}

    async def _call_tool(self, tool_name: str, arguments: Any):
        tool = self.tools.get(str(tool_name or ""))
        if tool is None:
            raise KeyError(f"Tool not found: {tool_name}")
        return await tool["handler"](dict(arguments or {}) if isinstance(arguments, dict) else {})

    async def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatch one JSON-RPC request.

        Implements the Model Context Protocol methods (initialize, ping, tools/list, tools/call, plus empty
        resources/prompts listings) so standard MCP clients can connect over stdio, and keeps the pre-MCP
        `list_tools` / `call_tool` methods for existing scripts. Notifications (no id) get no response.
        """
        method = str(request.get("method", "") or "")
        params = request.get("params", {}) if isinstance(request.get("params", {}), dict) else {}
        is_notification = "id" not in request

        if method == "initialize":
            from app.ApplicationInfo import applicationInfo

            return self._jsonrpc_result(request, {
                "protocolVersion": str(params.get("protocolVersion") or MCP_PROTOCOL_VERSION),
                "capabilities": {"tools": {"listChanged": False}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "legion", "version": str(applicationInfo.get("version", "0.0.0"))},
                "instructions": (
                    "Legion exposes a reconnaissance project: list_hosts/get_host for inventory, "
                    "start_nmap_scan/import_nmap_xml to add data, list_tool_catalog/run_tool for single tools, "
                    "run_scheduler and the approval tools for governed follow-up, and query_* / export_report for results."
                ),
            })
        if method.startswith("notifications/"):
            return None
        if method == "ping":
            return self._jsonrpc_result(request, {})
        if method in {"tools/list", "list_tools"}:
            listing = self._tool_listing()
            return self._jsonrpc_result(request, {"tools": listing} if method == "tools/list" else listing)
        if method in {"resources/list", "resources/templates/list"}:
            return self._jsonrpc_result(request, {"resources": [], "resourceTemplates": []})
        if method == "prompts/list":
            return self._jsonrpc_result(request, {"prompts": []})
        if method in {"tools/call", "call_tool"}:
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if tool_name not in self.tools:
                return self._jsonrpc_error(request, -32601, "Tool not found")
            if method == "call_tool":
                return self._jsonrpc_result(request, await self._call_tool(tool_name, arguments))
            try:
                result = await self._call_tool(tool_name, arguments)
            except Exception as exc:  # tool errors are reported in-band per the MCP spec
                return self._jsonrpc_result(request, {
                    "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                    "isError": True,
                })
            return self._jsonrpc_result(request, {
                "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
                "structuredContent": result if isinstance(result, dict) else {"result": result},
                "isError": False,
            })
        if is_notification:
            return None
        return self._jsonrpc_error(request, -32601, "Method not found")

    async def run(self):
        reader = asyncio.StreamReader(limit=_MAX_REQUEST_LINE_BYTES)
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        try:
            await self._serve(reader)
        finally:
            self.close()

    async def _serve(self, reader):
        while True:
            line = await _read_request_line(reader)
            if line is None:
                print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32600,
                    "message": f"Invalid Request: request line exceeds {_MAX_REQUEST_LINE_BYTES} bytes",
                }}), flush=True)
                continue
            if not line:
                break
            request_id = None
            try:
                try:
                    request = json.loads(line.decode())
                except (ValueError, UnicodeDecodeError) as exc:
                    error = {"code": -32700, "message": f"Parse error: {exc}"}
                else:
                    if not isinstance(request, dict):
                        error = {"code": -32600, "message": "Invalid Request: expected a JSON object"}
                    else:
                        request_id = request.get("id")
                        response = await self.handle_request(request)
                        if response is not None:
                            print(json.dumps(response, default=str), flush=True)
                        continue
            except Exception as exc:
                error = {"code": -32000, "message": str(exc)}
            print(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": error}), flush=True)


if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.run())
