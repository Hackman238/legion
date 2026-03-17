import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


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
        self._runtime = WebRuntime(logic)
        return self._runtime

    async def list_projects(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return {
            "projects": runtime.list_projects(limit=_int_arg(arguments, "limit", 500)),
            "current_project": runtime.get_project_details(),
        }

    async def open_project(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        path = str(arguments.get("path", "") or "").strip()
        if not path:
            raise ValueError("path is required")
        runtime = self._ensure_runtime()
        return {"project": runtime.open_project(path)}

    async def save_project(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        path = str(arguments.get("path", "") or "").strip()
        if not path:
            raise ValueError("path is required")
        runtime = self._ensure_runtime()
        return {
            "project": runtime.save_project_as(
                path,
                replace=_bool_arg(arguments, "replace", True),
            )
        }

    async def run_discovery(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        debug_info = {
            "sys_executable": sys.executable,
            "sys_path": sys.path,
        }
        try:
            import os
            import time

            from app.cli_utils import run_nmap_scan
            from app.importers.nmap_runner import import_nmap_xml_into_project

            runtime = self._ensure_runtime()
            logic = runtime.logic
            target = str(arguments.get("target", "localhost") or "localhost")
            run_actions = _bool_arg(arguments, "run_actions", False)

            runtime.create_new_temporary_project()
            host_repository = logic.activeProject.repositoryContainer.hostRepository
            session = logic.activeProject.database.session()
            try:
                db_host = host_repository.getHostInformation(target)
                if not db_host:
                    from db.entities.host import hostObj
                    hid = hostObj(
                        ip=target,
                        ipv4=target,
                        ipv6="",
                        macaddr="",
                        status="",
                        hostname=target,
                        vendor="",
                        uptime="",
                        lastboot="",
                        distance="",
                        state="",
                        count="",
                    )
                    session.add(hid)
                    session.commit()
            finally:
                session.close()

            output_prefix = os.path.join(
                logic.activeProject.properties.runningFolder,
                f"mcp-nmap-{int(time.time())}",
            )
            nmap_xml = run_nmap_scan(
                target,
                output_prefix,
                discovery=True,
                staged=False,
            )
            if not nmap_xml or not os.path.isfile(nmap_xml):
                return {
                    "target": target,
                    "error": "Nmap scan failed or produced no XML output",
                    "debug_info": debug_info,
                }

            import_nmap_xml_into_project(
                project=logic.activeProject,
                xml_path=nmap_xml,
                output="",
                update_progress_observable=None,
                host_repository=host_repository,
            )
            if run_actions:
                logic.run_scripted_actions()

            hosts = host_repository.getAllHostObjs()
            results = []
            for host in hosts:
                host_dict = host.__dict__.copy()
                host_dict.pop("_sa_instance_state", None)
                try:
                    ports = logic.activeProject.repositoryContainer.portRepository.getPortsByHostId(host.id)
                except Exception:
                    ports = []
                ports_data = []
                for port in ports:
                    port_dict = port.__dict__.copy()
                    port_dict.pop("_sa_instance_state", None)
                    try:
                        service = (
                            logic.activeProject.repositoryContainer.serviceRepository.getServiceById(port.serviceId)
                            if hasattr(port, "serviceId") and port.serviceId
                            else None
                        )
                    except Exception:
                        service = None
                    if service:
                        service_dict = service.__dict__.copy()
                        service_dict.pop("_sa_instance_state", None)
                        port_dict["service"] = service_dict
                    ports_data.append(port_dict)
                host_dict["ports"] = ports_data
                results.append(host_dict)

            return {
                "target": target,
                "run_actions": run_actions,
                "project": runtime.get_project_details(),
                "results": results,
                "debug_info": debug_info,
            }
        except Exception as exc:
            return {
                "target": str(arguments.get("target", "localhost") or "localhost"),
                "error": str(exc),
                "debug_info": debug_info,
            }

    async def get_engagement_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        _ = arguments
        runtime = self._ensure_runtime()
        return runtime.get_engagement_policy()

    async def set_engagement_policy(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return runtime.set_engagement_policy(arguments or {})

    async def get_plan_preview(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return runtime.get_scheduler_plan_preview(
            host_id=_int_arg(arguments, "host_id", 0),
            host_ip=str(arguments.get("host_ip", "") or ""),
            service=str(arguments.get("service", "") or ""),
            port=str(arguments.get("port", "") or ""),
            protocol=str(arguments.get("protocol", "tcp") or "tcp"),
            mode=str(arguments.get("mode", "compare") or "compare"),
            limit_targets=_int_arg(arguments, "limit_targets", 20),
            limit_actions=_int_arg(arguments, "limit_actions", 6),
        )

    async def list_approvals(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return {
            "approvals": runtime.get_scheduler_approvals(
                limit=_int_arg(arguments, "limit", 200),
                status=str(arguments.get("status", "") or "").strip().lower() or None,
            )
        }

    async def approve_approval(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        approval_id = _int_arg(arguments, "approval_id", 0)
        if approval_id <= 0:
            raise ValueError("approval_id is required")
        return runtime.approve_scheduler_approval(
            approval_id=approval_id,
            approve_family=_bool_arg(arguments, "approve_family", False),
            run_now=_bool_arg(arguments, "run_now", False),
            family_action=str(arguments.get("family_action", "") or ""),
        )

    async def execute_approved_plan_step(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        approval_id = _int_arg(arguments, "approval_id", 0)
        if approval_id <= 0:
            raise ValueError("approval_id is required")
        return runtime.approve_scheduler_approval(
            approval_id=approval_id,
            approve_family=_bool_arg(arguments, "approve_family", False),
            run_now=True,
            family_action=str(arguments.get("family_action", "") or ""),
        )

    async def reject_approval(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        approval_id = _int_arg(arguments, "approval_id", 0)
        if approval_id <= 0:
            raise ValueError("approval_id is required")
        return {
            "approval": runtime.reject_scheduler_approval(
                approval_id=approval_id,
                reason=str(arguments.get("reason", "rejected via MCP") or "rejected via MCP"),
                family_action=str(arguments.get("family_action", "") or ""),
            )
        }

    async def query_graph(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return runtime.get_evidence_graph(filters={
            "node_types": list(arguments.get("node_types", []) or []),
            "edge_types": list(arguments.get("edge_types", []) or []),
            "source_kinds": list(arguments.get("source_kinds", []) or []),
            "min_confidence": float(arguments.get("min_confidence", 0.0) or 0.0),
            "search": str(arguments.get("search", "") or ""),
            "include_ai_suggested": _bool_arg(arguments, "include_ai_suggested", True),
            "host_id": _int_arg(arguments, "host_id", 0) or None,
            "limit_nodes": _int_arg(arguments, "limit_nodes", 600),
            "limit_edges": _int_arg(arguments, "limit_edges", 1200),
        })

    async def query_findings(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return runtime.get_findings(
            host_id=_int_arg(arguments, "host_id", 0),
            limit_findings=_int_arg(arguments, "limit", 1000),
        )

    async def query_state(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return runtime.get_target_state_view(
            host_id=_int_arg(arguments, "host_id", 0),
            limit=_int_arg(arguments, "limit", 500),
        )

    async def export_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        scope = str(arguments.get("scope", "project") or "project").strip().lower() or "project"
        output_format = str(arguments.get("format", "json") or "json").strip().lower() or "json"
        if output_format not in {"json", "md", "markdown"}:
            output_format = "json"
        if output_format == "markdown":
            output_format = "md"

        if scope == "host":
            host_id = _int_arg(arguments, "host_id", 0)
            if host_id <= 0:
                raise ValueError("host_id is required when scope=host")
            report = runtime.get_host_ai_report(host_id)
            if output_format == "md":
                return {
                    "scope": "host",
                    "format": "md",
                    "host_id": host_id,
                    "body": runtime.render_host_ai_report_markdown(report),
                }
            return {
                "scope": "host",
                "format": "json",
                "host_id": host_id,
                "report": report,
            }

        report = runtime.get_project_ai_report()
        if output_format == "md":
            return {
                "scope": "project",
                "format": "md",
                "body": runtime.render_project_ai_report_markdown(report),
            }
        return {
            "scope": "project",
            "format": "json",
            "report": report,
        }

    async def list_execution_traces(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return {
            "executions": runtime.get_scheduler_execution_traces(
                limit=_int_arg(arguments, "limit", 200),
                host_id=_int_arg(arguments, "host_id", 0),
                host_ip=str(arguments.get("host_ip", "") or ""),
                tool_id=str(arguments.get("tool_id", "") or ""),
                include_output=_bool_arg(arguments, "include_output", False),
            )
        }

    async def get_execution_trace(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        execution_id = str(arguments.get("execution_id", "") or "").strip()
        if not execution_id:
            raise ValueError("execution_id is required")
        return runtime.get_scheduler_execution_trace(
            execution_id,
            output_max_chars=_int_arg(arguments, "max_chars", 4000),
        )

    async def create_annotation(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        runtime = self._ensure_runtime()
        return {
            "annotation": runtime.save_evidence_graph_annotation(
                target_kind=str(arguments.get("target_kind", "") or ""),
                target_ref=str(arguments.get("target_ref", "") or ""),
                body=str(arguments.get("body", "") or ""),
                created_by=str(arguments.get("created_by", "") or "operator"),
                source_ref=str(arguments.get("source_ref", "") or ""),
                annotation_id=str(arguments.get("annotation_id", "") or ""),
            )
        }

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if request.get("method") == "list_tools":
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": [
                    {
                        "name": name,
                        "description": tool["description"],
                        "inputSchema": tool["inputSchema"],
                    }
                    for name, tool in self.tools.items()
                ],
            }
        if request.get("method") == "call_tool":
            tool_name = request.get("params", {}).get("name")
            arguments = request.get("params", {}).get("arguments", {})
            if tool_name in self.tools:
                result = await self.tools[tool_name]["handler"](arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": result,
                }
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": "Tool not found"},
            }
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {"code": -32601, "message": "Method not found"},
        }

    async def run(self):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                request = json.loads(line.decode())
                response = await self.handle_request(request)
                print(json.dumps(response), flush=True)
            except Exception as exc:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id") if "request" in locals() else None,
                    "error": {"code": -32000, "message": str(exc)},
                }
                print(json.dumps(error_response), flush=True)


if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.run())
