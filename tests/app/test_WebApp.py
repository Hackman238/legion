import unittest
import tempfile
import io
import json
import os
import zipfile
from types import SimpleNamespace


class DummySchedulerConfig:
    def __init__(self):
        self.state = {
            "mode": "deterministic",
            "goal_profile": "internal_asset_discovery",
            "engagement_policy": {
                "preset": "internal_recon",
                "preset_label": "Internal Recon",
                "scope": "internal",
                "intent": "recon",
                "allow_exploitation": False,
                "allow_lateral_movement": False,
                "credential_attack_mode": "blocked",
                "lockout_risk_mode": "blocked",
                "stability_risk_mode": "approval",
                "detection_risk_mode": "low",
                "approval_mode": "risky",
                "runner_preference": "local",
                "noise_budget": "low",
                "custom_overrides": {},
                "legacy_goal_profile": "internal_asset_discovery",
            },
            "provider": "none",
            "providers": {},
            "feature_flags": {
                "graph_workspace": True,
                "optional_runners": True,
            },
            "project_report_delivery": {
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
            },
            "dangerous_categories": [],
            "preapproved_command_families": [],
        }

    def update_preferences(self, updates):
        updates = dict(updates or {})
        if isinstance(updates.get("engagement_policy"), dict):
            policy = dict(self.state.get("engagement_policy", {}))
            policy.update(updates.get("engagement_policy", {}))
            updates["engagement_policy"] = policy
        if isinstance(updates.get("feature_flags"), dict):
            feature_flags = dict(self.state.get("feature_flags", {}))
            feature_flags.update(updates.get("feature_flags", {}))
            updates["feature_flags"] = feature_flags
        elif "goal_profile" in updates:
            policy = dict(self.state.get("engagement_policy", {}))
            policy["preset"] = "external_pentest" if str(updates.get("goal_profile", "")).strip().lower() == "external_pentest" else "internal_recon"
            updates["engagement_policy"] = policy
        self.state.update(updates)
        if isinstance(self.state.get("engagement_policy"), dict):
            preset = str(self.state["engagement_policy"].get("preset", "") or "").strip().lower()
            self.state["goal_profile"] = "external_pentest" if preset in {"external_recon", "external_pentest"} else "internal_asset_discovery"
        return self.state

    def approve_family(self, family_id, metadata):
        self.state["preapproved_command_families"].append({"family_id": family_id, **metadata})
        return self.state


class DummyRuntime:
    def __init__(self):
        self.scheduler_config = DummySchedulerConfig()
        self.project = {
            "name": "demo",
            "output_folder": "/tmp/demo-tool-output",
            "running_folder": "/tmp/demo-running",
            "is_temporary": False,
        }
        self.jobs = [
            {
                "id": 1,
                "type": "import-targets",
                "status": "completed",
                "created_at": "2026-02-17T00:00:00Z",
                "started_at": "2026-02-17T00:00:01Z",
                "finished_at": "2026-02-17T00:00:02Z",
                "payload": {"path": "/tmp/targets.txt"},
                "result": {"added": 4},
                "error": "",
            }
        ]
        self.scan_history = [
            {
                "id": 1,
                "submission_kind": "nmap_scan",
                "status": "completed",
                "target_summary": "10.0.0.0/24",
                "scope_summary": "subnets: 10.0.0.0/24",
                "targets": ["10.0.0.0/24", "10.0.0.5"],
                "discovery": True,
                "staged": False,
                "run_actions": False,
                "nmap_path": "nmap",
                "nmap_args": "",
                "scan_mode": "easy",
                "scan_options": {"top_ports": 1000, "timing": "T3", "service_detection": True, "default_scripts": True},
                "created_at": "2026-02-17T00:00:00Z",
                "result_summary": "imported 4 hosts",
            }
        ]
        self.workspace_hosts = [
            {"id": 11, "ip": "10.0.0.5", "hostname": "dc01.local", "status": "up", "os": "windows", "open_ports": 2, "total_ports": 2, "services": ["kerberos", "smb"]},
            {"id": 12, "ip": "10.0.0.6", "hostname": "filesrv.local", "status": "down", "os": "windows", "open_ports": 0, "total_ports": 1, "services": []},
            {"id": 13, "ip": "10.0.0.7", "hostname": "web01.local", "status": "up", "os": "linux", "open_ports": 4, "total_ports": 5, "services": ["http", "https", "ssh"]},
        ]
        self.workspace_services = [
            {"service": "http", "host_count": 1, "port_count": 1, "protocols": ["tcp"]},
            {"service": "https", "host_count": 1, "port_count": 1, "protocols": ["tcp"]},
            {"service": "kerberos", "host_count": 1, "port_count": 1, "protocols": ["tcp"]},
            {"service": "smb", "host_count": 1, "port_count": 1, "protocols": ["tcp"]},
            {"service": "ssh", "host_count": 1, "port_count": 1, "protocols": ["tcp"]},
        ]
        self.tool_install_requests = []
        self.workspace_tools = [
            {
                "label": "SMB Enum Users",
                "tool_id": "smb-enum-users.nse",
                "command_template": "nmap --script=smb-enum-users [IP] -p [PORT]",
                "service_scope": ["smb"],
                "danger_categories": [],
                "run_count": 1,
                "last_status": "Finished",
                "last_start": "2026-02-17T00:00:00Z",
            }
        ]
        self.workspace_host_detail = {
            "host": {"id": 11, "ip": "10.0.0.5", "hostname": "dc01.local", "status": "up", "os": "windows"},
            "note": "host note",
            "ports": [
                {
                    "id": 1,
                    "port": "445",
                    "protocol": "tcp",
                    "state": "open",
                    "service": {"id": 1, "name": "smb", "product": "samba", "version": "4.x", "extrainfo": ""},
                    "scripts": [{
                        "id": 100,
                        "script_id": "nmap",
                        "output": "Starting Nmap 7.80\nNmap scan report for dc01.local\nHost is up.\n| smb-security-mode:\n|   message_signing: disabled\n|_  challenge_response: supported\nNmap done: 1 IP address",
                        "display_output": "| smb-security-mode: |   message_signing: disabled |_  challenge_response: supported",
                    }],
                }
            ],
            "cves": [{"id": 50, "name": "CVE-2025-0001", "severity": "high", "product": "samba", "url": ""}],
            "screenshots": [{"filename": "10.0.0.5-445-screenshot.png", "port": "445", "url": "/api/screenshots/10.0.0.5-445-screenshot.png"}],
            "ai_analysis": {
                "provider": "openai",
                "goal_profile": "internal_asset_discovery",
                "updated_at": "2026-02-18T12:00:00+00:00",
                "next_phase": "targeted_checks",
                "host_updates": {
                    "hostname": "dc01.local",
                    "hostname_confidence": 95,
                    "os": "windows",
                    "os_confidence": 92,
                },
                "technologies": [{"name": "samba", "version": "4.x", "cpe": "cpe:/a:samba:samba:4", "evidence": "nmap service"}],
                "findings": [{"title": "SMB signing not required", "severity": "high", "cvss": 7.5, "cve": "", "evidence": "smb-security-mode"}],
                "manual_tests": [{"why": "validate relay path", "command": "ntlmrelayx.py -tf targets.txt", "scope_note": "requires approval"}],
            },
            "target_state": {
                "last_mode": "deterministic",
                "engagement_preset": "internal_recon",
                "attempted_actions": [{"tool_id": "smb-enum-users.nse", "status": "executed"}],
                "coverage_gaps": [{"gap_id": "missing_smb_signing_checks"}],
                "urls": [],
                "credentials": [],
                "sessions": [],
            },
        }
        self.scheduler_approvals = [
            {
                "id": 77,
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "label": "SMB Bruteforce",
                "tool_id": "smb-default",
                "danger_categories": "credential_bruteforce",
                "risk_tags": "credential_bruteforce,account_lockout_risk",
                "policy_decision": "approval_required",
                "policy_reason": "requires approval under internal pentest",
                "risk_summary": "Could lock or throttle real user accounts.",
                "safer_alternative": "Prefer credential validation against known accounts or low-impact enumeration first.",
                "rationale": "validate weak SMB authentication controls",
                "status": "pending",
            }
        ]
        self.graph_snapshot = {
            "nodes": [
                {
                    "node_id": "graph-node-host",
                    "type": "host",
                    "label": "10.0.0.5",
                    "confidence": 98.0,
                    "source_kind": "observed",
                    "source_ref": "host:10.0.0.5",
                    "properties": {"host_id": 11, "ip": "10.0.0.5"},
                    "evidence_refs": ["host:10.0.0.5"],
                },
                {
                    "node_id": "graph-node-tech",
                    "type": "technology",
                    "label": "samba 4.x",
                    "confidence": 88.0,
                    "source_kind": "observed",
                    "source_ref": "host:11:technology:samba",
                    "properties": {"host_id": 11, "name": "samba", "version": "4.x"},
                    "evidence_refs": ["service banner"],
                },
                {
                    "node_id": "graph-node-finding",
                    "type": "finding",
                    "label": "SMB signing not required",
                    "confidence": 84.0,
                    "source_kind": "ai_suggested",
                    "source_ref": "host:11:finding:smb-signing",
                    "properties": {"host_id": 11, "severity": "high"},
                    "evidence_refs": ["smb-security-mode"],
                },
                {
                    "node_id": "graph-node-artifact-xml",
                    "type": "artifact",
                    "label": "web-nmap-11.xml",
                    "confidence": 90.0,
                    "source_kind": "observed",
                    "source_ref": "artifact:/tmp/web-nmap-11.xml",
                    "properties": {"host_id": 11, "ref": "/tmp/web-nmap-11.xml", "tool_id": "nmap"},
                    "evidence_refs": ["/tmp/web-nmap-11.xml"],
                },
                {
                    "node_id": "graph-node-artifact-gnmap",
                    "type": "artifact",
                    "label": "web-nmap-11.gnmap",
                    "confidence": 90.0,
                    "source_kind": "observed",
                    "source_ref": "artifact:/tmp/web-nmap-11.gnmap",
                    "properties": {"host_id": 11, "ref": "/tmp/web-nmap-11.gnmap", "tool_id": "nmap"},
                    "evidence_refs": ["/tmp/web-nmap-11.gnmap"],
                },
            ],
            "edges": [
                {
                    "edge_id": "graph-edge-host-tech",
                    "type": "fingerprinted_as",
                    "from_node_id": "graph-node-host",
                    "to_node_id": "graph-node-tech",
                    "confidence": 88.0,
                    "source_kind": "observed",
                    "source_ref": "host:11:technology:samba",
                    "properties": {},
                    "evidence_refs": ["service banner"],
                },
                {
                    "edge_id": "graph-edge-host-finding",
                    "type": "contains",
                    "from_node_id": "graph-node-host",
                    "to_node_id": "graph-node-finding",
                    "confidence": 84.0,
                    "source_kind": "ai_suggested",
                    "source_ref": "host:11:finding:smb-signing",
                    "properties": {},
                    "evidence_refs": ["smb-security-mode"],
                },
                {
                    "edge_id": "graph-edge-host-xml",
                    "type": "contains",
                    "from_node_id": "graph-node-host",
                    "to_node_id": "graph-node-artifact-xml",
                    "confidence": 90.0,
                    "source_kind": "observed",
                    "source_ref": "artifact:/tmp/web-nmap-11.xml",
                    "properties": {},
                    "evidence_refs": ["/tmp/web-nmap-11.xml"],
                },
                {
                    "edge_id": "graph-edge-host-gnmap",
                    "type": "contains",
                    "from_node_id": "graph-node-host",
                    "to_node_id": "graph-node-artifact-gnmap",
                    "confidence": 90.0,
                    "source_kind": "observed",
                    "source_ref": "artifact:/tmp/web-nmap-11.gnmap",
                    "properties": {},
                    "evidence_refs": ["/tmp/web-nmap-11.gnmap"],
                },
            ],
            "meta": {
                "total_nodes": 5,
                "total_edges": 4,
                "returned_nodes": 5,
                "returned_edges": 4,
                "filters": {},
            },
        }
        self.graph_layouts = [
            {
                "layout_id": "layout-1",
                "view_id": "attack_surface",
                "name": "default",
                "layout": {"positions": {"graph-node-host": {"x": 10, "y": 20}}},
                "updated_at": "2026-02-18T12:30:00Z",
            }
        ]
        self.graph_annotations = [
            {
                "annotation_id": "annotation-1",
                "target_kind": "node",
                "target_ref": "graph-node-host",
                "body": "Prioritize this host",
                "created_by": "tester",
                "created_at": "2026-02-18T12:31:00Z",
                "updated_at": "2026-02-18T12:31:00Z",
                "source_ref": "unit:test",
            }
        ]
        self.graph_text_path = tempfile.NamedTemporaryFile(prefix="legion-graph-artifact-", suffix=".txt", delete=False).name
        with open(self.graph_text_path, "w", encoding="utf-8") as handle:
            handle.write("Artifact preview line 1\nArtifact preview line 2\n")
        self.graph_image_path = tempfile.NamedTemporaryFile(prefix="legion-graph-shot-", suffix=".png", delete=False).name
        with open(self.graph_image_path, "wb") as handle:
            handle.write(
                b"\x89PNG\r\n\x1a\n"
                b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
                b"\x00\x00\x00\rIDATx\x9cc```\xf8\x0f\x00\x01\x05\x01\x02\xa7m\xa4\x91"
                b"\x00\x00\x00\x00IEND\xaeB`\x82"
            )
        self.execution_traces = [
            {
                "execution_id": "exec-1",
                "step_id": "step-1",
                "action_id": "action-1",
                "tool_id": "smb-enum-users.nse",
                "label": "SMB Enum Users",
                "scheduler_mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "service": "smb",
                "started_at": "2026-02-18T12:00:00Z",
                "finished_at": "2026-02-18T12:00:10Z",
                "runner_type": "local",
                "exit_status": "0",
                "stdout_ref": "/tmp/stdout.log",
                "stderr_ref": "",
                "artifact_refs": ["/tmp/evidence.txt"],
                "approval_id": "",
                "observations_created": ["script:smb-enum-users"],
                "graph_mutations": ["node:graph-node-host"],
                "operator_notes": "",
                "stdout_excerpt": "sample trace",
                "stderr_excerpt": "",
            }
        ]

    def get_snapshot(self):
        return {
            "project": dict(self.project),
            "summary": {
                "hosts": 0,
                "open_ports": 0,
                "services": 0,
                "cves": 0,
                "running_processes": 0,
                "finished_processes": 0,
            },
            "host_filter": "hide_down",
            "hosts": self.get_workspace_hosts(),
            "services": list(self.workspace_services),
            "tools": list(self.workspace_tools),
            "processes": [],
            "scheduler": self.get_scheduler_preferences(),
            "scheduler_decisions": self.get_scheduler_decisions(),
            "scheduler_approvals": list(self.scheduler_approvals),
            "scan_history": list(self.scan_history),
            "jobs": list(self.jobs),
        }

    def get_project_details(self):
        return dict(self.project)

    def list_projects(self, limit=500):
        rows = [
            {
                "name": "demo.legion",
                "path": "/tmp/demo.legion",
                "source": "temp",
                "is_current": True,
                "exists": True,
                "modified_at": "2026-02-18T12:00:00Z",
                "modified_at_epoch": 1739880000.0,
            },
            {
                "name": "saved.legion",
                "path": "/tmp/saved.legion",
                "source": "autosave",
                "is_current": False,
                "exists": True,
                "modified_at": "2026-02-18T11:00:00Z",
                "modified_at_epoch": 1739876400.0,
            },
        ]
        return rows[:limit]

    def create_new_temporary_project(self):
        self.project["name"] = "temp-project"
        self.project["is_temporary"] = True
        return dict(self.project)

    def open_project(self, path):
        if path == "missing.legion":
            raise FileNotFoundError("missing")
        self.project["name"] = path
        self.project["is_temporary"] = False
        return dict(self.project)

    def save_project_as(self, path, replace=True):
        if not path:
            raise ValueError("path required")
        self.project["name"] = path
        self.project["is_temporary"] = False
        return dict(self.project)

    def start_save_project_as_job(self, path, replace=True):
        _ = replace
        if not path:
            raise ValueError("path required")
        self.project["name"] = path
        self.project["is_temporary"] = False
        return {
            "id": 8,
            "type": "project-save-as",
            "status": "queued",
            "payload": {"path": path, "replace": bool(replace)},
        }

    def build_project_bundle_zip(self):
        temp = tempfile.NamedTemporaryFile(prefix="legion-test-bundle-", suffix=".zip", delete=False)
        try:
            temp.write(b"PK\x05\x06" + b"\x00" * 18)
        finally:
            temp.close()
        return temp.name, "legion-session-test.zip"

    def start_restore_project_zip_job(self, path):
        if not path:
            raise ValueError("path required")
        self.project["name"] = "restored.legion"
        self.project["is_temporary"] = False
        return {
            "id": 9,
            "type": "project-restore-zip",
            "status": "queued",
            "payload": {"path": path},
        }

    def start_targets_import_job(self, path):
        if path == "missing.txt":
            raise FileNotFoundError("missing")
        return {
            "id": 2,
            "type": "import-targets",
            "status": "queued",
            "payload": {"path": path},
        }

    def start_nmap_xml_import_job(self, path, run_actions=False):
        return {
            "id": 3,
            "type": "import-nmap-xml",
            "status": "queued",
            "payload": {"path": path, "run_actions": bool(run_actions)},
        }

    def start_nmap_scan_job(
            self,
            targets,
            discovery=True,
            staged=False,
            run_actions=False,
            nmap_path="nmap",
            nmap_args="",
            scan_mode="legacy",
            scan_options=None,
    ):
        if not targets:
            raise ValueError("At least one target is required")
        return {
            "id": 4,
            "type": "nmap-scan",
            "status": "queued",
            "payload": {
                "targets": targets,
                "discovery": bool(discovery),
                "staged": bool(staged),
                "run_actions": bool(run_actions),
                "nmap_path": nmap_path,
                "nmap_args": nmap_args,
                "scan_mode": scan_mode,
                "scan_options": dict(scan_options or {}),
            },
        }

    def start_scheduler_run_job(self):
        return {
            "id": 5,
            "type": "scheduler-run",
            "status": "queued",
            "payload": {},
        }

    def start_host_rescan_job(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "id": 10,
            "type": "nmap-scan",
            "status": "queued",
            "payload": {"targets": ["10.0.0.5"], "scan_mode": "easy"},
        }

    def start_host_dig_deeper_job(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "id": 11,
            "type": "scheduler-dig-deeper",
            "status": "queued",
            "payload": {"host_id": 11, "host_ip": "10.0.0.5"},
        }

    def start_subnet_rescan_job(self, subnet):
        if str(subnet).strip() != "10.0.0.0/24":
            raise KeyError(subnet)
        return {
            "id": 111,
            "type": "nmap-scan",
            "status": "queued",
            "payload": {"targets": ["10.0.0.0/24"], "scan_mode": "easy"},
        }

    def start_host_screenshot_refresh_job(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "id": 12,
            "type": "host-screenshot-refresh",
            "status": "queued",
            "payload": {"host_id": 11, "host_ip": "10.0.0.5", "target_count": 2},
        }

    def start_graph_screenshot_refresh_job(self, host_id, port, protocol="tcp"):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "id": 112,
            "type": "graph-screenshot-refresh",
            "status": "queued",
            "payload": {"host_id": 11, "port": str(port), "protocol": str(protocol or "tcp")},
        }

    def delete_graph_screenshot(self, *, host_id, artifact_ref="", filename="", port="", protocol="tcp"):
        _ = (artifact_ref, port, protocol)
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "deleted": True,
            "host_id": 11,
            "artifact_ref": str(artifact_ref or ""),
            "filename": str(filename or ""),
            "deleted_files": 1,
            "deleted_paths": [f"/tmp/demo-tool-output/screenshots/{filename or 'shot.png'}"],
        }

    def delete_workspace_port(self, *, host_id, port, protocol="tcp"):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "deleted": True,
            "kind": "port",
            "host_id": 11,
            "host_ip": "10.0.0.5",
            "hostname": "dc01.local",
            "port": str(port),
            "protocol": str(protocol or "tcp"),
            "service": "smb",
            "deleted_files": 1,
            "deleted_paths": ["/tmp/demo-tool-output/screenshots/10.0.0.5-445-screenshot.png"],
        }

    def delete_workspace_service(self, *, host_id, port, protocol="tcp", service=""):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "deleted": True,
            "kind": "service",
            "host_id": 11,
            "host_ip": "10.0.0.5",
            "hostname": "dc01.local",
            "port": str(port),
            "protocol": str(protocol or "tcp"),
            "service": str(service or "smb"),
            "deleted_files": 1,
            "deleted_paths": ["/tmp/demo-tool-output/screenshots/10.0.0.5-445-screenshot.png"],
        }

    def delete_host_workspace(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        self.workspace_hosts = []
        self.workspace_host_detail = {
            "host": {},
            "note": "",
            "ports": [],
            "cves": [],
            "screenshots": [],
        }
        return {
            "deleted": True,
            "host_id": 11,
            "host_ip": "10.0.0.5",
            "counts": {"hosts": 1, "ports": 2},
        }

    def start_tool_run_job(self, host_ip, port, protocol, tool_id, command_override="", timeout=300):
        return {
            "id": 6,
            "type": "tool-run",
            "status": "queued",
            "payload": {"host_ip": host_ip, "port": port, "protocol": protocol, "tool_id": tool_id},
        }

    def start_process_retry_job(self, process_id, timeout=300):
        _ = timeout
        return {
            "id": 7,
            "type": "process-retry",
            "status": "queued",
            "payload": {"process_id": int(process_id)},
        }

    def kill_process(self, process_id):
        return {"killed": True, "process_id": int(process_id), "had_live_handle": True}

    def close_process(self, process_id):
        return {"closed": True, "process_id": int(process_id)}

    def clear_processes(self, reset_all=False):
        return {"cleared": True, "reset_all": bool(reset_all)}

    def list_jobs(self, limit=100):
        return self.jobs[:limit]

    def get_job(self, job_id):
        if int(job_id) == 1:
            return self.jobs[0]
        raise KeyError(job_id)

    def start_tool_install_job(self, platform="kali", scope="missing", tool_keys=None):
        request_payload = {
            "platform": str(platform or "kali"),
            "scope": str(scope or "missing"),
            "tool_keys": list(tool_keys or []),
        }
        self.tool_install_requests.append(request_payload)
        return {
            "id": 91,
            "type": "tool-install",
            "status": "queued",
            "payload": request_payload,
        }

    def stop_job(self, job_id):
        if int(job_id) != 1:
            raise KeyError(job_id)
        return {
            "stopped": True,
            "job": {
                **self.jobs[0],
                "status": "cancelled",
                "error": "stopped by user",
            },
            "killed_process_ids": [],
        }

    def get_scheduler_preferences(self):
        return {
            "mode": self.scheduler_config.state["mode"],
            "goal_profile": self.scheduler_config.state["goal_profile"],
            "engagement_policy": self.scheduler_config.state["engagement_policy"],
            "engagement_presets": [
                {"id": "external_recon", "name": "External Recon"},
                {"id": "external_pentest", "name": "External Pentest"},
                {"id": "internal_recon", "name": "Internal Recon"},
                {"id": "internal_pentest", "name": "Internal Pentest"},
                {"id": "custom", "name": "Custom"},
            ],
            "provider": self.scheduler_config.state["provider"],
            "providers": self.scheduler_config.state["providers"],
            "feature_flags": self.scheduler_config.state["feature_flags"],
            "project_report_delivery": self.scheduler_config.state["project_report_delivery"],
            "dangerous_categories": self.scheduler_config.state["dangerous_categories"],
            "preapproved_families_count": len(self.scheduler_config.state["preapproved_command_families"]),
            "cloud_notice": "Cloud AI mode may send host/service metadata to third-party providers.",
        }

    def get_engagement_policy(self):
        return dict(self.scheduler_config.state["engagement_policy"])

    def set_engagement_policy(self, updates):
        policy = dict(self.scheduler_config.state["engagement_policy"])
        policy.update(dict(updates or {}))
        policy["legacy_goal_profile"] = "external_pentest" if policy.get("preset") in {"external_recon", "external_pentest"} else "internal_asset_discovery"
        self.scheduler_config.state["engagement_policy"] = policy
        self.scheduler_config.state["goal_profile"] = policy["legacy_goal_profile"]
        return dict(policy)

    def get_scheduler_decisions(self, limit=100):
        return [
            {
                "id": 1,
                "timestamp": "2026-02-17T00:00:00Z",
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "tool_id": "smb-enum-users.nse",
                "scheduler_mode": "deterministic",
                "approved": "True",
                "executed": "True",
                "reason": "queued",
                "command_family_id": "abc123",
            }
        ][:limit]

    def get_workspace_hosts(self, limit=None, include_down=False, service=""):
        rows = list(self.workspace_hosts)
        if not include_down:
            rows = [row for row in rows if str(row.get("status", "")).strip().lower() != "down"]
        service_filter = str(service or "").strip().lower()
        if service_filter:
            rows = [
                row for row in rows
                if any(str(item or "").strip().lower() == service_filter for item in list(row.get("services", []) or []))
            ]
        if limit is None:
            return rows
        return rows[:limit]

    def get_scan_history(self, limit=200):
        return self.scan_history[:limit]

    def get_workspace_services(self, limit=300, host_id=0):
        normalized_host_id = int(host_id or 0)
        if normalized_host_id > 0:
            host = next((row for row in self.workspace_hosts if int(row.get("id", 0) or 0) == normalized_host_id), None)
            services = list(host.get("services", []) if isinstance(host, dict) else [])
            return [
                {
                    "service": str(service),
                    "host_count": 1,
                    "port_count": 1,
                    "protocols": ["tcp"],
                }
                for service in services[:limit]
            ]
        return self.workspace_services[:limit]

    def get_workspace_tools(self, service="", limit=300):
        return self.workspace_tools[:limit]

    def get_workspace_tools_page(self, service="", limit=300, offset=0):
        _ = service
        rows = list(self.workspace_tools)
        safe_limit = max(1, min(int(limit or 300), 500))
        safe_offset = max(0, int(offset or 0))
        page = rows[safe_offset:safe_offset + safe_limit]
        next_offset = safe_offset + len(page)
        has_more = next_offset < len(rows)
        return {
            "tools": page,
            "offset": safe_offset,
            "limit": safe_limit,
            "total": len(rows),
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
        }

    def get_host_workspace(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return dict(self.workspace_host_detail)

    def get_target_state_view(self, host_id=0, limit=500):
        _ = limit
        if int(host_id or 0) == 11:
            return {
                "host": dict(self.workspace_host_detail["host"]),
                "target_state": dict(self.workspace_host_detail.get("target_state", {})),
            }
        return {
            "count": 1,
            "states": [
                {
                    "host": dict(self.workspace_host_detail["host"]),
                    "target_state": dict(self.workspace_host_detail.get("target_state", {})),
                }
            ],
        }

    def get_findings(self, host_id=0, limit_findings=1000):
        if int(host_id or 0) not in {0, 11}:
            raise KeyError(host_id)
        findings = [
            {
                "host": dict(self.workspace_host_detail["host"]),
                "title": "SMB signing not required",
                "severity": "high",
                "confidence": 84.0,
                "source_kind": "ai_suggested",
                "finding": {"title": "SMB signing not required", "severity": "high"},
            }
        ]
        return {
            "count": min(len(findings), int(limit_findings or 1000)),
            "host_scope_count": 1,
            "findings": findings[:limit_findings],
        }

    def get_scheduler_plan_preview(
            self,
            *,
            host_id=0,
            host_ip="",
            service="",
            port="",
            protocol="tcp",
            mode="compare",
            limit_targets=20,
            limit_actions=6,
    ):
        _ = host_id, host_ip, service, port, protocol, limit_targets, limit_actions
        return {
            "requested_mode": mode,
            "current_mode": "deterministic",
            "engagement_policy": dict(self.scheduler_config.state["engagement_policy"]),
            "target_count": 1,
            "targets": [
                {
                    "target": {
                        "host_id": 11,
                        "host_ip": "10.0.0.5",
                        "hostname": "dc01.local",
                        "port": "445",
                        "protocol": "tcp",
                        "service_name": "smb",
                    },
                    "attempted_tool_ids": ["smb-enum-users.nse"],
                    "mode": "compare",
                    "deterministic": {
                        "requested_mode": "deterministic",
                        "fallback_used": False,
                        "steps": [
                            {
                                "tool_id": "smb-security-mode",
                                "label": "SMB Security Mode",
                                "policy_decision": "allowed",
                            }
                        ],
                    },
                    "ai": {
                        "requested_mode": "ai",
                        "fallback_used": False,
                        "steps": [
                            {
                                "tool_id": "smb-security-mode",
                                "label": "SMB Security Mode",
                                "policy_decision": "allowed",
                            }
                        ],
                    },
                    "agreement": ["smb-security-mode"],
                    "deterministic_only": [],
                    "ai_only": [],
                }
            ],
        }

    def get_host_ai_report(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "generated_at": "2026-02-18T12:01:00+00:00",
            "report_version": 1,
            "host": dict(self.workspace_host_detail["host"]),
            "note": self.workspace_host_detail["note"],
            "ports": [
                {
                    "port": "445",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "smb",
                    "service_product": "samba",
                    "service_version": "4.x",
                    "service_extrainfo": "",
                    "banner": "samba 4.x",
                    "scripts": [{"script_id": "smb-enum-users.nse", "output_excerpt": "sample"}],
                }
            ],
            "cves": list(self.workspace_host_detail["cves"]),
            "screenshots": list(self.workspace_host_detail["screenshots"]),
            "ai_analysis": dict(self.workspace_host_detail.get("ai_analysis", {})),
            "target_state": dict(self.workspace_host_detail.get("target_state", {})),
        }

    def render_host_ai_report_markdown(self, report):
        host = report.get("host", {}) if isinstance(report, dict) else {}
        return (
            "# Legion Host AI Report\n\n"
            f"- Host ID: {host.get('id', '')}\n"
            f"- Host IP: {host.get('ip', '')}\n"
        )

    def get_host_report(self, host_id):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {
            "generated_at": "2026-02-18T12:05:00+00:00",
            "report_version": 2,
            "report_kind": "host",
            "project": dict(self.project),
            "host": dict(self.workspace_host_detail["host"]),
            "scope_and_policy": {"engagement_policy": dict(self.scheduler_config.state["engagement_policy"])},
            "summary_of_discovered_assets": {
                "service_count": 1,
                "url_count": 0,
                "technology_count": 1,
                "finding_count": 1,
                "credential_count": 0,
                "identity_count": 0,
                "session_count": 0,
                "screenshot_count": 1,
                "artifact_count": 1,
            },
            "validated_findings": {
                "count": 1,
                "items": [{"title": "SMB signing not required", "evidence": "smb-security-mode"}],
            },
            "attack_paths": [{"summary": "SMB signing not required --validated_by--> evidence"}],
            "credentials_and_sessions": {"credentials": [], "identities": [], "sessions": []},
            "evidence_references": [{"ref": "smb-security-mode", "kind": "graph_evidence"}],
            "recommended_next_steps": {
                "next_phase": "targeted_checks",
                "manual_tests": [{"why": "validate relay path", "command": "ntlmrelayx.py -tf targets.txt"}],
                "coverage_gaps": [{"gap_id": "missing_smb_signing_checks", "description": "missing signing validation"}],
                "pending_approvals": [],
            },
            "skipped_or_blocked_actions": [{"label": "SMB Bruteforce", "policy_reason": "requires approval"}],
            "methodology_coverage": {
                "last_mode": "deterministic",
                "next_phase": "targeted_checks",
                "attempted_action_count": 1,
                "strategy_packs_seen": ["internal_network"],
                "runner_usage": {"local": 1},
            },
            "observed_facts": [{"label": "samba", "summary": "service banner"}],
            "inferred_relationships": [],
            "ai_suggestions": [{"label": "validate relay path", "summary": "ntlmrelayx.py -tf targets.txt"}],
            "operator_conclusions": [{"label": "Note #1", "summary": "host note"}],
        }

    def render_host_report_markdown(self, report):
        host = report.get("host", {}) if isinstance(report, dict) else {}
        return (
            "# Legion Host Report\n\n"
            f"- Host ID: {host.get('id', '')}\n"
            "## Scope and Policy\n"
        )

    def build_host_ai_reports_zip(self):
        handle = tempfile.NamedTemporaryFile(prefix="test-host-ai-reports-", suffix=".zip", delete=False)
        path = handle.name
        handle.close()
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            report = self.get_host_ai_report(11)
            archive.writestr("bundle/hosts/host-11.json", json.dumps(report))
            archive.writestr("bundle/hosts/host-11.md", self.render_host_ai_report_markdown(report))
            archive.writestr("bundle/manifest.json", json.dumps({"host_count": 1}))
        return path, os.path.basename(path)

    def get_project_ai_report(self):
        return {
            "generated_at": "2026-02-18T12:03:00+00:00",
            "report_version": 1,
            "project": dict(self.project),
            "summary": {
                "hosts": len(self.workspace_hosts),
                "open_ports": 2,
                "services": len(self.workspace_services),
                "cves": 1,
                "running_processes": 0,
                "finished_processes": 1,
            },
            "host_count": 1,
            "hosts": [self.get_host_ai_report(11)],
        }

    def render_project_ai_report_markdown(self, report):
        project = report.get("project", {}) if isinstance(report, dict) else {}
        return (
            "# Legion Project AI Report\n\n"
            f"- Project: {project.get('name', '')}\n"
            f"- Host Count: {report.get('host_count', 0)}\n"
        )

    def get_project_report(self):
        return {
            "generated_at": "2026-02-18T12:06:00+00:00",
            "report_version": 2,
            "report_kind": "project",
            "project": dict(self.project),
            "scope_and_policy": {"engagement_policy": dict(self.scheduler_config.state["engagement_policy"])},
            "summary": {
                "hosts": len(self.workspace_hosts),
                "open_ports": 2,
                "services": len(self.workspace_services),
                "cves": 1,
            },
            "summary_of_discovered_assets": {
                "host_count": 1,
                "service_count": 1,
                "url_count": 0,
                "technology_count": 1,
                "finding_count": 1,
                "credential_count": 0,
                "identity_count": 0,
                "session_count": 0,
                "screenshot_count": 1,
                "artifact_count": 1,
                "hosts": [{"host": dict(self.workspace_host_detail["host"]), "finding_count": 1}],
            },
            "validated_findings": {
                "count": 1,
                "items": [{"title": "SMB signing not required", "evidence": "smb-security-mode"}],
            },
            "attack_paths": [{"summary": "Host -> Finding -> Evidence"}],
            "credentials_and_sessions": {"credentials": [], "identities": [], "sessions": []},
            "evidence_references": [{"ref": "smb-security-mode", "kind": "graph_evidence"}],
            "recommended_next_steps": {
                "next_phases": ["targeted_checks"],
                "manual_tests": [{"why": "validate relay path", "command": "ntlmrelayx.py -tf targets.txt"}],
                "coverage_gaps": [{"gap_id": "missing_smb_signing_checks", "description": "missing signing validation"}],
                "pending_approvals": [],
            },
            "skipped_or_blocked_actions": [{"label": "SMB Bruteforce", "policy_reason": "requires approval"}],
            "methodology_coverage": {
                "attempted_action_count": 1,
                "strategy_packs_seen": ["internal_network"],
                "runner_usage": {"local": 1},
            },
            "hosts": [{"host": dict(self.workspace_host_detail["host"]), "finding_count": 1}],
            "observed_facts": [{"label": "samba", "summary": "service banner"}],
            "inferred_relationships": [],
            "ai_suggestions": [{"label": "validate relay path", "summary": "ntlmrelayx.py -tf targets.txt"}],
            "operator_conclusions": [{"label": "Note #1", "summary": "host note"}],
        }

    def render_project_report_markdown(self, report):
        project = report.get("project", {}) if isinstance(report, dict) else {}
        return (
            "# Legion Project Report\n\n"
            f"- Project: {project.get('name', '')}\n"
            "## Scope and Policy\n"
        )

    def push_project_ai_report(self, overrides=None):
        delivery = dict(self.scheduler_config.state.get("project_report_delivery", {}))
        overrides = overrides or {}
        if isinstance(overrides, dict):
            delivery.update(overrides)
        endpoint = str(delivery.get("endpoint", "") or "").strip()
        if not endpoint:
            return {"ok": False, "error": "Project report delivery endpoint is required."}
        return {
            "ok": True,
            "provider_name": str(delivery.get("provider_name", "") or ""),
            "endpoint": endpoint,
            "method": str(delivery.get("method", "POST")),
            "format": str(delivery.get("format", "json")),
            "status_code": 200,
            "response_body_excerpt": "{\"ok\":true}",
        }

    def push_project_report(self, overrides=None):
        result = self.push_project_ai_report(overrides=overrides)
        result["report_label"] = "project report"
        return result

    def update_host_note(self, host_id, text_value):
        if int(host_id) != 11:
            raise KeyError(host_id)
        self.workspace_host_detail["note"] = text_value
        return {"host_id": int(host_id), "saved": True}

    def create_script_entry(self, host_id, port, protocol, script_id, output):
        if int(host_id) != 11:
            raise KeyError(host_id)
        self.workspace_host_detail["ports"][0]["scripts"].append(
            {"id": 101, "script_id": script_id, "output": output}
        )
        return {"id": 101, "script_id": script_id, "port_id": 1}

    def delete_script_entry(self, script_db_id):
        return {"deleted": True, "id": int(script_db_id)}

    def create_cve_entry(self, host_id, name, **_kwargs):
        if int(host_id) != 11:
            raise KeyError(host_id)
        return {"id": 88, "name": name, "host_id": int(host_id), "created": True}

    def delete_cve_entry(self, cve_id):
        return {"deleted": True, "id": int(cve_id)}

    def get_process_output(self, process_id, offset=0, max_chars=12000):
        _ = max_chars
        if int(process_id) != 1:
            raise KeyError(process_id)
        text = "sample output"
        offset_value = max(0, int(offset or 0))
        chunk = text[offset_value:]
        return {
            "id": 1,
            "name": "smb-enum-users.nse",
            "hostIp": "10.0.0.5",
            "port": "445",
            "protocol": "tcp",
            "command": "echo test",
            "status": "Finished",
            "output": text,
            "output_chunk": chunk,
            "output_length": len(text),
            "offset": offset_value,
            "next_offset": len(text),
            "completed": True,
        }

    def get_script_output(self, script_db_id, offset=0, max_chars=12000):
        _ = max_chars
        if int(script_db_id) != 100:
            raise KeyError(script_db_id)
        text = "script process output"
        offset_value = max(0, int(offset or 0))
        chunk = text[offset_value:]
        return {
            "script_db_id": 100,
            "script_id": "smb-enum-users.nse",
            "source": "process",
            "process_id": 1,
            "command": "nmap --script smb-enum-users.nse",
            "status": "Finished",
            "output": text,
            "output_chunk": chunk,
            "output_length": len(text),
            "offset": offset_value,
            "next_offset": len(text),
            "completed": True,
        }

    def get_screenshot_file(self, filename):
        if filename == "10.0.0.5-445-screenshot.png":
            return __file__
        raise FileNotFoundError(filename)

    def get_scheduler_approvals(self, limit=200, status=None):
        _ = status
        return self.scheduler_approvals[:limit]

    def get_scheduler_execution_traces(self, *, limit=200, host_id=0, host_ip="", tool_id="", include_output=False):
        _ = host_id, host_ip
        rows = list(self.execution_traces)
        if tool_id:
            rows = [item for item in rows if str(item.get("tool_id", "")) == str(tool_id)]
        if not include_output:
            rows = [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"stdout_excerpt", "stderr_excerpt"}
                }
                for item in rows
            ]
        return rows[:limit]

    def get_scheduler_execution_trace(self, execution_id, output_max_chars=4000):
        _ = output_max_chars
        for item in self.execution_traces:
            if str(item.get("execution_id", "")) == str(execution_id):
                return dict(item)
        raise KeyError(execution_id)

    def approve_scheduler_approval(self, approval_id, approve_family=False, run_now=True, family_action=""):
        _ = approve_family
        _ = run_now
        _ = family_action
        if int(approval_id) != 77:
            raise KeyError(approval_id)
        return {"approval": {"id": 77, "status": "approved"}, "job": {"id": 99}}

    def reject_scheduler_approval(self, approval_id, reason="", family_action=""):
        _ = reason
        _ = family_action
        if int(approval_id) != 77:
            raise KeyError(approval_id)
        return {"id": 77, "status": "rejected"}

    def test_scheduler_provider(self, updates=None):
        merged = dict(self.scheduler_config.state)
        updates = updates or {}
        for key, value in updates.items():
            if key == "providers" and isinstance(value, dict):
                providers = dict(merged.get("providers", {}))
                for provider_name, provider_cfg in value.items():
                    existing = dict(providers.get(provider_name, {}))
                    if isinstance(provider_cfg, dict):
                        existing.update(provider_cfg)
                    providers[provider_name] = existing
                merged["providers"] = providers
            else:
                merged[key] = value
        provider = str(merged.get("provider", "none"))
        if provider == "lm_studio":
            return {
                "ok": True,
                "provider": "lm_studio",
                "model": "o3-7b",
                "latency_ms": 41,
            }
        return {
            "ok": False,
            "provider": provider,
            "error": "AI provider is set to none.",
        }

    def get_scheduler_provider_logs(self, limit=200):
        return [
            {
                "timestamp": "2026-02-17T00:00:00Z",
                "provider": "openai",
                "method": "POST",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "api_style": "openai_compatible",
                "request_headers": {"Authorization": "Bearer ***redacted***"},
                "request_body": "{\"model\":\"gpt-5-mini\"}",
                "response_status": 200,
                "response_body": "{\"choices\":[]}",
                "error": "",
            }
        ][:max(1, int(limit or 1))]

    def get_evidence_graph(self, filters=None):
        filters = dict(filters or {})
        nodes = list(self.graph_snapshot.get("nodes", []))
        edges = list(self.graph_snapshot.get("edges", []))

        node_types = {str(item).strip().lower() for item in list(filters.get("node_types", []) or []) if str(item).strip()}
        edge_types = {str(item).strip().lower() for item in list(filters.get("edge_types", []) or []) if str(item).strip()}
        source_kinds = {str(item).strip().lower() for item in list(filters.get("source_kinds", []) or []) if str(item).strip()}
        min_confidence = float(filters.get("min_confidence", 0.0) or 0.0)
        search = str(filters.get("search", "") or "").strip().lower()
        include_ai = bool(filters.get("include_ai_suggested", True))
        hide_nmap_xml_artifacts = bool(filters.get("hide_nmap_xml_artifacts", False))
        host_filter = str(filters.get("host_filter", filters.get("filter", "hide_down")) or "").strip().lower()
        host_id = int(filters.get("host_id", 0) or 0)

        def _artifact_hidden(item):
            if str(item.get("type", "")).strip().lower() != "artifact":
                return False
            filename = str(item.get("label", "") or item.get("properties", {}).get("ref", "")).strip().lower()
            if filename.endswith(".gnmap") or filename.endswith(".nmap"):
                return True
            return hide_nmap_xml_artifacts and filename.endswith(".xml") and "nmap" in filename

        nodes = [item for item in nodes if not _artifact_hidden(item)]

        if host_filter != "show_all":
            down_host_ids = {
                int(item.get("id", 0) or 0)
                for item in list(self.workspace_hosts or [])
                if str(item.get("status", "") or "").strip().lower() == "down"
            }
            nodes = [
                item for item in nodes
                if int(item.get("properties", {}).get("host_id", 0) or 0) not in down_host_ids
            ]

        if not include_ai:
            nodes = [item for item in nodes if str(item.get("source_kind", "")).strip().lower() != "ai_suggested"]
            edges = [item for item in edges if str(item.get("source_kind", "")).strip().lower() != "ai_suggested"]
        if node_types:
            nodes = [item for item in nodes if str(item.get("type", "")).strip().lower() in node_types]
        if source_kinds:
            nodes = [item for item in nodes if str(item.get("source_kind", "")).strip().lower() in source_kinds]
        if min_confidence > 0.0:
            nodes = [item for item in nodes if float(item.get("confidence", 0.0) or 0.0) >= min_confidence]
        if search:
            nodes = [
                item for item in nodes
                if search in str(item.get("label", "")).lower() or search in json.dumps(item.get("properties", {}), sort_keys=True).lower()
            ]
        if host_id > 0:
            nodes = [
                item for item in nodes
                if int(item.get("properties", {}).get("host_id", 0) or 0) == host_id
            ]
        node_ids = {item.get("node_id") for item in nodes}
        filtered_edges = []
        for item in edges:
            if edge_types and str(item.get("type", "")).strip().lower() not in edge_types:
                continue
            if source_kinds and str(item.get("source_kind", "")).strip().lower() not in source_kinds:
                continue
            if min_confidence > 0.0 and float(item.get("confidence", 0.0) or 0.0) < min_confidence:
                continue
            if str(item.get("from_node_id")) not in node_ids or str(item.get("to_node_id")) not in node_ids:
                continue
            filtered_edges.append(item)
        return {
            "nodes": nodes,
            "edges": filtered_edges,
            "meta": {
                "total_nodes": len(self.graph_snapshot.get("nodes", [])),
                "total_edges": len(self.graph_snapshot.get("edges", [])),
                "returned_nodes": len(nodes),
                "returned_edges": len(filtered_edges),
                "filters": {
                    **filters,
                    "hide_down_hosts": host_filter != "show_all",
                },
            },
        }

    def rebuild_evidence_graph(self, host_id=None):
        return {
            "mutations": ["node:graph-node-host", "edge:graph-edge-host-tech"],
            "mutation_count": 2,
            "nodes": len(self.graph_snapshot.get("nodes", [])),
            "edges": len(self.graph_snapshot.get("edges", [])),
            "host_id": host_id,
        }

    def export_evidence_graph_json(self, rebuild=False):
        _ = rebuild
        return dict(self.graph_snapshot)

    def export_evidence_graph_graphml(self, rebuild=False):
        _ = rebuild
        return "<graphml><graph id='demo-graph'></graph></graphml>"

    def get_evidence_graph_layouts(self):
        return list(self.graph_layouts)

    def save_evidence_graph_layout(self, *, view_id, name, layout_state, layout_id=""):
        item = {
            "layout_id": layout_id or "layout-2",
            "view_id": str(view_id),
            "name": str(name),
            "layout": dict(layout_state or {}),
            "updated_at": "2026-02-18T12:32:00Z",
        }
        self.graph_layouts.append(item)
        return item

    def get_evidence_graph_annotations(self, *, target_ref="", target_kind=""):
        rows = list(self.graph_annotations)
        if target_ref:
            rows = [item for item in rows if str(item.get("target_ref", "")) == str(target_ref)]
        if target_kind:
            rows = [item for item in rows if str(item.get("target_kind", "")) == str(target_kind)]
        return rows

    def save_evidence_graph_annotation(
            self,
            *,
            target_kind,
            target_ref,
            body,
            created_by="operator",
            source_ref="",
            annotation_id="",
    ):
        item = {
            "annotation_id": annotation_id or "annotation-2",
            "target_kind": str(target_kind),
            "target_ref": str(target_ref),
            "body": str(body),
            "created_by": str(created_by),
            "created_at": "2026-02-18T12:33:00Z",
            "updated_at": "2026-02-18T12:33:00Z",
            "source_ref": str(source_ref),
        }
        self.graph_annotations.append(item)
        return item

    def get_graph_related_content(self, node_id, max_chars=12000):
        _ = max_chars
        if str(node_id) == "graph-node-host":
            return {
                "node_id": "graph-node-host",
                "entry_count": 2,
                "entries": [
                    {
                        "node_id": "graph-node-artifact",
                        "node_type": "artifact",
                        "label": "evidence.txt",
                        "filename": "evidence.txt",
                        "ref": self.graph_text_path,
                        "kind": "text",
                        "available": True,
                        "preview_text": "Artifact preview line 1\nArtifact preview line 2\n",
                        "preview_url": "",
                        "download_url": "/api/graph/content/graph-node-artifact?download=1",
                        "message": "",
                    },
                    {
                        "node_id": "graph-node-shot",
                        "node_type": "screenshot",
                        "label": "portal.png",
                        "filename": "portal.png",
                        "ref": self.graph_image_path,
                        "kind": "image",
                        "available": True,
                        "preview_text": "",
                        "preview_url": "/api/graph/content/graph-node-shot",
                        "download_url": "/api/graph/content/graph-node-shot?download=1",
                        "message": "",
                    },
                ],
            }
        raise KeyError(node_id)

    def get_graph_content(self, node_id, download=False, max_chars=12000):
        _ = max_chars
        if str(node_id) == "graph-node-artifact":
            return {
                "kind": "text",
                "text": "Artifact preview line 1\nArtifact preview line 2\n",
                "filename": "evidence.txt",
                "mimetype": "text/plain; charset=utf-8",
                "download": bool(download),
            }
        if str(node_id) == "graph-node-shot":
            return {
                "kind": "image",
                "path": self.graph_image_path,
                "filename": "portal.png",
                "mimetype": "image/png",
                "download": bool(download),
            }
        raise KeyError(node_id)


class WebAppTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = DummyRuntime()
        self.app = create_app(self.runtime)
        self.client = self.app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(200, response.status_code)
        self.assertEqual("ok", response.json.get("status"))

    def test_tool_audit_route_returns_rows(self):
        self.runtime.settings = SimpleNamespace(
            tools_path_nmap="",
            tools_path_hydra="",
            tools_path_texteditor="",
            tools_path_responder="",
            tools_path_ntlmrelay="",
            hostActions=[],
            portActions=[],
            portTerminalActions=[],
        )
        response = self.client.get("/api/settings/tool-audit")
        self.assertEqual(200, response.status_code)
        body = response.get_json()
        self.assertIn("summary", body)
        self.assertIn("tools", body)
        self.assertGreater(len(body["tools"]), 10)
        first = body["tools"][0]
        self.assertIn("label", first)
        self.assertIn("status", first)
        self.assertIn("kali_install", first)
        self.assertIn("ubuntu_install", first)

    def test_tool_audit_install_plan_route_returns_script(self):
        self.runtime.settings = SimpleNamespace(
            tools_path_nmap="",
            tools_path_hydra="",
            tools_path_texteditor="",
            tools_path_responder="",
            tools_path_ntlmrelay="",
            hostActions=[],
            portActions=[],
            portTerminalActions=[],
        )
        response = self.client.get("/api/settings/tool-audit/install-plan?platform=ubuntu")
        self.assertEqual(200, response.status_code)
        body = response.get_json()
        self.assertEqual("ubuntu", body.get("platform"))
        self.assertIn("script", body)
        self.assertIn("commands", body)
        self.assertIn("manual", body)
        self.assertIn("supported_platforms", body)

    def test_tool_audit_install_route_queues_job(self):
        response = self.client.post("/api/settings/tool-audit/install", json={
            "platform": "ubuntu",
            "scope": "missing",
        })
        self.assertEqual(202, response.status_code)
        body = response.get_json()
        self.assertEqual("accepted", body.get("status"))
        self.assertEqual("tool-install", body.get("job", {}).get("type"))
        self.assertEqual("ubuntu", self.runtime.tool_install_requests[-1]["platform"])

    def test_index_renders(self):
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        body = response.get_data(as_text=True)
        self.assertIn("<h1>LEGION</h1>", body)
        self.assertIn("v0.6.0", body)
        self.assertIn("Localhost only", body)
        self.assertNotIn("Web Console", body)
        self.assertIn("Graph Workspace", body)
        self.assertIn("graph-workspace-canvas", body)
        self.assertIn("graph-matrix-view", body)
        self.assertIn("graph-zoom-slider", body)
        self.assertIn("graph-hide-nmap-xml-artifacts", body)
        self.assertIn("graph-detail-content-list", body)
        self.assertIn("graph-detail-panel", body)
        self.assertIn("graph-detail-floating-layer", body)
        self.assertIn("graph-host-actions-block", body)
        self.assertIn("graph-port-actions-block", body)
        self.assertIn("graph-service-actions-block", body)
        self.assertIn("graph-subnet-actions-block", body)
        self.assertIn("graph-screenshot-actions-block", body)
        self.assertIn("graph-detail-dock-toggle-button", body)
        self.assertIn("graph-detail-close-button", body)
        self.assertIn("graph-filters-toggle-button", body)
        self.assertIn('aria-label="Show Filters"', body)
        self.assertIn('id="graph-filters-panel" class="graph-filters-panel" hidden', body)
        self.assertIn("graph-layout-tidy-button", body)
        self.assertIn("graph-layout-save-button", body)
        self.assertIn("graph-export-svg-button", body)
        self.assertIn("graph-export-png-button", body)
        self.assertIn("graph-render-mode-select", body)
        self.assertIn("graph-focus-depth-select", body)
        self.assertIn('aria-label="Refresh Graph"', body)
        self.assertIn('aria-label="Tidy Layout"', body)
        self.assertIn('aria-label="Focus Selected"', body)
        self.assertIn("graph-focus-selection-button", body)
        self.assertIn("graph-clear-focus-button", body)
        self.assertIn("graph-expand-selection-button", body)
        self.assertIn("graph-collapse-expanded-button", body)
        self.assertIn("graph-note-open-button", body)
        self.assertIn("graph-note-modal", body)
        self.assertIn("graph-note-save-button", body)
        self.assertIn('id="ribbon-logging-jobs-button"', body)
        self.assertIn('id="ribbon-logging-submitted-scans-button"', body)
        self.assertIn('id="ribbon-logging-scheduler-decisions-button"', body)
        self.assertIn('id="ribbon-settings-menu-button"', body)
        self.assertIn('id="ribbon-settings-menu"', body)
        self.assertIn('id="jobs-modal"', body)
        self.assertIn('id="submitted-scans-modal"', body)
        self.assertIn('id="scheduler-decisions-modal"', body)
        self.assertIn('id="settings-tool-audit-refresh-button"', body)
        self.assertIn('id="settings-tool-audit-body"', body)
        self.assertIn('id="settings-tool-install-platform"', body)
        self.assertIn('id="settings-tool-install-copy-button"', body)
        self.assertIn('id="settings-tool-install-run-button"', body)
        self.assertIn('id="settings-tool-install-script"', body)
        self.assertIn('id="jobs-body"', body)
        self.assertIn('id="scan-history-body"', body)
        self.assertIn('id="decisions-body"', body)
        self.assertIn("ribbon-process-group", body)
        self.assertIn("ribbon-process-table-wrap", body)
        self.assertIn('id="processes-body"', body)
        self.assertIn('id="process-clear-finished-button"', body)
        self.assertIn('aria-label="Hide Finished/Issues"', body)
        self.assertIn('id="process-clear-all-button"', body)
        self.assertIn('aria-label="Hide All Non-Running"', body)
        self.assertIn('id="services-panel-toggle-button"', body)
        self.assertIn('id="services-panel-body" class="table-wrap" hidden', body)
        self.assertIn('id="graph-panel-toggle-button"', body)
        self.assertIn('id="graph-panel-body"', body)
        self.assertIn('id="graph-zoom-slider" type="range" min="10"', body)
        self.assertIn('id="graph-resize-handle"', body)
        self.assertIn('id="startup-wizard-overlay" class="startup-wizard-overlay" aria-hidden="true"', body)
        self.assertIn("graph-footer-separator", body)
        self.assertNotIn("graph-legend-footer", body)
        self.assertNotIn("drag nodes or groups to reposition them", body)
        self.assertNotIn("<h2>Tools</h2>", body)
        self.assertNotIn("<h2>Processes</h2>", body)
        self.assertNotIn("<h2>Jobs</h2>", body)
        self.assertNotIn("<h2>Submitted Scans</h2>", body)
        self.assertNotIn("<h2>Scheduler Decisions</h2>", body)
        self.assertLess(body.index('id="ribbon-launch-wizard-button"'), body.index("<h2>Project</h2>"))
        self.assertLess(body.index("<h2>Project</h2>"), body.index('id="stat-hosts"'))
        self.assertLess(body.index('id="ribbon-logging-menu-button"'), body.index('id="ribbon-settings-menu-button"'))
        self.assertLess(body.index('id="ribbon-launch-wizard-button"'), body.index("<h2>Graph Workspace</h2>"))
        self.assertLess(body.index('id="graph-workspace-shell"'), body.index('id="graph-refresh-button"'))
        self.assertLess(body.index('id="graph-layout-select"'), body.index('id="graph-focus-depth-select"'))
        self.assertLess(body.index('id="graph-refresh-button"'), body.index('id="graph-resize-handle"'))
        self.assertLess(body.index('id="graph-resize-handle"'), body.index('id="graph-workspace-status"'))
        self.assertLess(body.index("<h2>Graph Workspace</h2>"), body.index('<h2>Hosts</h2>'))
        self.assertLess(body.index('<h2>Hosts</h2>'), body.index('<h2>Services</h2>'))
        self.assertLess(body.index('<h2>Services</h2>'), body.index('<h2>Host Detail</h2>'))

    def test_index_renders_all_interfaces_chip_when_configured(self):
        self.app.config["LEGION_WEB_BIND_HOST"] = "0.0.0.0"
        self.app.config["LEGION_WEB_BIND_LABEL"] = "All interfaces"
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        body = response.get_data(as_text=True)
        self.assertIn("All interfaces", body)

    def test_index_renders_opaque_ui_body_class_when_configured(self):
        self.app.config["LEGION_UI_OPAQUE"] = True
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        body = response.get_data(as_text=True)
        self.assertIn('<body class="opaque-ui">', body)
        self.assertIn("window.LEGION_OPAQUE_UI_ENABLED = true", body)

    def test_index_hides_graph_workspace_when_rollout_flag_is_disabled(self):
        self.runtime.scheduler_config.update_preferences({
            "feature_flags": {
                "graph_workspace": False,
            }
        })
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        body = response.get_data(as_text=True)
        self.assertIn("Graph Workspace", body)
        self.assertIn("Disabled by rollout flag.", body)
        self.assertNotIn("graph-workspace-canvas", body)

    def test_index_renders_hosts_panel_menu(self):
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        body = response.get_data(as_text=True)
        self.assertIn("hosts-reset-filter-button", body)
        self.assertIn("hosts-panel-menu-button", body)
        self.assertIn("hosts-export-json-button", body)
        self.assertIn("hosts-filter-hide-down-button", body)
        self.assertIn("fa-filter-circle-xmark", body)

    def test_snapshot_endpoint(self):
        response = self.client.get("/api/snapshot")
        self.assertEqual(200, response.status_code)
        self.assertEqual("demo", response.json["project"]["name"])

    def test_project_endpoints(self):
        details = self.client.get("/api/project")
        self.assertEqual(200, details.status_code)
        self.assertEqual("demo", details.json["name"])

        listing = self.client.get("/api/projects?limit=10")
        self.assertEqual(200, listing.status_code)
        self.assertEqual(2, len(listing.json["projects"]))
        self.assertTrue(listing.json["projects"][0]["is_current"])

        new_temp = self.client.post("/api/project/new-temp", json={})
        self.assertEqual(200, new_temp.status_code)
        self.assertTrue(new_temp.json["project"]["is_temporary"])

        opened = self.client.post("/api/project/open", json={"path": "engagement.legion"})
        self.assertEqual(200, opened.status_code)
        self.assertEqual("engagement.legion", opened.json["project"]["name"])

        save = self.client.post("/api/project/save-as", json={"path": "saved.legion", "replace": True})
        self.assertEqual(202, save.status_code)
        self.assertEqual("accepted", save.json.get("status"))
        self.assertEqual("project-save-as", save.json["job"]["type"])

    def test_project_open_returns_not_found(self):
        response = self.client.post("/api/project/open", json={"path": "missing.legion"})
        self.assertEqual(404, response.status_code)

    def test_project_download_zip_endpoint(self):
        response = self.client.get("/api/project/download-zip")
        self.assertEqual(200, response.status_code)
        disposition = response.headers.get("Content-Disposition", "")
        self.assertIn("attachment;", disposition)
        self.assertIn(".zip", disposition)

    def test_project_restore_zip_endpoint(self):
        response = self.client.post(
            "/api/project/restore-zip",
            data={"bundle": (io.BytesIO(b"PK\x05\x06" + b"\x00" * 18), "session.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(202, response.status_code)
        self.assertEqual("accepted", response.json.get("status"))
        self.assertEqual("project-restore-zip", response.json["job"]["type"])

    def test_export_hosts_csv_endpoint(self):
        response = self.client.get("/api/export/hosts-csv")
        self.assertEqual(200, response.status_code)
        self.assertIn("attachment; filename=", response.headers.get("Content-Disposition", ""))
        csv_text = response.get_data(as_text=True)
        self.assertIn("id,ip,hostname,status,os,open_ports,total_ports,services", csv_text)
        self.assertIn("10.0.0.5", csv_text)
        self.assertIn("kerberos; smb", csv_text)
        self.assertNotIn("10.0.0.6", csv_text)
        self.assertNotIn("scheduler_mode", csv_text)

    def test_export_hosts_csv_endpoint_show_all_includes_down_hosts(self):
        response = self.client.get("/api/export/hosts-csv?filter=show_all")
        self.assertEqual(200, response.status_code)
        csv_text = response.get_data(as_text=True)
        self.assertIn("10.0.0.6", csv_text)

    def test_export_hosts_csv_endpoint_service_filter(self):
        response = self.client.get("/api/export/hosts-csv?service=http")
        self.assertEqual(200, response.status_code)
        csv_text = response.get_data(as_text=True)
        self.assertIn("10.0.0.7", csv_text)
        self.assertNotIn("10.0.0.5", csv_text)

    def test_export_hosts_json_endpoint(self):
        response = self.client.get("/api/export/hosts-json")
        self.assertEqual(200, response.status_code)
        self.assertIn("attachment; filename=", response.headers.get("Content-Disposition", ""))
        payload = response.get_json()
        self.assertEqual("hide_down", payload["filter"])
        self.assertEqual("", payload["service"])
        self.assertEqual(2, payload["host_count"])
        self.assertEqual(["kerberos", "smb"], payload["hosts"][0]["services"])
        self.assertFalse(any(item["ip"] == "10.0.0.6" for item in payload["hosts"]))

    def test_workspace_hosts_endpoint_service_filter(self):
        response = self.client.get("/api/workspace/hosts?service=http")
        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual("hide_down", payload["filter"])
        self.assertEqual("http", payload["service"])
        self.assertEqual(1, len(payload["hosts"]))
        self.assertEqual("10.0.0.7", payload["hosts"][0]["ip"])

    def test_scheduler_preferences_endpoint(self):
        response = self.client.get("/api/scheduler/preferences")
        self.assertEqual(200, response.status_code)
        self.assertEqual("deterministic", response.json["mode"])

    def test_scheduler_preferences_update_endpoint(self):
        response = self.client.post("/api/scheduler/preferences", json={"mode": "ai", "goal_profile": "external_pentest"})
        self.assertEqual(200, response.status_code)
        self.assertEqual("ai", response.json["mode"])
        self.assertEqual("external_pentest", response.json["goal_profile"])

    def test_scheduler_preferences_update_accepts_engagement_policy(self):
        response = self.client.post(
            "/api/scheduler/preferences",
            json={
                "engagement_policy": {
                    "preset": "external_recon",
                    "scope": "external",
                    "intent": "recon",
                    "noise_budget": "low",
                }
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("external_pentest", response.json["goal_profile"])
        self.assertEqual("external_recon", response.json["engagement_policy"]["preset"])

    def test_scheduler_preferences_update_accepts_feature_flags(self):
        response = self.client.post(
            "/api/scheduler/preferences",
            json={
                "feature_flags": {
                    "graph_workspace": False,
                    "optional_runners": False,
                }
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertFalse(response.json["feature_flags"]["graph_workspace"])
        self.assertFalse(response.json["feature_flags"]["optional_runners"])

    def test_engagement_policy_endpoints(self):
        current = self.client.get("/api/engagement-policy")
        self.assertEqual(200, current.status_code)
        self.assertEqual("internal_recon", current.json["preset"])

        updated = self.client.post(
            "/api/engagement-policy",
            json={
                "preset": "internal_pentest",
                "intent": "pentest",
                "allow_exploitation": True,
            },
        )
        self.assertEqual(200, updated.status_code)
        self.assertEqual("internal_pentest", updated.json["preset"])
        self.assertTrue(updated.json["allow_exploitation"])

    def test_scheduler_provider_test_endpoint(self):
        response = self.client.post(
            "/api/scheduler/provider/test",
            json={
                "provider": "lm_studio",
                "providers": {
                    "lm_studio": {
                        "enabled": True,
                        "base_url": "http://127.0.0.1:1234/v1",
                        "model": "o3-7b",
                    }
                },
            },
        )
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json["ok"])
        self.assertEqual("lm_studio", response.json["provider"])

    def test_scheduler_provider_logs_endpoint(self):
        response = self.client.get("/api/scheduler/provider/logs?limit=20")
        self.assertEqual(200, response.status_code)
        self.assertIn("logs", response.json)
        self.assertIn("text", response.json)
        self.assertEqual("openai", response.json["logs"][0]["provider"])

    def test_scheduler_approve_family_endpoint(self):
        response = self.client.post("/api/scheduler/approve-family", json={"family_id": "fam123", "tool_id": "hydra"})
        self.assertEqual(200, response.status_code)
        self.assertEqual("ok", response.json["status"])
        self.assertEqual(1, len(self.runtime.scheduler_config.state["preapproved_command_families"]))

    def test_scheduler_decisions_endpoint(self):
        response = self.client.get("/api/scheduler/decisions?limit=10")
        self.assertEqual(200, response.status_code)
        self.assertEqual(1, len(response.json["decisions"]))
        self.assertEqual("10.0.0.5", response.json["decisions"][0]["host_ip"])

    def test_scheduler_plan_preview_endpoint(self):
        response = self.client.get("/api/scheduler/plan-preview?host_id=11&mode=compare")
        self.assertEqual(200, response.status_code)
        self.assertEqual("compare", response.json["requested_mode"])
        self.assertEqual(1, response.json["target_count"])
        self.assertEqual(["smb-security-mode"], response.json["targets"][0]["agreement"])
        self.assertEqual("allowed", response.json["targets"][0]["deterministic"]["steps"][0]["policy_decision"])

    def test_scheduler_execution_trace_endpoints(self):
        listing = self.client.get("/api/scheduler/executions?include_output=true")
        self.assertEqual(200, listing.status_code)
        self.assertEqual(1, len(listing.json["executions"]))
        self.assertEqual("exec-1", listing.json["executions"][0]["execution_id"])
        self.assertEqual("sample trace", listing.json["executions"][0]["stdout_excerpt"])

        detail = self.client.get("/api/scheduler/executions/exec-1")
        self.assertEqual(200, detail.status_code)
        self.assertEqual("smb-enum-users.nse", detail.json["tool_id"])
        self.assertEqual("sample trace", detail.json["stdout_excerpt"])

    def test_scan_history_endpoint(self):
        response = self.client.get("/api/scans/history?limit=10")
        self.assertEqual(200, response.status_code)
        self.assertEqual(1, len(response.json["scans"]))
        self.assertEqual("nmap_scan", response.json["scans"][0]["submission_kind"])
        self.assertEqual("10.0.0.0/24", response.json["scans"][0]["target_summary"])

    def test_graph_api_endpoints(self):
        graph = self.client.get("/api/graph?node_type=technology&hide_ai_suggested=true&host_id=11")
        self.assertEqual(200, graph.status_code)
        self.assertEqual(1, len(graph.json["nodes"]))
        self.assertEqual("technology", graph.json["nodes"][0]["type"])
        self.assertEqual(0, len(graph.json["edges"]))
        self.assertFalse(graph.json["meta"]["filters"]["include_ai_suggested"])

        rebuild = self.client.post("/api/graph/rebuild", json={"host_id": 11})
        self.assertEqual(200, rebuild.status_code)
        self.assertEqual("ok", rebuild.json["status"])
        self.assertEqual(2, rebuild.json["mutation_count"])

        export_json = self.client.get("/api/graph/export/json?rebuild=true")
        self.assertEqual(200, export_json.status_code)
        self.assertIn("attachment; filename=", export_json.headers.get("Content-Disposition", ""))
        self.assertIn("graph-node-host", export_json.get_data(as_text=True))

        export_graphml = self.client.get("/api/graph/export/graphml")
        self.assertEqual(200, export_graphml.status_code)
        self.assertIn(".graphml", export_graphml.headers.get("Content-Disposition", ""))
        self.assertIn("<graphml>", export_graphml.get_data(as_text=True))

        layouts = self.client.get("/api/graph/layouts")
        self.assertEqual(200, layouts.status_code)
        self.assertEqual("attack_surface", layouts.json["layouts"][0]["view_id"])

        save_layout = self.client.post(
            "/api/graph/layouts",
            json={"view_id": "attack_surface", "name": "focused", "layout": {"positions": {"graph-node-host": {"x": 20, "y": 40}}}},
        )
        self.assertEqual(200, save_layout.status_code)
        self.assertEqual("ok", save_layout.json["status"])
        self.assertEqual("focused", save_layout.json["layout"]["name"])

        annotations = self.client.get("/api/graph/annotations?target_ref=graph-node-host&target_kind=node")
        self.assertEqual(200, annotations.status_code)
        self.assertEqual(1, len(annotations.json["annotations"]))

        save_annotation = self.client.post(
            "/api/graph/annotations",
            json={"target_kind": "node", "target_ref": "graph-node-tech", "body": "Track this tech", "created_by": "tester"},
        )
        self.assertEqual(200, save_annotation.status_code)
        self.assertEqual("ok", save_annotation.json["status"])
        self.assertEqual("Track this tech", save_annotation.json["annotation"]["body"])

        content = self.client.get("/api/graph/nodes/graph-node-host/content")
        self.assertEqual(200, content.status_code)
        self.assertEqual(2, content.json["entry_count"])
        self.assertEqual("text", content.json["entries"][0]["kind"])

        text_download = self.client.get("/api/graph/content/graph-node-artifact")
        self.assertEqual(200, text_download.status_code)
        self.assertIn("Artifact preview line 1", text_download.get_data(as_text=True))

        image_download = self.client.get("/api/graph/content/graph-node-shot?download=1")
        self.assertEqual(200, image_download.status_code)
        self.assertIn("attachment;", image_download.headers.get("Content-Disposition", ""))

    def test_graph_api_hides_nmap_text_artifacts_and_optionally_hides_xml(self):
        default_graph = self.client.get("/api/graph")
        self.assertEqual(200, default_graph.status_code)
        default_ids = {item["node_id"] for item in default_graph.json["nodes"]}
        self.assertIn("graph-node-artifact-xml", default_ids)
        self.assertNotIn("graph-node-artifact-gnmap", default_ids)

        hide_xml = self.client.get("/api/graph?hide_nmap_xml_artifacts=true")
        self.assertEqual(200, hide_xml.status_code)
        hidden_ids = {item["node_id"] for item in hide_xml.json["nodes"]}
        self.assertNotIn("graph-node-artifact-xml", hidden_ids)
        self.assertTrue(hide_xml.json["meta"]["filters"]["hide_nmap_xml_artifacts"])

    def test_graph_api_mirrors_hosts_filter_for_down_hosts(self):
        self.runtime.graph_snapshot["nodes"].append({
            "node_id": "graph-node-down-host",
            "type": "host",
            "label": "10.0.0.6",
            "confidence": 95.0,
            "source_kind": "observed",
            "source_ref": "host:10.0.0.6",
            "properties": {"host_id": 12, "ip": "10.0.0.6"},
            "evidence_refs": ["host:10.0.0.6"],
        })

        hidden = self.client.get("/api/graph?filter=hide_down")
        self.assertEqual(200, hidden.status_code)
        hidden_ids = {item["node_id"] for item in hidden.json["nodes"]}
        self.assertNotIn("graph-node-down-host", hidden_ids)
        self.assertTrue(hidden.json["meta"]["filters"]["hide_down_hosts"])

        shown = self.client.get("/api/graph?filter=show_all")
        self.assertEqual(200, shown.status_code)
        shown_ids = {item["node_id"] for item in shown.json["nodes"]}
        self.assertIn("graph-node-down-host", shown_ids)
        self.assertFalse(shown.json["meta"]["filters"]["hide_down_hosts"])

    def test_graph_api_validation(self):
        missing_layout = self.client.post("/api/graph/layouts", json={"layout": {}})
        self.assertEqual(400, missing_layout.status_code)

        missing_annotation = self.client.post("/api/graph/annotations", json={"target_kind": "node", "target_ref": ""})
        self.assertEqual(400, missing_annotation.status_code)

    def test_scan_and_import_endpoints(self):
        target_import = self.client.post("/api/targets/import-file", json={"path": "/tmp/targets.txt"})
        self.assertEqual(202, target_import.status_code)
        self.assertEqual("accepted", target_import.json["status"])

        nmap_import = self.client.post("/api/nmap/import-xml", json={"path": "/tmp/scan.xml", "run_actions": True})
        self.assertEqual(202, nmap_import.status_code)
        self.assertEqual("import-nmap-xml", nmap_import.json["job"]["type"])

        scan = self.client.post(
            "/api/nmap/scan",
            json={
                "targets": ["10.0.0.0/24"],
                "discovery": True,
                "staged": False,
                "run_actions": False,
                "nmap_args": "-p- --reason",
                "scan_mode": "hard",
                "scan_options": {"full_ports": True, "discovery": False},
            },
        )
        self.assertEqual(202, scan.status_code)
        self.assertEqual("nmap-scan", scan.json["job"]["type"])
        self.assertEqual("-p- --reason", scan.json["job"]["payload"]["nmap_args"])
        self.assertEqual("hard", scan.json["job"]["payload"]["scan_mode"])

    def test_jobs_endpoints(self):
        listing = self.client.get("/api/jobs?limit=10")
        self.assertEqual(200, listing.status_code)
        self.assertEqual(1, len(listing.json["jobs"]))

        details = self.client.get("/api/jobs/1")
        self.assertEqual(200, details.status_code)
        self.assertEqual(1, details.json["id"])

        stop = self.client.post("/api/jobs/1/stop", json={})
        self.assertEqual(200, stop.status_code)
        self.assertEqual("ok", stop.json["status"])
        self.assertTrue(stop.json["stopped"])

        missing = self.client.get("/api/jobs/99")
        self.assertEqual(404, missing.status_code)
        missing_stop = self.client.post("/api/jobs/99/stop", json={})
        self.assertEqual(404, missing_stop.status_code)

    def test_workspace_endpoints(self):
        hosts = self.client.get("/api/workspace/hosts")
        self.assertEqual(200, hosts.status_code)
        self.assertEqual("hide_down", hosts.json["filter"])
        self.assertEqual(2, len(hosts.json["hosts"]))
        self.assertFalse(any(item["ip"] == "10.0.0.6" for item in hosts.json["hosts"]))

        limited_hosts = self.client.get("/api/workspace/hosts?limit=2")
        self.assertEqual(200, limited_hosts.status_code)
        self.assertEqual(2, len(limited_hosts.json["hosts"]))

        all_hosts = self.client.get("/api/workspace/hosts?filter=show_all")
        self.assertEqual(200, all_hosts.status_code)
        self.assertEqual("show_all", all_hosts.json["filter"])
        self.assertEqual(3, len(all_hosts.json["hosts"]))
        self.assertTrue(any(item["ip"] == "10.0.0.6" for item in all_hosts.json["hosts"]))

        services = self.client.get("/api/workspace/services")
        self.assertEqual(200, services.status_code)
        self.assertIn("smb", [item["service"] for item in services.json["services"]])

        filtered_services = self.client.get("/api/workspace/services?host_id=11")
        self.assertEqual(200, filtered_services.status_code)
        self.assertEqual(11, filtered_services.json["host_id"])
        self.assertEqual(["kerberos", "smb"], [item["service"] for item in filtered_services.json["services"]])

        tools = self.client.get("/api/workspace/tools")
        self.assertEqual(200, tools.status_code)
        self.assertIn("total", tools.json)
        self.assertIn("has_more", tools.json)
        self.assertEqual("smb-enum-users.nse", tools.json["tools"][0]["tool_id"])

        detail = self.client.get("/api/workspace/hosts/11")
        self.assertEqual(200, detail.status_code)
        self.assertEqual("10.0.0.5", detail.json["host"]["ip"])
        self.assertEqual("openai", detail.json["ai_analysis"]["provider"])
        self.assertEqual("missing_smb_signing_checks", detail.json["target_state"]["coverage_gaps"][0]["gap_id"])
        self.assertNotIn("Starting Nmap", detail.json["ports"][0]["scripts"][0]["display_output"])
        self.assertIn("message_signing: disabled", detail.json["ports"][0]["scripts"][0]["display_output"])

        target_state = self.client.get("/api/workspace/hosts/11/target-state")
        self.assertEqual(200, target_state.status_code)
        self.assertEqual("internal_recon", target_state.json["target_state"]["engagement_preset"])

        findings = self.client.get("/api/workspace/findings?host_id=11&limit=10")
        self.assertEqual(200, findings.status_code)
        self.assertEqual(1, findings.json["count"])
        self.assertEqual("SMB signing not required", findings.json["findings"][0]["title"])

        ai_report_json = self.client.get("/api/workspace/hosts/11/ai-report?format=json")
        self.assertEqual(200, ai_report_json.status_code)
        self.assertIn("application/json", str(ai_report_json.content_type))
        self.assertIn("attachment; filename=", ai_report_json.headers.get("Content-Disposition", ""))
        self.assertIn("ai_analysis", ai_report_json.get_data(as_text=True))
        self.assertIn("target_state", ai_report_json.get_data(as_text=True))

        ai_report_md = self.client.get("/api/workspace/hosts/11/ai-report?format=md")
        self.assertEqual(200, ai_report_md.status_code)
        self.assertIn("text/markdown", str(ai_report_md.content_type))
        self.assertIn("# Legion Host AI Report", ai_report_md.get_data(as_text=True))

        host_report_json = self.client.get("/api/workspace/hosts/11/report?format=json")
        self.assertEqual(200, host_report_json.status_code)
        self.assertIn("application/json", str(host_report_json.content_type))
        self.assertIn("validated_findings", host_report_json.get_data(as_text=True))

        host_report_md = self.client.get("/api/workspace/hosts/11/report?format=md")
        self.assertEqual(200, host_report_md.status_code)
        self.assertIn("text/markdown", str(host_report_md.content_type))
        self.assertIn("# Legion Host Report", host_report_md.get_data(as_text=True))

        project_ai_report_json = self.client.get("/api/workspace/project-ai-report?format=json")
        self.assertEqual(200, project_ai_report_json.status_code)
        self.assertIn("application/json", str(project_ai_report_json.content_type))
        self.assertIn("host_count", project_ai_report_json.get_data(as_text=True))

        project_ai_report_md = self.client.get("/api/workspace/project-ai-report?format=md")
        self.assertEqual(200, project_ai_report_md.status_code)
        self.assertIn("text/markdown", str(project_ai_report_md.content_type))
        self.assertIn("# Legion Project AI Report", project_ai_report_md.get_data(as_text=True))

        project_report_json = self.client.get("/api/workspace/project-report?format=json")
        self.assertEqual(200, project_report_json.status_code)
        self.assertIn("application/json", str(project_report_json.content_type))
        self.assertIn("summary_of_discovered_assets", project_report_json.get_data(as_text=True))

        project_report_md = self.client.get("/api/workspace/project-report?format=md")
        self.assertEqual(200, project_report_md.status_code)
        self.assertIn("text/markdown", str(project_report_md.content_type))
        self.assertIn("# Legion Project Report", project_report_md.get_data(as_text=True))

        project_push_missing_endpoint = self.client.post("/api/workspace/project-ai-report/push", json={})
        self.assertEqual(400, project_push_missing_endpoint.status_code)

        project_push_ok = self.client.post(
            "/api/workspace/project-ai-report/push",
            json={
                "project_report_delivery": {
                    "provider_name": "siem",
                    "endpoint": "https://example.local/report",
                    "method": "POST",
                    "format": "json",
                }
            },
        )
        self.assertEqual(200, project_push_ok.status_code)
        self.assertEqual("ok", project_push_ok.json.get("status"))

        project_report_push = self.client.post(
            "/api/workspace/project-report/push",
            json={
                "project_report_delivery": {
                    "provider_name": "siem",
                    "endpoint": "https://example.local/report",
                    "method": "POST",
                    "format": "json",
                }
            },
        )
        self.assertEqual(200, project_report_push.status_code)
        self.assertEqual("ok", project_report_push.json.get("status"))

        ai_report_zip = self.client.get("/api/workspace/ai-reports/download-zip")
        self.assertEqual(200, ai_report_zip.status_code)
        self.assertIn("application/zip", str(ai_report_zip.content_type))
        self.assertIn("attachment; filename=", ai_report_zip.headers.get("Content-Disposition", ""))

        host_rescan = self.client.post("/api/workspace/hosts/11/rescan", json={})
        self.assertEqual(202, host_rescan.status_code)
        self.assertEqual("accepted", host_rescan.json["status"])

        subnet_rescan = self.client.post("/api/workspace/subnets/rescan", json={"subnet": "10.0.0.0/24"})
        self.assertEqual(202, subnet_rescan.status_code)
        self.assertEqual("accepted", subnet_rescan.json["status"])

        host_screenshots = self.client.post("/api/workspace/hosts/11/refresh-screenshots", json={})
        self.assertEqual(202, host_screenshots.status_code)
        self.assertEqual("accepted", host_screenshots.json["status"])

        graph_screenshot_refresh = self.client.post(
            "/api/workspace/screenshots/refresh",
            json={"host_id": 11, "port": "443", "protocol": "tcp"},
        )
        self.assertEqual(202, graph_screenshot_refresh.status_code)
        self.assertEqual("accepted", graph_screenshot_refresh.json["status"])

        graph_screenshot_delete = self.client.post(
            "/api/workspace/screenshots/delete",
            json={
                "host_id": 11,
                "artifact_ref": "/api/screenshots/10.0.0.5-445-screenshot.png",
                "filename": "10.0.0.5-445-screenshot.png",
                "port": "445",
                "protocol": "tcp",
            },
        )
        self.assertEqual(200, graph_screenshot_delete.status_code)
        self.assertTrue(graph_screenshot_delete.json["deleted"])

        graph_port_delete = self.client.post(
            "/api/workspace/ports/delete",
            json={"host_id": 11, "port": "445", "protocol": "tcp"},
        )
        self.assertEqual(200, graph_port_delete.status_code)
        self.assertTrue(graph_port_delete.json["deleted"])
        self.assertEqual("port", graph_port_delete.json["kind"])

        graph_service_delete = self.client.post(
            "/api/workspace/services/delete",
            json={"host_id": 11, "port": "445", "protocol": "tcp", "service": "smb"},
        )
        self.assertEqual(200, graph_service_delete.status_code)
        self.assertTrue(graph_service_delete.json["deleted"])
        self.assertEqual("service", graph_service_delete.json["kind"])

        host_dig = self.client.post("/api/workspace/hosts/11/dig-deeper", json={})
        self.assertEqual(202, host_dig.status_code)
        self.assertEqual("accepted", host_dig.json["status"])

        note = self.client.post("/api/workspace/hosts/11/note", json={"text": "updated"})
        self.assertEqual(200, note.status_code)
        self.assertTrue(note.json["saved"])

        script_add = self.client.post(
            "/api/workspace/hosts/11/scripts",
            json={"script_id": "test-script", "port": "445", "protocol": "tcp", "output": "ok"},
        )
        self.assertEqual(200, script_add.status_code)
        self.assertEqual("test-script", script_add.json["script"]["script_id"])

        script_delete = self.client.delete("/api/workspace/scripts/100")
        self.assertEqual(200, script_delete.status_code)
        self.assertTrue(script_delete.json["deleted"])
        script_output = self.client.get("/api/workspace/scripts/100/output")
        self.assertEqual(200, script_output.status_code)
        self.assertEqual("script process output", script_output.json["output"])

        cve_add = self.client.post("/api/workspace/hosts/11/cves", json={"name": "CVE-2025-1111"})
        self.assertEqual(200, cve_add.status_code)
        self.assertEqual("CVE-2025-1111", cve_add.json["cve"]["name"])

        cve_delete = self.client.delete("/api/workspace/cves/50")
        self.assertEqual(200, cve_delete.status_code)
        self.assertTrue(cve_delete.json["deleted"])

        tool_run = self.client.post(
            "/api/workspace/tools/run",
            json={"host_ip": "10.0.0.5", "port": "445", "protocol": "tcp", "tool_id": "smb-enum-users.nse"},
        )
        self.assertEqual(202, tool_run.status_code)
        self.assertEqual("accepted", tool_run.json["status"])

        process_output = self.client.get("/api/processes/1/output")
        self.assertEqual(200, process_output.status_code)
        self.assertEqual("sample output", process_output.json["output"])
        process_output_tail = self.client.get("/api/processes/1/output?offset=7")
        self.assertEqual(200, process_output_tail.status_code)
        self.assertEqual("output", process_output_tail.json["output_chunk"])

        process_kill = self.client.post("/api/processes/1/kill", json={})
        self.assertEqual(200, process_kill.status_code)
        self.assertTrue(process_kill.json["killed"])

        process_retry = self.client.post("/api/processes/1/retry", json={})
        self.assertEqual(202, process_retry.status_code)
        self.assertEqual("accepted", process_retry.json["status"])

        process_close = self.client.post("/api/processes/1/close", json={})
        self.assertEqual(200, process_close.status_code)
        self.assertTrue(process_close.json["closed"])

        process_clear = self.client.post("/api/processes/clear", json={"reset_all": True})
        self.assertEqual(200, process_clear.status_code)
        self.assertTrue(process_clear.json["cleared"])

        screenshot = self.client.get("/api/screenshots/10.0.0.5-445-screenshot.png")
        self.assertEqual(200, screenshot.status_code)

        remove_host = self.client.delete("/api/workspace/hosts/11")
        self.assertEqual(200, remove_host.status_code)
        self.assertEqual("ok", remove_host.json["status"])
        self.assertTrue(remove_host.json["deleted"])

    def test_scheduler_approval_endpoints(self):
        listing = self.client.get("/api/scheduler/approvals?status=pending")
        self.assertEqual(200, listing.status_code)
        self.assertEqual(1, len(listing.json["approvals"]))

        approve = self.client.post("/api/scheduler/approvals/77/approve", json={"approve_family": True, "family_action": "allowed"})
        self.assertIn(approve.status_code, {200, 202})
        self.assertEqual("ok", approve.json["status"])

        reject = self.client.post("/api/scheduler/approvals/77/reject", json={"reason": "no", "family_action": "suppressed"})
        self.assertEqual(200, reject.status_code)
        self.assertEqual("ok", reject.json["status"])

        scheduler_run = self.client.post("/api/scheduler/run", json={})
        self.assertEqual(202, scheduler_run.status_code)
        self.assertEqual("accepted", scheduler_run.json["status"])


if __name__ == "__main__":
    unittest.main()
