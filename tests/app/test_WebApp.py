import unittest
import tempfile
import io
import json
import os
import zipfile


class DummySchedulerConfig:
    def __init__(self):
        self.state = {
            "mode": "deterministic",
            "goal_profile": "internal_asset_discovery",
            "provider": "none",
            "providers": {},
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
        self.state.update(updates)
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
        self.workspace_hosts = [
            {"id": 11, "ip": "10.0.0.5", "hostname": "dc01.local", "status": "up", "os": "windows", "open_ports": 2},
        ]
        self.workspace_services = [
            {"service": "smb", "host_count": 1, "port_count": 1, "protocols": ["tcp"]},
        ]
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
                    "scripts": [{"id": 100, "script_id": "smb-enum-users.nse", "output": "sample"}],
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
        }
        self.scheduler_approvals = [
            {
                "id": 77,
                "host_ip": "10.0.0.5",
                "port": "445",
                "protocol": "tcp",
                "tool_id": "smb-default",
                "danger_categories": "credential_bruteforce",
                "status": "pending",
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
            "hosts": [],
            "services": list(self.workspace_services),
            "tools": list(self.workspace_tools),
            "processes": [],
            "scheduler": self.get_scheduler_preferences(),
            "scheduler_decisions": self.get_scheduler_decisions(),
            "scheduler_approvals": list(self.scheduler_approvals),
            "jobs": list(self.jobs),
        }

    def get_project_details(self):
        return dict(self.project)

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
            "provider": self.scheduler_config.state["provider"],
            "providers": self.scheduler_config.state["providers"],
            "project_report_delivery": self.scheduler_config.state["project_report_delivery"],
            "dangerous_categories": self.scheduler_config.state["dangerous_categories"],
            "preapproved_families_count": len(self.scheduler_config.state["preapproved_command_families"]),
            "cloud_notice": "Cloud AI mode may send host/service metadata to third-party providers.",
        }

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

    def get_workspace_hosts(self, limit=400):
        return self.workspace_hosts[:limit]

    def get_workspace_services(self, limit=300):
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
        }

    def render_host_ai_report_markdown(self, report):
        host = report.get("host", {}) if isinstance(report, dict) else {}
        return (
            "# Legion Host AI Report\n\n"
            f"- Host ID: {host.get('id', '')}\n"
            f"- Host IP: {host.get('ip', '')}\n"
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

    def approve_scheduler_approval(self, approval_id, approve_family=False, run_now=True):
        _ = approve_family
        _ = run_now
        if int(approval_id) != 77:
            raise KeyError(approval_id)
        return {"approval": {"id": 77, "status": "approved"}, "job": {"id": 99}}

    def reject_scheduler_approval(self, approval_id, reason=""):
        _ = reason
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

    def test_index_renders(self):
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertIn("Web Console", response.get_data(as_text=True))

    def test_snapshot_endpoint(self):
        response = self.client.get("/api/snapshot")
        self.assertEqual(200, response.status_code)
        self.assertEqual("demo", response.json["project"]["name"])

    def test_project_endpoints(self):
        details = self.client.get("/api/project")
        self.assertEqual(200, details.status_code)
        self.assertEqual("demo", details.json["name"])

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

    def test_scheduler_preferences_endpoint(self):
        response = self.client.get("/api/scheduler/preferences")
        self.assertEqual(200, response.status_code)
        self.assertEqual("deterministic", response.json["mode"])

    def test_scheduler_preferences_update_endpoint(self):
        response = self.client.post("/api/scheduler/preferences", json={"mode": "ai", "goal_profile": "external_pentest"})
        self.assertEqual(200, response.status_code)
        self.assertEqual("ai", response.json["mode"])
        self.assertEqual("external_pentest", response.json["goal_profile"])

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
        self.assertEqual(1, len(hosts.json["hosts"]))

        services = self.client.get("/api/workspace/services")
        self.assertEqual(200, services.status_code)
        self.assertEqual("smb", services.json["services"][0]["service"])

        tools = self.client.get("/api/workspace/tools")
        self.assertEqual(200, tools.status_code)
        self.assertIn("total", tools.json)
        self.assertIn("has_more", tools.json)
        self.assertEqual("smb-enum-users.nse", tools.json["tools"][0]["tool_id"])

        detail = self.client.get("/api/workspace/hosts/11")
        self.assertEqual(200, detail.status_code)
        self.assertEqual("10.0.0.5", detail.json["host"]["ip"])
        self.assertEqual("openai", detail.json["ai_analysis"]["provider"])

        ai_report_json = self.client.get("/api/workspace/hosts/11/ai-report?format=json")
        self.assertEqual(200, ai_report_json.status_code)
        self.assertIn("application/json", str(ai_report_json.content_type))
        self.assertIn("attachment; filename=", ai_report_json.headers.get("Content-Disposition", ""))
        self.assertIn("ai_analysis", ai_report_json.get_data(as_text=True))

        ai_report_md = self.client.get("/api/workspace/hosts/11/ai-report?format=md")
        self.assertEqual(200, ai_report_md.status_code)
        self.assertIn("text/markdown", str(ai_report_md.content_type))
        self.assertIn("# Legion Host AI Report", ai_report_md.get_data(as_text=True))

        project_ai_report_json = self.client.get("/api/workspace/project-ai-report?format=json")
        self.assertEqual(200, project_ai_report_json.status_code)
        self.assertIn("application/json", str(project_ai_report_json.content_type))
        self.assertIn("host_count", project_ai_report_json.get_data(as_text=True))

        project_ai_report_md = self.client.get("/api/workspace/project-ai-report?format=md")
        self.assertEqual(200, project_ai_report_md.status_code)
        self.assertIn("text/markdown", str(project_ai_report_md.content_type))
        self.assertIn("# Legion Project AI Report", project_ai_report_md.get_data(as_text=True))

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

        ai_report_zip = self.client.get("/api/workspace/ai-reports/download-zip")
        self.assertEqual(200, ai_report_zip.status_code)
        self.assertIn("application/zip", str(ai_report_zip.content_type))
        self.assertIn("attachment; filename=", ai_report_zip.headers.get("Content-Disposition", ""))

        host_rescan = self.client.post("/api/workspace/hosts/11/rescan", json={})
        self.assertEqual(202, host_rescan.status_code)
        self.assertEqual("accepted", host_rescan.json["status"])

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

        approve = self.client.post("/api/scheduler/approvals/77/approve", json={"approve_family": True})
        self.assertIn(approve.status_code, {200, 202})
        self.assertEqual("ok", approve.json["status"])

        reject = self.client.post("/api/scheduler/approvals/77/reject", json={"reason": "no"})
        self.assertEqual(200, reject.status_code)
        self.assertEqual("ok", reject.json["status"])

        scheduler_run = self.client.post("/api/scheduler/run", json={})
        self.assertEqual(202, scheduler_run.status_code)
        self.assertEqual("accepted", scheduler_run.json["status"])


if __name__ == "__main__":
    unittest.main()
