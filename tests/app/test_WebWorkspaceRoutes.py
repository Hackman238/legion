import unittest
from pathlib import Path
import tempfile


class _WorkspaceRouteRuntime:
    def __init__(self, screenshot_path):
        self.calls = []
        self.screenshot_path = str(screenshot_path)

    def get_workspace_hosts(self, limit=None, include_down=False, service="", category=""):
        self.calls.append(("get_workspace_hosts", limit, bool(include_down), str(service), str(category)))
        rows = [
            {"id": 11, "ip": "10.0.0.5", "hostname": "dc01", "status": "up", "os": "Windows", "open_ports": 2, "total_ports": 2, "services": ["kerberos", "smb"]},
            {"id": 12, "ip": "10.0.0.7", "hostname": "web01", "status": "up", "os": "Linux", "open_ports": 1, "total_ports": 1, "services": ["http"]},
            {"id": 13, "ip": "10.0.0.6", "hostname": "offline", "status": "down", "os": "Unknown", "open_ports": 0, "total_ports": 0, "services": ["ssh"]},
        ]
        if not include_down:
            rows = [row for row in rows if row["status"] != "down"]
        if service:
            service_filters = {
                token.strip()
                for token in str(service).split(",")
                if token.strip()
            }
            rows = [
                row for row in rows
                if any(item in service_filters for item in list(row.get("services", [])))
            ]
        if category:
            rows = [row for row in rows if str(category) == "server"]
        if limit:
            rows = rows[: int(limit)]
        return rows

    def get_workspace_overview(self):
        self.calls.append(("get_workspace_overview",))
        return {
            "hosts": [{"id": 11, "ip": "10.0.0.5"}],
            "scheduler_rationale_feed": [{"host_ip": "10.0.0.5", "headline": "smbmap"}],
        }

    def get_workspace_services(self, limit=300, host_id=0, category=""):
        self.calls.append(("get_workspace_services", int(limit), int(host_id), str(category)))
        rows = [
            {"service": "kerberos", "host_ip": "10.0.0.5"},
            {"service": "smb", "host_ip": "10.0.0.5"},
            {"service": "http", "host_ip": "10.0.0.7"},
        ]
        if host_id == 11:
            rows = [row for row in rows if row["host_ip"] == "10.0.0.5"]
        return rows[: int(limit)]

    def get_workspace_tools_page(self, service="", limit=300, offset=0):
        self.calls.append(("get_workspace_tools_page", str(service), int(limit), int(offset)))
        rows = [
            {"tool_id": "smbmap", "service": "smb"},
            {"tool_id": "whatweb-http", "service": "http"},
        ]
        if service:
            rows = [row for row in rows if row["service"] == str(service)]
        paged = rows[int(offset): int(offset) + int(limit)]
        return {"tools": paged, "total": len(rows), "offset": int(offset), "limit": int(limit), "has_more": False}

    def get_workspace_tool_targets(self, host_id=0, service="", limit=300):
        self.calls.append(("get_workspace_tool_targets", int(host_id), str(service), int(limit)))
        rows = [
            {"host_id": 11, "host_ip": "10.0.0.5", "port": "445", "service": "smb"},
            {"host_id": 12, "host_ip": "10.0.0.7", "port": "80", "service": "http"},
        ]
        if host_id:
            rows = [row for row in rows if row["host_id"] == int(host_id)]
        if service:
            rows = [row for row in rows if row["service"] == str(service)]
        return rows[: int(limit)]

    def get_host_workspace(self, host_id):
        self.calls.append(("get_host_workspace", int(host_id)))
        if int(host_id) != 11:
            raise KeyError(f"Unknown host id: {host_id}")
        return {"host": {"id": 11, "ip": "10.0.0.5"}, "ai_analysis": {"provider": "openai"}}

    def get_target_state_view(self, host_id=0, limit=500):
        self.calls.append(("get_target_state_view", int(host_id), int(limit)))
        if int(host_id) != 11:
            raise KeyError(f"Unknown host id: {host_id}")
        return {"target_state": {"engagement_preset": "internal_recon"}}

    def get_findings(self, host_id=0, limit_findings=1000):
        self.calls.append(("get_findings", int(host_id), int(limit_findings)))
        return {"count": 1, "findings": [{"title": "SMB signing not required"}]}

    def get_screenshot_file(self, filename):
        self.calls.append(("get_screenshot_file", str(filename)))
        resolved = Path(self.screenshot_path)
        if str(filename) != resolved.name:
            raise FileNotFoundError(filename)
        return str(resolved)

    def get_credential_capture_state(self, include_captures=False):
        self.calls.append(("get_credential_capture_state", bool(include_captures)))
        return {
            "capture_count": 1,
            "responder": {"config": {"interface_name": "eth0"}},
            "ntlmrelayx": {"config": {"socks": False}},
        }

    def save_credential_capture_config(self, updates=None):
        payload = dict(updates or {})
        self.calls.append(("save_credential_capture_config", payload))
        return {
            "capture_count": 1,
            "responder": {"config": dict(payload.get("responder", {}))},
            "ntlmrelayx": {"config": dict(payload.get("ntlmrelayx", {}))},
        }

    def start_credential_capture_session_job(self, tool_id):
        self.calls.append(("start_credential_capture_session_job", str(tool_id)))
        return {"id": 301, "type": "credential-capture-session"}

    def stop_credential_capture_session(self, tool_id):
        self.calls.append(("stop_credential_capture_session", str(tool_id)))
        return {"stopped": True, "tool": str(tool_id)}

    def get_credential_capture_log_payload(self, tool_id):
        self.calls.append(("get_credential_capture_log_payload", str(tool_id)))
        return {"tool": str(tool_id), "text": "responder log line 1\n"}

    def get_workspace_credential_captures(self, limit=None):
        self.calls.append(("get_workspace_credential_captures", int(limit or 0)))
        return {
            "captures": [{"username": "alice"}],
            "capture_count": 1,
            "unique_hash_count": 1,
            "deduped_hashes": ["alice::CORP:1122:3344"],
            "panel_enabled": True,
        }

    def start_host_screenshot_refresh_job(self, host_id):
        self.calls.append(("start_host_screenshot_refresh_job", int(host_id)))
        return {"id": 401}

    def start_graph_screenshot_refresh_job(self, host_id, port, protocol="tcp"):
        self.calls.append(("start_graph_screenshot_refresh_job", int(host_id), str(port), str(protocol)))
        return {"id": 402}

    def delete_graph_screenshot(self, **kwargs):
        self.calls.append(("delete_graph_screenshot", dict(kwargs)))
        return {"deleted": True}

    def delete_workspace_port(self, **kwargs):
        self.calls.append(("delete_workspace_port", dict(kwargs)))
        return {"deleted": True, "kind": "port"}

    def delete_workspace_service(self, **kwargs):
        self.calls.append(("delete_workspace_service", dict(kwargs)))
        return {"deleted": True, "kind": "service"}

    def update_host_note(self, host_id, text_value):
        self.calls.append(("update_host_note", int(host_id), str(text_value)))
        return {"host_id": int(host_id), "note": str(text_value)}

    def update_host_categories(self, host_id, manual_categories=None, override_auto=False):
        self.calls.append(("update_host_categories", int(host_id), list(manual_categories or []), bool(override_auto)))
        return {
            "host_id": int(host_id),
            "manual_categories": list(manual_categories or []),
            "device_category_override": bool(override_auto),
        }

    def create_script_entry(self, host_id, port, protocol, script_id, output):
        self.calls.append(("create_script_entry", int(host_id), str(port), str(protocol), str(script_id), str(output)))
        return {"id": 501, "script_id": str(script_id)}

    def delete_script_entry(self, script_id):
        self.calls.append(("delete_script_entry", int(script_id)))
        return {"deleted": True, "script_id": int(script_id)}

    def get_script_output(self, script_id, offset=0, max_chars=12000):
        self.calls.append(("get_script_output", int(script_id), int(offset), int(max_chars)))
        return {"script_id": int(script_id), "output": "script output"}

    def create_cve_entry(self, **kwargs):
        self.calls.append(("create_cve_entry", dict(kwargs)))
        return {"id": 601, "name": str(kwargs.get("name", ""))}

    def delete_cve_entry(self, cve_id):
        self.calls.append(("delete_cve_entry", int(cve_id)))
        return {"deleted": True, "cve_id": int(cve_id)}

    def start_host_dig_deeper_job(self, host_id):
        self.calls.append(("start_host_dig_deeper_job", int(host_id)))
        return {"id": 701, "type": "scheduler-dig-deeper"}

    def delete_host_workspace(self, host_id):
        self.calls.append(("delete_host_workspace", int(host_id)))
        return {"deleted": True, "host_id": int(host_id)}

    def start_tool_run_job(self, host_ip, port, protocol, tool_id, command_override="", timeout=300):
        self.calls.append((
            "start_tool_run_job",
            str(host_ip),
            str(port),
            str(protocol),
            str(tool_id),
            str(command_override),
            int(timeout),
        ))
        return {"id": 702, "type": "tool-run"}

    def kill_process(self, process_id):
        self.calls.append(("kill_process", int(process_id)))
        return {"killed": True, "process_id": int(process_id)}

    def start_process_retry_job(self, process_id, timeout=300):
        self.calls.append(("start_process_retry_job", int(process_id), int(timeout)))
        return {"id": 703, "type": "process-retry"}

    def close_process(self, process_id):
        self.calls.append(("close_process", int(process_id)))
        return {"closed": True, "process_id": int(process_id)}

    def clear_processes(self, reset_all=False):
        self.calls.append(("clear_processes", bool(reset_all)))
        return {"cleared": True, "reset_all": bool(reset_all)}

    def get_process_output(self, process_id, offset=0, max_chars=12000):
        self.calls.append(("get_process_output", int(process_id), int(offset), int(max_chars)))
        text_value = "sample output"
        start = max(0, min(int(offset), len(text_value)))
        chunk = text_value[start: start + int(max_chars)]
        return {"process_id": int(process_id), "output": text_value, "output_chunk": chunk}


class WebWorkspaceRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.tempdir = tempfile.TemporaryDirectory()
        self.screenshot_path = Path(self.tempdir.name) / "demo.png"
        self.screenshot_path.write_bytes(b"fake-image-bytes")
        self.runtime = _WorkspaceRouteRuntime(self.screenshot_path)
        self.client = create_app(self.runtime).test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_workspace_routes_delegate_to_workspace_service(self):
        hosts = self.client.get("/api/workspace/hosts")
        self.assertEqual(200, hosts.status_code)
        self.assertEqual("hide_down", hosts.json["filter"])
        self.assertEqual(2, len(hosts.json["hosts"]))
        self.assertEqual("no-store, max-age=0, must-revalidate", hosts.headers.get("Cache-Control"))

        all_hosts = self.client.get("/api/workspace/hosts?filter=show_all")
        self.assertEqual(200, all_hosts.status_code)
        self.assertEqual("show_all", all_hosts.json["filter"])
        self.assertEqual(3, len(all_hosts.json["hosts"]))

        multi_service_hosts = self.client.get("/api/workspace/hosts?service=smb&service=http")
        self.assertEqual(200, multi_service_hosts.status_code)
        self.assertEqual(["smb", "http"], multi_service_hosts.json["services"])
        self.assertEqual({"10.0.0.5", "10.0.0.7"}, {item["ip"] for item in multi_service_hosts.json["hosts"]})

        hosts_csv = self.client.get("/api/export/hosts-csv?service=http")
        self.assertEqual(200, hosts_csv.status_code)
        self.assertIn("attachment; filename=", hosts_csv.headers.get("Content-Disposition", ""))
        self.assertIn("10.0.0.7", hosts_csv.get_data(as_text=True))

        hosts_json = self.client.get("/api/export/hosts-json?filter=show_all")
        self.assertEqual(200, hosts_json.status_code)
        self.assertIn("attachment; filename=", hosts_json.headers.get("Content-Disposition", ""))
        self.assertEqual(3, hosts_json.get_json()["host_count"])

        overview = self.client.get("/api/workspace/overview")
        self.assertEqual(200, overview.status_code)
        self.assertEqual("10.0.0.5", overview.json["scheduler_rationale_feed"][0]["host_ip"])

        services = self.client.get("/api/workspace/services?host_id=11")
        self.assertEqual(200, services.status_code)
        self.assertEqual(11, services.json["host_id"])
        self.assertEqual(["kerberos", "smb"], [item["service"] for item in services.json["services"]])

        tools = self.client.get("/api/workspace/tools?service=http")
        self.assertEqual(200, tools.status_code)
        self.assertEqual(["whatweb-http"], [item["tool_id"] for item in tools.json["tools"]])

        tool_targets = self.client.get("/api/workspace/tool-targets?service=http")
        self.assertEqual(200, tool_targets.status_code)
        self.assertEqual("10.0.0.7", tool_targets.json["targets"][0]["host_ip"])

        detail = self.client.get("/api/workspace/hosts/11")
        self.assertEqual(200, detail.status_code)
        self.assertEqual("10.0.0.5", detail.json["host"]["ip"])

        target_state = self.client.get("/api/workspace/hosts/11/target-state")
        self.assertEqual(200, target_state.status_code)
        self.assertEqual("internal_recon", target_state.json["target_state"]["engagement_preset"])

        findings = self.client.get("/api/workspace/findings?host_id=11&limit=10")
        self.assertEqual(200, findings.status_code)
        self.assertEqual("SMB signing not required", findings.json["findings"][0]["title"])

        screenshot = self.client.get(f"/api/screenshots/{self.screenshot_path.name}")
        self.assertEqual(200, screenshot.status_code)
        self.assertEqual(b"fake-image-bytes", screenshot.data)
        screenshot.close()

        state = self.client.get("/api/workspace/credential-capture")
        self.assertEqual(200, state.status_code)
        self.assertEqual(1, state.json["capture_count"])
        self.assertEqual("no-store, max-age=0, must-revalidate", state.headers.get("Cache-Control"))

        saved = self.client.post(
            "/api/workspace/credential-capture/config",
            json={"responder": {"mode": "passive"}},
        )
        self.assertEqual(200, saved.status_code)
        self.assertEqual("passive", saved.json["responder"]["config"]["mode"])

        started = self.client.post("/api/workspace/credential-capture/start", json={"tool": "responder"})
        self.assertEqual(202, started.status_code)
        self.assertEqual("credential-capture-session", started.json["job"]["type"])

        stopped = self.client.post("/api/workspace/credential-capture/stop", json={"tool": "responder"})
        self.assertEqual(200, stopped.status_code)
        self.assertTrue(stopped.json["stopped"])

        listing = self.client.get("/api/workspace/credentials?limit=2")
        self.assertEqual(200, listing.status_code)
        self.assertEqual(1, listing.json["unique_hash_count"])

        hashes = self.client.get("/api/workspace/credentials/download?format=txt")
        self.assertEqual(200, hashes.status_code)
        self.assertIn("attachment; filename=credential-hashes.txt", hashes.headers.get("Content-Disposition", ""))
        self.assertIn("alice::CORP:", hashes.get_data(as_text=True))

        payload = self.client.get("/api/workspace/credentials/download?format=json")
        self.assertEqual(200, payload.status_code)
        self.assertIn("attachment; filename=credentials.json", payload.headers.get("Content-Disposition", ""))
        self.assertEqual(1, payload.get_json()["capture_count"])

        log_response = self.client.get("/api/workspace/credential-capture/log?tool=responder")
        self.assertEqual(200, log_response.status_code)
        self.assertIn("attachment; filename=responder-log.txt", log_response.headers.get("Content-Disposition", ""))
        self.assertIn("responder log line 1", log_response.get_data(as_text=True))

        host_screenshots = self.client.post("/api/workspace/hosts/11/refresh-screenshots", json={})
        self.assertEqual(202, host_screenshots.status_code)
        self.assertEqual(401, host_screenshots.json["job"]["id"])

        graph_screenshot_refresh = self.client.post(
            "/api/workspace/screenshots/refresh",
            json={"host_id": 11, "port": "443", "protocol": "tcp"},
        )
        self.assertEqual(202, graph_screenshot_refresh.status_code)
        self.assertEqual(402, graph_screenshot_refresh.json["job"]["id"])

        graph_screenshot_delete = self.client.post(
            "/api/workspace/screenshots/delete",
            json={"host_id": 11, "artifact_ref": "/api/screenshots/demo.png", "filename": "demo.png", "port": "443"},
        )
        self.assertEqual(200, graph_screenshot_delete.status_code)
        self.assertTrue(graph_screenshot_delete.json["deleted"])

        port_delete = self.client.post(
            "/api/workspace/ports/delete",
            json={"host_id": 11, "port": "445", "protocol": "tcp"},
        )
        self.assertEqual(200, port_delete.status_code)
        self.assertEqual("port", port_delete.json["kind"])

        service_delete = self.client.post(
            "/api/workspace/services/delete",
            json={"host_id": 11, "port": "445", "protocol": "tcp", "service": "smb"},
        )
        self.assertEqual(200, service_delete.status_code)
        self.assertEqual("service", service_delete.json["kind"])

        note = self.client.post("/api/workspace/hosts/11/note", json={"text": "updated"})
        self.assertEqual(200, note.status_code)
        self.assertEqual("updated", note.json["note"])

        categories = self.client.post(
            "/api/workspace/hosts/11/categories",
            json={"manual_categories": ["server"], "override_auto": True},
        )
        self.assertEqual(200, categories.status_code)
        self.assertTrue(categories.json["device_category_override"])

        script_create = self.client.post(
            "/api/workspace/hosts/11/scripts",
            json={"script_id": "smb-security-mode", "port": "445", "protocol": "tcp", "output": "ok"},
        )
        self.assertEqual(200, script_create.status_code)
        self.assertEqual("smb-security-mode", script_create.json["script"]["script_id"])

        script_delete = self.client.delete("/api/workspace/scripts/501")
        self.assertEqual(200, script_delete.status_code)
        self.assertTrue(script_delete.json["deleted"])

        script_output = self.client.get("/api/workspace/scripts/501/output?offset=2&max_chars=32")
        self.assertEqual(200, script_output.status_code)
        self.assertEqual("script output", script_output.json["output"])

        cve_create = self.client.post(
            "/api/workspace/hosts/11/cves",
            json={"name": "CVE-2026-9999", "severity": "high"},
        )
        self.assertEqual(200, cve_create.status_code)
        self.assertEqual("CVE-2026-9999", cve_create.json["cve"]["name"])

        cve_delete = self.client.delete("/api/workspace/cves/601")
        self.assertEqual(200, cve_delete.status_code)
        self.assertTrue(cve_delete.json["deleted"])

        dig = self.client.post("/api/workspace/hosts/11/dig-deeper", json={})
        self.assertEqual(202, dig.status_code)
        self.assertEqual("scheduler-dig-deeper", dig.json["job"]["type"])

        tool_run = self.client.post(
            "/api/workspace/tools/run",
            json={"host_ip": "10.0.0.5", "port": "445", "protocol": "tcp", "tool_id": "smbmap"},
        )
        self.assertEqual(202, tool_run.status_code)
        self.assertEqual("tool-run", tool_run.json["job"]["type"])

        process_output = self.client.get("/api/processes/1/output?offset=7")
        self.assertEqual(200, process_output.status_code)
        self.assertEqual("output", process_output.json["output_chunk"])

        process_kill = self.client.post("/api/processes/1/kill", json={})
        self.assertEqual(200, process_kill.status_code)
        self.assertTrue(process_kill.json["killed"])

        process_retry = self.client.post("/api/processes/1/retry", json={"timeout": 123})
        self.assertEqual(202, process_retry.status_code)
        self.assertEqual("process-retry", process_retry.json["job"]["type"])

        process_close = self.client.post("/api/processes/1/close", json={})
        self.assertEqual(200, process_close.status_code)
        self.assertTrue(process_close.json["closed"])

        process_clear = self.client.post("/api/processes/clear", json={"reset_all": True})
        self.assertEqual(200, process_clear.status_code)
        self.assertTrue(process_clear.json["cleared"])

        remove_host = self.client.delete("/api/workspace/hosts/11")
        self.assertEqual(200, remove_host.status_code)
        self.assertTrue(remove_host.json["deleted"])


if __name__ == "__main__":
    unittest.main()
