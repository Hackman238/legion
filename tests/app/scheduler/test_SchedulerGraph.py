import unittest

from sqlalchemy import text

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.execution import get_execution_record, store_execution_record
from app.scheduler.graph import (
    ensure_scheduler_graph_tables,
    export_evidence_graph_graphml,
    export_evidence_graph_json,
    get_evidence_graph_snapshot,
    list_graph_annotations,
    list_graph_layout_states,
    query_evidence_graph,
    upsert_graph_annotation,
    upsert_graph_layout_state,
)
from app.scheduler.models import ExecutionRecord, PlanStep
from app.scheduler.state import get_target_state, upsert_target_state
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.cve import cve
from db.entities.host import hostObj
from db.entities.note import note
from db.entities.port import portObj
from db.entities.service import serviceObj


class SchedulerEvidenceGraphTest(unittest.TestCase):
    def _create_project(self):
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        return project_manager, project

    def test_target_state_sync_builds_graph_and_exports(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="portal.local", osMatch="Linux")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            service = serviceObj(name="https", host=host_id, product="nginx", version="1.25")
            session.add(service)
            session.commit()

            port = portObj("443", "tcp", "open", host_id, service.id)
            session.add(port)
            session.add(cve(
                name="CVE-2025-1234",
                url="https://example.test/CVE-2025-1234",
                product="nginx",
                hostId=str(host_id),
                severity="high",
                source="nmap",
                version="1.25",
                exploitId=7,
                exploit="ExploitDB #7",
                exploitUrl="https://exploit-db.test/exploits/7",
            ))
            session.add(note(hostId=host_id, text="Operator note: verify admin panel manually"))
            session.commit()
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "last_mode": "deterministic",
                "goal_profile": "external_pentest",
                "engagement_preset": "external_pentest",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "hostname": "portal.local",
                "hostname_confidence": 96,
                "os_match": "Linux",
                "os_confidence": 82,
                "technologies": [{"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "server header"}],
                "findings": [{
                    "title": "Admin panel exposed",
                    "severity": "medium",
                    "cvss": 5.0,
                    "cve": "",
                    "evidence": "/admin",
                    "evidence_items": ["/admin", "/admin/login"],
                }],
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https", "service_product": "nginx", "service_version": "1.25"}],
                "urls": [{"url": "https://portal.local", "port": "443", "protocol": "tcp", "service": "https"}],
                "attempted_actions": [{
                    "tool_id": "nuclei-web",
                    "label": "Nuclei Web",
                    "status": "executed",
                    "attempted_at": "2026-03-17T02:00:00Z",
                    "port": "443",
                    "protocol": "tcp",
                    "service": "https",
                    "artifact_refs": ["/tmp/nuclei-10.0.0.5.txt", "/tmp/10.0.0.5-443-screenshot.png"],
                }],
                "credentials": [{"username": "svc-web", "realm": "local", "type": "password", "evidence": "manual note"}],
                "sessions": [{"session_type": "shell", "username": "svc-web", "host": "10.0.0.9", "port": "443", "protocol": "tcp", "evidence": "validated shell"}],
                "screenshots": [{"artifact_ref": "/tmp/10.0.0.5-443-screenshot.png", "filename": "10.0.0.5-443-screenshot.png", "port": "443", "protocol": "tcp"}],
                "artifacts": [{"ref": "/tmp/nuclei-10.0.0.5.txt", "kind": "artifact", "tool_id": "nuclei-web", "port": "443", "protocol": "tcp"}],
            })

            snapshot = get_evidence_graph_snapshot(project.database)
            node_types = {item["type"] for item in snapshot["nodes"]}
            edge_types = {item["type"] for item in snapshot["edges"]}

            self.assertTrue({
                "scope", "subnet", "host", "fqdn", "port", "service", "url", "technology", "cpe",
                "finding", "cve", "exploit_reference", "credential", "identity", "session",
                "artifact", "screenshot", "action", "evidence_record",
            }.issubset(node_types))
            self.assertTrue({
                "contains", "resolves_to", "exposes", "fingerprinted_as", "mapped_to_cpe",
                "affected_by", "supports_exploit", "authenticated_as", "pivoted_to",
                "captured", "produced", "derived_from",
            }.issubset(edge_types))
            self.assertTrue(any(item["type"] == "technology" and item["source_kind"] == "observed" for item in snapshot["nodes"]))
            self.assertTrue(any(item["type"] == "finding" and item["evidence_refs"] for item in snapshot["nodes"]))
            self.assertTrue(any(str(item["source_ref"]).startswith("note:") for item in snapshot["annotations"]))
            finding_node = next(
                item for item in snapshot["nodes"]
                if item["type"] == "finding" and item["label"] == "Admin panel exposed"
            )
            self.assertIn("/admin/login", list(finding_node.get("evidence_refs", []) or []))
            evidence_node = next(
                item for item in snapshot["nodes"]
                if item["type"] == "evidence_record" and item.get("properties", {}).get("evidence") == "/admin"
            )
            self.assertIn("/admin/login", list(evidence_node.get("evidence_refs", []) or []))

            exported_json = export_evidence_graph_json(project.database)
            exported_graphml = export_evidence_graph_graphml(project.database)

            self.assertEqual(len(snapshot["nodes"]), len(exported_json["nodes"]))
            self.assertIn("<graphml", exported_graphml)
            self.assertIn("portal.local", exported_graphml)
            self.assertIn("CVE-2025-1234", exported_graphml)
        finally:
            project_manager.closeProject(project)

    def test_execution_record_sync_populates_graph_mutations(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            step = PlanStep.from_legacy_fields(
                tool_id="smb-enum-users.nse",
                label="SMB Enum Users",
                command_template="nmap --script=smb-enum-users [IP] -p [PORT]",
                protocol="tcp",
                score=100.0,
                rationale="Enumerate SMB users on an exposed service.",
                mode="deterministic",
                goal_profile="internal_asset_discovery",
                family_id="smb-enum-users",
                target_ref={"host_ip": "10.0.0.5", "port": "445", "service": "smb", "protocol": "tcp"},
            )
            step.linked_evidence_refs = ["host:10.0.0.5", "service:smb"]
            record = ExecutionRecord.from_plan_step(
                step,
                started_at="2026-03-17T02:10:00Z",
                finished_at="2026-03-17T02:10:05Z",
                exit_status="completed",
                stdout_ref="process_output:42",
                artifact_refs=["/tmp/smb-enum-users.txt"],
                approval_id="",
            )

            stored = store_execution_record(
                project.database,
                record,
                step=step,
                host_ip="10.0.0.5",
                port="445",
                protocol="tcp",
                service="smb",
            )
            fetched = get_execution_record(project.database, record.execution_id)
            snapshot = get_evidence_graph_snapshot(project.database)

            self.assertTrue(stored.get("graph_mutations"))
            self.assertIsNotNone(fetched)
            self.assertTrue(fetched["graph_mutations"])
            self.assertTrue(any(item["type"] == "action" and item["properties"].get("execution_id") == record.execution_id for item in snapshot["nodes"]))
            self.assertTrue(any(item["type"] == "artifact" and item["properties"].get("ref") == "/tmp/smb-enum-users.txt" for item in snapshot["nodes"]))
            self.assertTrue(any(item["type"] == "evidence_record" and item["properties"].get("ref") == "process_output:42" for item in snapshot["nodes"]))
            self.assertTrue(any(item["type"] == "produced" for item in snapshot["edges"]))
        finally:
            project_manager.closeProject(project)

    def test_query_evidence_graph_filters_nodes_and_hides_ai_suggestions(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="dc01.local", osMatch="Windows")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.add(serviceObj(name="smb", host=host_id, product="samba", version="4.x"))
            session.commit()
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "last_mode": "ai",
                "provider": "openai",
                "technologies": [
                    {"name": "samba", "version": "4.x", "cpe": "cpe:/a:samba:samba:4", "evidence": "service banner", "source_kind": "observed"},
                ],
                "findings": [
                    {"title": "SMB signing not required", "severity": "high", "cvss": 7.5, "evidence": "smb-security-mode", "source_kind": "ai_suggested"},
                ],
                "service_inventory": [{"port": "445", "protocol": "tcp", "state": "open", "service": "smb", "service_product": "samba", "service_version": "4.x"}],
            })

            filtered = query_evidence_graph(
                project.database,
                node_types=["technology"],
                source_kinds=["observed"],
                include_ai_suggested=False,
                host_id=host_id,
                search="samba",
                limit_nodes=50,
                limit_edges=50,
            )

            self.assertEqual(1, len(filtered["nodes"]))
            self.assertEqual("technology", filtered["nodes"][0]["type"])
            self.assertEqual("observed", filtered["nodes"][0]["source_kind"])
            self.assertEqual(0, len([item for item in filtered["nodes"] if item["source_kind"] == "ai_suggested"]))
            self.assertEqual(host_id, filtered["meta"]["filters"]["host_id"])
        finally:
            project_manager.closeProject(project)

    def test_query_evidence_graph_hides_down_hosts_when_requested(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            up_host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="up.local", osMatch="Linux", status="up")
            down_host = hostObj(ip="10.0.0.6", ipv4="10.0.0.6", hostname="down.local", osMatch="Linux", status="down")
            session.add(up_host)
            session.add(down_host)
            session.commit()
            up_host_id = int(up_host.id)
            down_host_id = int(down_host.id)
            session.close()

            upsert_target_state(project.database, up_host_id, {
                "host_ip": "10.0.0.5",
                "hostname": "up.local",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
                "urls": [{"url": "https://up.local", "port": "443", "protocol": "tcp", "service": "https"}],
            })
            upsert_target_state(project.database, down_host_id, {
                "host_ip": "10.0.0.6",
                "hostname": "down.local",
                "service_inventory": [{"port": "80", "protocol": "tcp", "state": "open", "service": "http"}],
                "urls": [{"url": "http://down.local", "port": "80", "protocol": "tcp", "service": "http"}],
            })

            hidden = query_evidence_graph(project.database, hide_down_hosts=True, limit_nodes=200, limit_edges=200)
            hidden_host_ids = {
                int(item.get("properties", {}).get("host_id", 0) or 0)
                for item in hidden["nodes"]
                if isinstance(item.get("properties", {}), dict)
            }
            self.assertIn(up_host_id, hidden_host_ids)
            self.assertNotIn(down_host_id, hidden_host_ids)
            self.assertTrue(hidden["meta"]["filters"]["hide_down_hosts"])

            shown = query_evidence_graph(project.database, hide_down_hosts=False, limit_nodes=200, limit_edges=200)
            shown_host_ids = {
                int(item.get("properties", {}).get("host_id", 0) or 0)
                for item in shown["nodes"]
                if isinstance(item.get("properties", {}), dict)
            }
            self.assertIn(down_host_id, shown_host_ids)
            self.assertFalse(shown["meta"]["filters"]["hide_down_hosts"])

            scoped = query_evidence_graph(
                project.database,
                host_ids=[up_host_id],
                hide_down_hosts=False,
                limit_nodes=200,
                limit_edges=200,
            )
            scoped_host_ids = {
                int(item.get("properties", {}).get("host_id", 0) or 0)
                for item in scoped["nodes"]
                if isinstance(item.get("properties", {}), dict)
            }
            self.assertIn(up_host_id, scoped_host_ids)
            self.assertNotIn(down_host_id, scoped_host_ids)
            self.assertEqual([up_host_id], scoped["meta"]["filters"]["host_ids"])

            empty = query_evidence_graph(
                project.database,
                host_ids=[],
                hide_down_hosts=False,
                limit_nodes=200,
                limit_edges=200,
            )
            self.assertEqual([], empty["nodes"])
            self.assertEqual([], empty["edges"])
            self.assertEqual([], empty["meta"]["filters"]["host_ids"])
        finally:
            project_manager.closeProject(project)

    def test_target_state_sync_removes_stale_url_nodes_after_normalization(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="portal.local", osMatch="Linux")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            session.execute(
                text(
                    "INSERT INTO graph_node (node_id, node_key, type, label, confidence, source_kind, source_ref, first_seen, last_seen, properties_json) "
                    "VALUES (:node_id, :node_key, 'url', :label, 90.0, 'observed', :source_ref, :first_seen, :last_seen, :properties_json)"
                ),
                {
                    "node_id": "url-stale-1",
                    "node_key": f"url:{host_id}:https://portal.local:443/",
                    "label": "https://portal.local:443/",
                    "source_ref": "url:https://portal.local:443/",
                    "first_seen": "2026-03-17T00:00:00Z",
                    "last_seen": "2026-03-17T00:00:00Z",
                    "properties_json": "{\"host_id\": %d, \"url\": \"https://portal.local:443/\"}" % host_id,
                },
            )
            session.commit()
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "hostname": "portal.local",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
                "urls": [
                    {"url": "https://portal.local:443/", "port": "443", "protocol": "tcp", "service": "https"},
                    {"url": "https://portal.local/", "port": "443", "protocol": "tcp", "service": "https"},
                ],
            })

            snapshot = get_evidence_graph_snapshot(project.database)
            url_labels = [item["label"] for item in snapshot["nodes"] if item["type"] == "url"]

            self.assertIn("https://portal.local", url_labels)
            self.assertNotIn("https://portal.local:443/", url_labels)
            self.assertEqual(1, len([item for item in url_labels if item == "https://portal.local"]))
        finally:
            project_manager.closeProject(project)

    def test_query_evidence_graph_hides_nmap_text_artifacts_and_can_hide_xml(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="portal.local", osMatch="Linux")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "hostname": "portal.local",
                "artifacts": [
                    {"ref": "/tmp/web-nmap-01.xml", "tool_id": "nmap", "port": "443", "protocol": "tcp"},
                    {"ref": "/tmp/web-nmap-01.gnmap", "tool_id": "nmap", "port": "443", "protocol": "tcp"},
                    {"ref": "/tmp/nuclei-findings.txt", "tool_id": "nuclei-web", "port": "443", "protocol": "tcp"},
                ],
            })

            default_graph = query_evidence_graph(project.database, host_id=host_id, limit_nodes=100, limit_edges=100)
            default_labels = {str(item["label"]) for item in default_graph["nodes"] if item["type"] == "artifact"}
            self.assertIn("web-nmap-01.xml", default_labels)
            self.assertIn("nuclei-findings.txt", default_labels)
            self.assertNotIn("web-nmap-01.gnmap", default_labels)

            hidden_xml_graph = query_evidence_graph(
                project.database,
                host_id=host_id,
                hide_nmap_xml_artifacts=True,
                limit_nodes=100,
                limit_edges=100,
            )
            hidden_labels = {str(item["label"]) for item in hidden_xml_graph["nodes"] if item["type"] == "artifact"}
            self.assertNotIn("web-nmap-01.xml", hidden_labels)
            self.assertIn("nuclei-findings.txt", hidden_labels)
            self.assertTrue(hidden_xml_graph["meta"]["filters"]["hide_nmap_xml_artifacts"])
        finally:
            project_manager.closeProject(project)

    def test_graph_layout_and_annotation_round_trip(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            layout = upsert_graph_layout_state(
                project.database,
                view_id="attack_surface",
                name="default",
                layout_state={"positions": {"node-1": {"x": 10, "y": 20}}},
            )
            annotation = upsert_graph_annotation(
                project.database,
                target_kind="node",
                target_ref="graph-node-test",
                body="Flag this host for follow-up",
                created_by="tester",
                source_ref="unit:test",
            )

            self.assertEqual("attack_surface", list_graph_layout_states(project.database)[0]["view_id"])
            self.assertEqual("Flag this host for follow-up", list_graph_annotations(project.database)[0]["body"])
            self.assertTrue(layout["layout_id"])
            self.assertTrue(annotation["annotation_id"])
        finally:
            project_manager.closeProject(project)

    def test_single_host_rebuild_only_resyncs_that_hosts_executions(self):
        from unittest.mock import patch
        from app.scheduler import graph as graph_module

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host_a = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="alpha.local", status="up")
            host_b = hostObj(ip="10.0.1.7", ipv4="10.0.1.7", hostname="bravo.local", status="up")
            session.add(host_a)
            session.add(host_b)
            session.commit()
            host_a_id = int(host_a.id)
            session.close()

            for host_ip in ("10.0.0.5", "10.0.1.7"):
                step = PlanStep.from_legacy_fields(
                    tool_id="whatweb",
                    label="WhatWeb",
                    command_template="whatweb [IP]",
                    protocol="tcp",
                    score=100.0,
                    rationale="fingerprint",
                    mode="deterministic",
                    goal_profile="internal_asset_discovery",
                    family_id="whatweb",
                    target_ref={"host_ip": host_ip, "port": "80", "service": "http", "protocol": "tcp"},
                )
                record = ExecutionRecord.from_plan_step(
                    step,
                    started_at="2026-03-17T02:10:00Z",
                    finished_at="2026-03-17T02:10:05Z",
                    exit_status="completed",
                    stdout_ref=f"process_output:{host_ip}",
                )
                store_execution_record(project.database, record, step=step, host_ip=host_ip, port="80", protocol="tcp", service="http")

            real_sync = graph_module.sync_execution_record_to_evidence_graph
            synced_hosts = []

            def _recording_sync(database, **kwargs):
                synced_hosts.append(kwargs.get("host_ip", ""))
                return real_sync(database, **kwargs)

            with patch.object(graph_module, "sync_execution_record_to_evidence_graph", side_effect=_recording_sync):
                graph_module.rebuild_evidence_graph(project.database, host_id=host_a_id)
                self.assertEqual(["10.0.0.5"], synced_hosts)

                synced_hosts.clear()
                graph_module.rebuild_evidence_graph(project.database, host_id=999999)
                self.assertEqual([], synced_hosts)

                synced_hosts.clear()
                graph_module.rebuild_evidence_graph(project.database)
                self.assertEqual(["10.0.0.5", "10.0.1.7"], sorted(synced_hosts))
        finally:
            project_manager.closeProject(project)

    def test_host_sync_prunes_screenshot_and_artifact_nodes_removed_from_target_state(self):
        from app.scheduler import graph as graph_module
        from app.scheduler.state import modify_target_state

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="portal.local", status="up")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
                "screenshots": [
                    {"artifact_ref": "/tmp/shots/portal-443.png", "filename": "portal-443.png", "port": "443", "protocol": "tcp"},
                    {"artifact_ref": "/tmp/shots/portal-80.png", "filename": "portal-80.png", "port": "80", "protocol": "tcp"},
                ],
                "artifacts": [
                    {"ref": "/tmp/shots/portal-443.png", "kind": "screenshot", "port": "443", "protocol": "tcp"},
                    {"ref": "/tmp/scan.txt", "kind": "artifact", "port": "443", "protocol": "tcp"},
                ],
            })
            before = get_evidence_graph_snapshot(project.database)
            self.assertEqual(
                {"portal-443.png", "portal-80.png"},
                {item["label"] for item in before["nodes"] if item["type"] == "screenshot"},
            )

            # What app/web/runtime_artifacts.py does when a screenshot file is deleted.
            def drop_port_443_screenshot(state):
                state["screenshots"] = [item for item in state.get("screenshots", []) if item.get("port") != "443"]
                state["artifacts"] = [item for item in state.get("artifacts", []) if item.get("ref") != "/tmp/shots/portal-443.png"]
                return state

            modify_target_state(project.database, host_id, drop_port_443_screenshot)
            graph_module.rebuild_evidence_graph(project.database, host_id=host_id)

            after = get_evidence_graph_snapshot(project.database)
            self.assertEqual(["portal-80.png"], [item["label"] for item in after["nodes"] if item["type"] == "screenshot"])
            self.assertEqual(["scan.txt"], [item["label"] for item in after["nodes"] if item["type"] == "artifact"])
            node_ids = {item["node_id"] for item in after["nodes"]}
            for edge in after["edges"]:
                self.assertIn(edge["from_node_id"], node_ids)
                self.assertIn(edge["to_node_id"], node_ids)
            self.assertFalse([edge for edge in after["edges"] if edge["type"] == "captured" and "portal-443" in str(edge.get("source_ref", ""))])

            session = project.database.session()
            try:
                stale_refs = session.execute(text(
                    "SELECT COUNT(*) FROM graph_evidence_ref WHERE owner_id NOT IN (SELECT node_id FROM graph_node) "
                    "AND owner_id NOT IN (SELECT edge_id FROM graph_edge)"
                )).scalar()
            finally:
                session.close()
            self.assertEqual(0, int(stale_refs or 0))
        finally:
            project_manager.closeProject(project)

    def test_unchanged_resync_of_one_host_reports_no_mutations_on_shared_nodes(self):
        from app.scheduler.graph import sync_target_state_to_evidence_graph

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host_a = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="alpha.local", status="up")
            host_b = hostObj(ip="10.0.0.6", ipv4="10.0.0.6", hostname="bravo.local", status="up")
            session.add(host_a)
            session.add(host_b)
            session.commit()
            host_a_id, host_b_id = int(host_a.id), int(host_b.id)
            for host_id in (host_a_id, host_b_id):
                # The same CVE/exploit on both hosts: cve and exploit nodes plus the supports_exploit edge are shared.
                session.add(cve(
                    name="CVE-2025-1234",
                    url="https://example.test/CVE-2025-1234",
                    product="nginx",
                    hostId=str(host_id),
                    severity="high",
                    source="nmap",
                    version="1.25",
                    exploitId=7,
                    exploit="ExploitDB #7",
                    exploitUrl="https://exploit-db.test/exploits/7",
                ))
            session.commit()
            session.close()

            state_a = upsert_target_state(project.database, host_a_id, {
                "host_ip": "10.0.0.5",
                "hostname": "alpha.local",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
            })
            upsert_target_state(project.database, host_b_id, {
                "host_ip": "10.0.0.6",
                "hostname": "bravo.local",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
            })

            mutations = sync_target_state_to_evidence_graph(project.database, host_id=host_a_id, target_state=state_a)
            self.assertEqual([], mutations)

            snapshot = get_evidence_graph_snapshot(project.database)
            subnet_nodes = [item for item in snapshot["nodes"] if item["type"] == "subnet"]
            self.assertEqual(1, len(subnet_nodes))
            # An equal-priority refresh that changes nothing else keeps the ref already stored.
            self.assertEqual(f"host:{host_a_id}", subnet_nodes[0]["source_ref"])
        finally:
            project_manager.closeProject(project)

    def test_partial_target_state_passed_to_sync_does_not_prune_discovered_nodes(self):
        from app.scheduler.graph import sync_target_state_to_evidence_graph

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="portal.local", status="up")
            session.add(host)
            session.commit()
            host_id = int(host.id)
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "hostname": "portal.local",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
                "urls": [
                    {"url": "https://portal.local/", "port": "443", "protocol": "tcp", "service": "https"},
                    {"url": "https://portal.local/admin", "port": "443", "protocol": "tcp", "service": "https"},
                ],
                "screenshots": [
                    {"artifact_ref": "/tmp/shots/portal-443.png", "filename": "portal-443.png", "port": "443", "protocol": "tcp"},
                ],
            })

            def _labels(node_type):
                snapshot = get_evidence_graph_snapshot(project.database)
                return sorted(item["label"] for item in snapshot["nodes"] if item["type"] == node_type)

            self.assertEqual(["https://portal.local", "https://portal.local/admin"], _labels("url"))
            self.assertEqual(["portal-443.png"], _labels("screenshot"))

            # A partial dict (no urls/screenshots keys) must not be read as "the host has none".
            sync_target_state_to_evidence_graph(project.database, host_id=host_id, target_state={
                "host_ip": "10.0.0.5",
                "hostname": "portal.local",
                "last_mode": "deterministic",
            })
            self.assertEqual(["https://portal.local", "https://portal.local/admin"], _labels("url"))
            self.assertEqual(["portal-443.png"], _labels("screenshot"))

            # The full stored state with the keys present (even empty) is authoritative.
            full_state = dict(get_target_state(project.database, host_id))
            full_state["screenshots"] = []
            sync_target_state_to_evidence_graph(project.database, host_id=host_id, target_state=full_state)
            self.assertEqual([], _labels("screenshot"))
        finally:
            project_manager.closeProject(project)


class LegacyGraphTableUniqueKeyTest(unittest.TestCase):
    def test_legacy_tables_get_unique_node_and_edge_keys(self):
        import os
        import tempfile
        from sqlalchemy import create_engine
        from sqlalchemy.exc import IntegrityError
        from sqlalchemy.orm import sessionmaker
        from app.scheduler.graph import ensure_scheduler_graph_tables

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{os.path.join(tmpdir, 'legacy.db')}")
            make_session = sessionmaker(bind=engine)
            session = make_session()
            # Pre-node_key/edge_key schema: those columns are later added by ALTER TABLE (no UNIQUE).
            session.execute(text("CREATE TABLE graph_node (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT)"))
            session.execute(text("CREATE TABLE graph_edge (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT)"))
            session.execute(text("ALTER TABLE graph_node ADD COLUMN node_key TEXT"))
            # Duplicates written by the old race: they must be collapsed so the unique index can be added.
            session.execute(text("INSERT INTO graph_node (label, node_key) VALUES ('old', 'dup'), ('new', 'dup')"))
            session.commit()
            session.close()

            database = type("LegacyDb", (), {"engine": engine, "session": staticmethod(make_session)})()
            ensure_scheduler_graph_tables(database)

            session = make_session()
            try:
                labels = [row[0] for row in session.execute(text("SELECT label FROM graph_node WHERE node_key = 'dup'"))]
                self.assertEqual(["new"], labels)
                for table, column in (("graph_node", "node_key"), ("graph_edge", "edge_key")):
                    session.execute(text(f"INSERT INTO {table} ({column}) VALUES ('shared')"))
                    with self.assertRaises(IntegrityError):
                        session.execute(text(f"INSERT INTO {table} ({column}) VALUES ('shared')"))
                    session.rollback()
            finally:
                session.close()
            engine.dispose()


class GraphSchemaCacheRollbackTest(unittest.TestCase):
    def test_rolled_back_unique_index_pass_is_not_cached(self):
        import os
        import tempfile
        from unittest.mock import patch
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.scheduler import graph as graph_module
        from app.scheduler.schema_cache import clear_schema_cache

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{os.path.join(tmpdir, 'legacy.db')}")
            make_session = sessionmaker(bind=engine)
            session = make_session()
            session.execute(text("CREATE TABLE graph_node (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT)"))
            session.execute(text("CREATE TABLE graph_edge (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT)"))
            session.commit()
            # Bring every column up to date but, like an older release, without the unique key indexes.
            with patch.object(graph_module, "_ensure_unique_index"):
                graph_module._ensure_tables_uncached(session)
            # Duplicates make the index pass start a transaction (DELETE) that a rollback can undo.
            session.execute(text("INSERT INTO graph_node (label, node_key) VALUES ('old', 'dup'), ('new', 'dup')"))
            session.commit()
            session.close()
            clear_schema_cache()
            self.addCleanup(clear_schema_cache)

            # A read-only caller runs the schema pass, then rolls it back (no commit).
            rolled_back = make_session()
            graph_module._ensure_tables(rolled_back)
            rolled_back.rollback()
            rolled_back.close()
            check = make_session()
            self.assertFalse(graph_module._has_unique_index_on(check, "graph_node", "node_key"))
            check.close()

            # The next committing pass must still create the index (it was not cached as done).
            database = type("LegacyDb", (), {"engine": engine, "session": staticmethod(make_session)})()
            graph_module.ensure_scheduler_graph_tables(database)
            check = make_session()
            self.assertTrue(graph_module._has_unique_index_on(check, "graph_node", "node_key"))
            self.assertTrue(graph_module._has_unique_index_on(check, "graph_edge", "edge_key"))
            check.close()
            engine.dispose()


class GraphEvidenceRefIndexTest(unittest.TestCase):
    def test_existing_project_gets_evidence_ref_lookup_index(self):
        import os
        import tempfile
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.scheduler import graph as graph_module
        from app.scheduler.schema_cache import clear_schema_cache, is_schema_ensured

        columns = ["owner_kind", "owner_id", "evidence_ref"]
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{os.path.join(tmpdir, 'legacy.db')}")
            make_session = sessionmaker(bind=engine)
            session = make_session()
            # An older project file: every graph table/column/unique index present, but no evidence ref index.
            graph_module._ensure_tables_uncached(session)
            session.execute(text("DROP INDEX IF EXISTS ix_graph_evidence_ref_owner_ref"))
            session.commit()
            self.assertFalse(graph_module._has_index_on(session, "graph_evidence_ref", columns))
            session.close()
            clear_schema_cache()
            self.addCleanup(clear_schema_cache)

            # A rolled back pass must not be cached as complete.
            rolled_back = make_session()
            graph_module._ensure_tables(rolled_back)
            rolled_back.rollback()
            rolled_back.close()
            self.assertFalse(is_schema_ensured(engine, "graph"))

            database = type("LegacyDb", (), {"engine": engine, "session": staticmethod(make_session)})()
            graph_module.ensure_scheduler_graph_tables(database)
            check = make_session()
            try:
                self.assertTrue(graph_module._has_index_on(check, "graph_evidence_ref", columns))
                plan = " ".join(
                    str(row[-1]) for row in check.execute(text(
                        "EXPLAIN QUERY PLAN SELECT id FROM graph_evidence_ref "
                        "WHERE owner_kind = 'node' AND owner_id = 'n1' AND evidence_ref = 'ref' LIMIT 1"
                    )).fetchall()
                )
                self.assertIn("ix_graph_evidence_ref_owner_ref", plan)
            finally:
                check.close()
            # Once the index exists the schema pass is cached.
            graph_module.ensure_scheduler_graph_tables(database)
            self.assertTrue(is_schema_ensured(engine, "graph"))
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
