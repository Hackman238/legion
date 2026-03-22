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
from app.scheduler.state import upsert_target_state
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


if __name__ == "__main__":
    unittest.main()
