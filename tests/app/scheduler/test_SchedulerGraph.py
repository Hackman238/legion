import unittest

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
                "findings": [{"title": "Admin panel exposed", "severity": "medium", "cvss": 5.0, "cve": "", "evidence": "/admin"}],
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
