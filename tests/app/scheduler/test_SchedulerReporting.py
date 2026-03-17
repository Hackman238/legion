import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.approvals import queue_pending_approval
from app.scheduler.audit import log_scheduler_decision
from app.scheduler.execution import store_execution_record
from app.scheduler.graph import ensure_scheduler_graph_tables, upsert_graph_annotation
from app.scheduler.models import ExecutionRecord, PlanStep
from app.scheduler.reporting import (
    build_host_report,
    build_project_report,
    render_host_report_markdown,
    render_project_report_markdown,
)
from app.scheduler.state import upsert_target_state
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.cve import cve
from db.entities.host import hostObj
from db.entities.note import note
from db.entities.port import portObj
from db.entities.service import serviceObj


class SchedulerReportingTest(unittest.TestCase):
    def _create_project(self):
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        return project_manager, project

    def test_host_and_project_reports_include_required_sections_and_provenance(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="portal.local", osMatch="Linux", status="up")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            service = serviceObj(name="https", host=host_id, product="nginx", version="1.25")
            session.add(service)
            session.commit()
            session.add(portObj("443", "tcp", "open", host_id, service.id))
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
            session.add(note(hostId=host_id, text="Operator note: validate admin path manually"))
            session.commit()
            session.close()

            upsert_target_state(project.database, host_id, {
                "host_ip": "10.0.0.5",
                "last_mode": "deterministic",
                "goal_profile": "external_pentest",
                "engagement_preset": "external_pentest",
                "hostname": "portal.local",
                "hostname_confidence": 96,
                "os_match": "Linux",
                "os_confidence": 84,
                "next_phase": "validation",
                "technologies": [
                    {"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "server header", "source_kind": "observed"},
                ],
                "findings": [
                    {"title": "Admin panel exposed", "severity": "medium", "cvss": 5.0, "evidence": "/admin", "source_kind": "observed"},
                    {"title": "Potential default credentials", "severity": "high", "cvss": 8.0, "evidence": "login banner", "source_kind": "ai_suggested"},
                ],
                "manual_tests": [
                    {"why": "validate authentication weakness", "command": "curl -k https://10.0.0.5/admin", "scope_note": "safe", "source_kind": "ai_suggested"},
                ],
                "service_inventory": [
                    {"port": "443", "protocol": "tcp", "state": "open", "service": "https", "service_product": "nginx", "service_version": "1.25"},
                ],
                "urls": [
                    {"url": "https://portal.local/admin", "port": "443", "protocol": "tcp", "service": "https"},
                ],
                "coverage_gaps": [
                    {"gap_id": "missing_auth_validation", "description": "authentication validation not completed", "recommended_tool_ids": ["nuclei-web"], "source_kind": "inferred"},
                ],
                "attempted_actions": [
                    {
                        "tool_id": "nuclei-web",
                        "label": "Nuclei Web",
                        "status": "executed",
                        "attempted_at": "2026-03-17T02:00:00Z",
                        "port": "443",
                        "protocol": "tcp",
                        "service": "https",
                        "pack_ids": ["external_surface", "vuln_validation"],
                        "artifact_refs": ["/tmp/nuclei-10.0.0.5.txt"],
                    }
                ],
                "credentials": [
                    {"username": "svc-web", "realm": "local", "type": "password", "evidence": "manual note", "source_kind": "observed"},
                ],
                "sessions": [
                    {"session_type": "shell", "username": "svc-web", "host": "10.0.0.9", "port": "443", "protocol": "tcp", "evidence": "validated shell", "source_kind": "observed"},
                ],
                "screenshots": [
                    {"artifact_ref": "/tmp/10.0.0.5-443-screenshot.png", "filename": "10.0.0.5-443-screenshot.png", "port": "443", "protocol": "tcp"},
                ],
                "artifacts": [
                    {"ref": "/tmp/nuclei-10.0.0.5.txt", "kind": "artifact", "tool_id": "nuclei-web", "port": "443", "protocol": "tcp"},
                ],
            })

            step = PlanStep.from_legacy_fields(
                tool_id="nuclei-web",
                label="Nuclei Web",
                command_template="nuclei -u https://[IP]:[PORT] -silent",
                protocol="tcp",
                score=100.0,
                rationale="Validate web exposure and collect evidence.",
                mode="deterministic",
                goal_profile="external_pentest",
                family_id="nuclei-web",
                target_ref={"host_ip": "10.0.0.5", "port": "443", "service": "https", "protocol": "tcp"},
            )
            step.linked_evidence_refs = ["host:10.0.0.5", "service:https"]
            record = ExecutionRecord.from_plan_step(
                step,
                started_at="2026-03-17T02:10:00Z",
                finished_at="2026-03-17T02:10:05Z",
                exit_status="completed",
                stdout_ref="process_output:42",
                artifact_refs=["/tmp/nuclei-10.0.0.5.txt", "/tmp/10.0.0.5-443-screenshot.png"],
            )
            store_execution_record(
                project.database,
                record,
                step=step,
                host_ip="10.0.0.5",
                port="443",
                protocol="tcp",
                service="https",
            )

            log_scheduler_decision(project.database, {
                "timestamp": "2026-03-17T02:12:00Z",
                "host_ip": "10.0.0.5",
                "port": "443",
                "protocol": "tcp",
                "service": "https",
                "scheduler_mode": "deterministic",
                "goal_profile": "external_pentest",
                "engagement_preset": "external_pentest",
                "tool_id": "hydra-http-form",
                "label": "HTTP Bruteforce",
                "command_family_id": "hydra-http-form",
                "danger_categories": "credential_bruteforce",
                "risk_tags": "credential_bruteforce,high_detection_likelihood",
                "requires_approval": "True",
                "policy_decision": "approval_required",
                "policy_reason": "Credential attacks require approval in external pentest.",
                "risk_summary": "Could trigger account lockouts.",
                "safer_alternative": "Validate known credentials first.",
                "family_policy_state": "",
                "approved": "False",
                "executed": "False",
                "reason": "pending approval #1",
                "rationale": "Validate weak authentication controls.",
                "approval_id": "1",
            })

            queue_pending_approval(project.database, {
                "host_ip": "10.0.0.5",
                "port": "443",
                "protocol": "tcp",
                "service": "https",
                "tool_id": "hydra-http-form",
                "label": "HTTP Bruteforce",
                "command_template": "hydra -L users.txt -P pass.txt https-post-form",
                "command_family_id": "hydra-http-form",
                "danger_categories": "credential_bruteforce",
                "risk_tags": "credential_bruteforce,high_detection_likelihood",
                "scheduler_mode": "deterministic",
                "goal_profile": "external_pentest",
                "engagement_preset": "external_pentest",
                "rationale": "Validate weak authentication controls.",
                "policy_decision": "approval_required",
                "policy_reason": "Credential attacks require approval in external pentest.",
                "risk_summary": "Could trigger account lockouts.",
                "safer_alternative": "Validate known credentials first.",
                "evidence_refs": "host:10.0.0.5,/admin",
            })

            upsert_graph_annotation(
                project.database,
                target_kind="node",
                target_ref="graph-node-manual",
                body="Operator conclusion: keep this host in scope for validation",
                created_by="tester",
                source_ref=f"host:{host_id}:annotation",
            )

            engagement_policy = {
                "preset": "external_pentest",
                "scope": "external",
                "intent": "pentest",
                "allow_exploitation": True,
                "allow_lateral_movement": False,
                "approval_mode": "risky",
            }
            host_row = {
                "id": host_id,
                "ip": "10.0.0.5",
                "hostname": "portal.local",
                "status": "up",
                "os": "Linux",
            }

            host_report = build_host_report(
                project.database,
                host_row=host_row,
                engagement_policy=engagement_policy,
                project_metadata={"name": "reporting.legion", "is_temporary": True},
            )
            project_report = build_project_report(
                project.database,
                project_metadata={"name": "reporting.legion", "is_temporary": True},
                engagement_policy=engagement_policy,
                summary={"hosts": 1, "services": 1},
                host_inventory=[host_row],
            )

            self.assertEqual(2, host_report["report_version"])
            self.assertEqual("external_pentest", host_report["scope_and_policy"]["engagement_policy"]["preset"])
            self.assertGreaterEqual(host_report["validated_findings"]["count"], 2)
            self.assertTrue(host_report["attack_paths"])
            self.assertTrue(host_report["evidence_references"])
            self.assertTrue(host_report["recommended_next_steps"]["manual_tests"])
            self.assertTrue(host_report["skipped_or_blocked_actions"])
            self.assertTrue(host_report["observed_facts"])
            self.assertTrue(host_report["ai_suggestions"])
            self.assertTrue(host_report["operator_conclusions"])

            self.assertEqual(2, project_report["report_version"])
            self.assertEqual("external_pentest", project_report["scope_and_policy"]["engagement_policy"]["preset"])
            self.assertEqual(1, project_report["summary_of_discovered_assets"]["host_count"])
            self.assertGreaterEqual(project_report["validated_findings"]["count"], 2)
            self.assertTrue(project_report["attack_paths"])
            self.assertTrue(project_report["recommended_next_steps"]["pending_approvals"])
            self.assertTrue(project_report["methodology_coverage"]["strategy_packs_seen"])

            host_markdown = render_host_report_markdown(host_report)
            project_markdown = render_project_report_markdown(project_report)
            self.assertIn("# Legion Host Report", host_markdown)
            self.assertIn("## Scope and Policy", host_markdown)
            self.assertIn("## Provenance Separation", host_markdown)
            self.assertIn("# Legion Project Report", project_markdown)
            self.assertIn("## Attack Paths / Exploitation Chain", project_markdown)
            self.assertIn("## Skipped or Blocked Actions Due to Policy", project_markdown)
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
