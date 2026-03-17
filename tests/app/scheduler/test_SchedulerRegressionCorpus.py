import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.ProjectManager import ProjectManager
from app.importers.nmap_runner import import_nmap_xml_into_project
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.approvals import get_pending_approval, queue_pending_approval
from app.scheduler.config import SchedulerConfigManager
from app.scheduler.execution import store_execution_record
from app.scheduler.graph import ensure_scheduler_graph_tables, get_evidence_graph_snapshot
from app.scheduler.models import ExecutionRecord, PlanStep
from app.scheduler.planner import SchedulerPlanner
from app.scheduler.reporting import build_project_report
from app.scheduler.state import get_target_state, upsert_target_state
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory
from db.entities.cve import cve


CORPUS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "fixtures", "scheduler-regression")
)


class SchedulerRegressionCorpusTest(unittest.TestCase):
    def _load_manifest(self):
        with open(os.path.join(CORPUS_DIR, "manifest.json"), "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _load_case(self, case_id):
        manifest = self._load_manifest()
        mapping = {
            str(item.get("id", "")): str(item.get("file", ""))
            for item in list(manifest.get("cases", []) or [])
            if isinstance(item, dict)
        }
        filename = mapping[case_id]
        with open(os.path.join(CORPUS_DIR, filename), "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _create_project(self):
        project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        return project_manager, project

    def test_manifest_lists_internal_external_and_approval_cases(self):
        manifest = self._load_manifest()
        kinds = {str(item.get("kind", "")) for item in manifest.get("cases", [])}
        case_ids = {str(item.get("id", "")) for item in manifest.get("cases", [])}

        self.assertTrue({"internal_project", "external_project", "approval_case"}.issubset(kinds))
        self.assertTrue({"internal_recon", "external_web", "approval_required"}.issubset(case_ids))

    def test_internal_recon_corpus_case_locks_deterministic_mapping_and_state(self):
        case = self._load_case("internal_recon")
        project_manager, project = self._create_project()
        try:
            import_nmap_xml_into_project(project=project, xml_path=os.path.join(CORPUS_DIR, case["nmap_xml"]))
            hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
            self.assertEqual(1, len(hosts))
            host = hosts[0]
            self.assertEqual(case["expectations"]["imported_host_ip"], host.ip)

            upsert_target_state(project.database, int(host.id), dict(case["target_state"]))
            persisted_state = get_target_state(project.database, int(host.id))
            self.assertEqual("protocol_enumeration", persisted_state["next_phase"])
            self.assertEqual("Active Directory", persisted_state["technologies"][0]["name"])
            self.assertEqual("missing_safe_smb_enum", persisted_state["coverage_gaps"][0]["gap_id"])

            with tempfile.TemporaryDirectory() as tmpdir:
                manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
                manager.update_preferences({
                    "mode": "deterministic",
                    "engagement_policy": dict(case["engagement_policy"]),
                })
                planner = SchedulerPlanner(manager)
                planner_settings = case["planner"]
                steps = planner.plan_actions(
                    planner_settings["service"],
                    planner_settings["protocol"],
                    SimpleNamespace(
                        automatedAttacks=list(planner_settings["automated_attacks"]),
                        portActions=list(planner_settings["port_actions"]),
                    ),
                )

            tool_ids = [item.tool_id for item in steps]
            blocked_tool_ids = [item.tool_id for item in steps if item.is_blocked]
            allowed_tool_ids = [item.tool_id for item in steps if item.policy_decision == "allowed"]

            self.assertEqual(case["expectations"]["tool_order"], tool_ids)
            self.assertEqual(case["expectations"]["blocked_tools"], blocked_tool_ids)
            self.assertEqual(case["expectations"]["allowed_tools"], allowed_tool_ids)
        finally:
            project_manager.closeProject(project)

    def test_external_web_corpus_case_builds_graph_and_report(self):
        case = self._load_case("external_web")
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_graph_tables(project.database)
            import_nmap_xml_into_project(project=project, xml_path=os.path.join(CORPUS_DIR, case["nmap_xml"]))
            hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
            self.assertEqual(1, len(hosts))
            host = hosts[0]
            host_id = int(host.id)

            session = project.database.session()
            for item in list(case.get("cves", []) or []):
                session.add(cve(
                    name=item["name"],
                    url=item["url"],
                    product=item["product"],
                    hostId=str(host_id),
                    severity=item["severity"],
                    source=item["source"],
                    version=item["version"],
                    exploitId=item["exploitId"],
                    exploit=item["exploit"],
                    exploitUrl=item["exploitUrl"],
                ))
            session.commit()
            session.close()

            upsert_target_state(project.database, host_id, dict(case["target_state"]))
            execution_payload = dict(case["execution_record"])
            step = PlanStep.from_legacy_fields(
                tool_id=execution_payload["tool_id"],
                label=execution_payload["label"],
                command_template=execution_payload["command_template"],
                protocol=execution_payload["protocol"],
                score=100.0,
                rationale="Corpus validation run.",
                mode="deterministic",
                goal_profile="external_pentest",
                family_id=execution_payload["family_id"],
                target_ref=dict(execution_payload["target_ref"]),
            )
            step.linked_evidence_refs = [
                f"host:{execution_payload['target_ref']['host_ip']}",
                execution_payload["target_ref"]["service"],
            ]
            record = ExecutionRecord.from_plan_step(
                step,
                started_at="2026-03-17T12:00:00Z",
                finished_at="2026-03-17T12:00:05Z",
                exit_status="completed",
                stdout_ref=execution_payload["stdout_ref"],
                artifact_refs=list(execution_payload["artifact_refs"]),
            )
            store_execution_record(
                project.database,
                record,
                step=step,
                host_ip=execution_payload["target_ref"]["host_ip"],
                port=execution_payload["target_ref"]["port"],
                protocol=execution_payload["target_ref"]["protocol"],
                service=execution_payload["target_ref"]["service"],
            )

            graph = get_evidence_graph_snapshot(project.database)
            node_types = {item["type"] for item in graph["nodes"]}
            self.assertTrue(set(case["expectations"]["required_node_types"]).issubset(node_types))
            self.assertTrue(any(item["type"] == "screenshot" for item in graph["nodes"]))
            self.assertTrue(any(item["type"] == "cve" and item["label"] == "CVE-2025-1234" for item in graph["nodes"]))

            host_row = {
                "id": host_id,
                "ip": host.ip,
                "hostname": host.hostname,
                "status": getattr(host, "status", "up"),
                "os": getattr(host, "osMatch", ""),
            }
            report = build_project_report(
                project.database,
                project_metadata={"name": "external-web-corpus.legion", "is_temporary": True},
                engagement_policy=dict(case["engagement_policy"]),
                summary={"hosts": 1, "services": 2},
                host_inventory=[host_row],
            )

            self.assertEqual(1, report["summary_of_discovered_assets"]["host_count"])
            self.assertGreaterEqual(report["validated_findings"]["count"], 1)
            self.assertTrue(report["evidence_references"])
            for section_name in case["expectations"]["required_report_sections"]:
                self.assertIn(section_name, report)
        finally:
            project_manager.closeProject(project)

    def test_approval_required_corpus_case_round_trips_policy_and_queue(self):
        case = self._load_case("approval_required")
        project_manager, project = self._create_project()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
                manager.update_preferences({
                    "mode": "deterministic",
                    "engagement_policy": dict(case["engagement_policy"]),
                })
                planner = SchedulerPlanner(manager)
                planner_settings = case["planner"]
                steps = planner.plan_actions(
                    planner_settings["service"],
                    planner_settings["protocol"],
                    SimpleNamespace(
                        automatedAttacks=list(planner_settings["automated_attacks"]),
                        portActions=list(planner_settings["port_actions"]),
                    ),
                )

            approval_required = [item.tool_id for item in steps if item.policy_decision == "approval_required"]
            allowed = [item.tool_id for item in steps if item.policy_decision == "allowed"]

            self.assertEqual(case["expectations"]["approval_required_tools"], approval_required)
            self.assertEqual(case["expectations"]["allowed_tools"], allowed)

            approval_id = queue_pending_approval(project.database, dict(case["approval_payload"]))
            stored = get_pending_approval(project.database, approval_id)

            self.assertEqual("approval_required", stored["policy_decision"])
            self.assertEqual("hydra-http-form", stored["tool_id"])
            self.assertIn("account_lockout_risk", stored["risk_tags"])
        finally:
            project_manager.closeProject(project)

    @patch.object(SchedulerPlanner, "_plan_ai", return_value=[])
    def test_ai_mode_corpus_case_falls_back_to_deterministic_without_bypassing_governance(self, _mock_plan_ai):
        case = self._load_case("approval_required")
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SchedulerConfigManager(config_path=os.path.join(tmpdir, "scheduler-ai.json"))
            manager.update_preferences({
                "mode": "ai",
                "provider": "lm_studio",
                "engagement_policy": dict(case["engagement_policy"]),
            })
            planner = SchedulerPlanner(manager)
            planner_settings = case["planner"]
            steps = planner.plan_actions(
                planner_settings["service"],
                planner_settings["protocol"],
                SimpleNamespace(
                    automatedAttacks=list(planner_settings["automated_attacks"]),
                    portActions=list(planner_settings["port_actions"]),
                ),
            )

        self.assertTrue(steps)
        self.assertEqual("deterministic", steps[0].origin_mode)
        self.assertTrue(any(item.policy_decision == "approval_required" for item in steps))


if __name__ == "__main__":
    unittest.main()
