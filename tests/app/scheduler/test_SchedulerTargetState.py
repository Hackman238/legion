import unittest

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.scheduler.insights import get_host_ai_state, upsert_host_ai_state
from app.scheduler.state import (
    delete_target_state,
    ensure_scheduler_target_state_table,
    get_target_state,
    upsert_target_state,
)
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory


class SchedulerTargetStateStoreTest(unittest.TestCase):
    def _create_project(self):
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        return project_manager, project

    def test_upsert_get_delete_target_state_round_trip(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            upsert_target_state(project.database, 11, {
                "host_ip": "10.0.0.5",
                "last_mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "engagement_preset": "internal_recon",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "hostname": "portal.local",
                "hostname_confidence": 96,
                "os_match": "Linux",
                "os_confidence": 80,
                "next_phase": "targeted_checks",
                "technologies": [{"name": "nginx", "version": "1.25", "cpe": "cpe:/a:nginx:nginx:1.25", "evidence": "banner"}],
                "findings": [{"title": "Admin panel exposed", "severity": "medium", "cvss": 5.0, "cve": "", "evidence": "/admin"}],
                "manual_tests": [{"why": "validate auth", "command": "curl -k https://10.0.0.5/admin", "scope_note": "safe"}],
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https", "service_product": "nginx"}],
                "urls": [
                    {"url": "https://10.0.0.5:443/", "port": "443", "protocol": "tcp", "service": "https"},
                    {"url": "https://10.0.0.5", "port": "", "protocol": "tcp", "service": "https"},
                    {"url": "http://10.0.0.5:8080/", "port": "8080", "protocol": "tcp", "service": "http"},
                ],
                "coverage_gaps": [{"gap_id": "missing_nikto", "description": "missing nikto", "recommended_tool_ids": ["nikto"]}],
                "attempted_actions": [{"tool_id": "nuclei-web", "status": "executed", "attempted_at": "2026-03-17T01:00:00Z", "port": "443", "protocol": "tcp", "service": "https"}],
                "credentials": [{"username": "svc-web", "realm": "local", "type": "password", "evidence": "manual note"}],
                "sessions": [{"session_type": "shell", "username": "svc-web", "host": "10.0.0.5", "port": "443", "protocol": "tcp"}],
                "screenshots": [{
                    "artifact_ref": "/tmp/10.0.0.5-443-screenshot.png",
                    "filename": "10.0.0.5-443-screenshot.png",
                    "port": "443",
                    "protocol": "tcp",
                    "target_url": "https://portal.local:443",
                    "capture_engine": "EyeWitness",
                    "captured_at": "2026-03-22T06:00:00+00:00",
                    "service_name": "https",
                    "hostname": "portal.local",
                }],
                "artifacts": [{"ref": "/tmp/scan.txt", "kind": "artifact", "tool_id": "nuclei-web", "port": "443", "protocol": "tcp"}],
                "raw": {"source": "test"},
            })

            loaded = get_target_state(project.database, 11)
            self.assertIsNotNone(loaded)
            self.assertEqual("internal_recon", loaded["engagement_preset"])
            self.assertEqual("portal.local", loaded["hostname"])
            self.assertEqual("nginx", loaded["technologies"][0]["name"])
            self.assertEqual("Admin panel exposed", loaded["findings"][0]["title"])
            loaded_urls = {str(item.get("url", "")): str(item.get("port", "")) for item in loaded["urls"]}
            self.assertEqual("443", loaded_urls["https://10.0.0.5"])
            self.assertEqual("8080", loaded_urls["http://10.0.0.5:8080"])
            self.assertEqual("missing_nikto", loaded["coverage_gaps"][0]["gap_id"])
            self.assertEqual("nuclei-web", loaded["attempted_actions"][0]["tool_id"])
            self.assertEqual("svc-web", loaded["credentials"][0]["username"])
            self.assertEqual("shell", loaded["sessions"][0]["session_type"])
            self.assertEqual("https://portal.local:443", loaded["screenshots"][0]["target_url"])
            self.assertEqual("EyeWitness", loaded["screenshots"][0]["capture_engine"])
            self.assertEqual("/tmp/scan.txt", loaded["artifacts"][0]["ref"])

            deleted = delete_target_state(project.database, 11)
            self.assertEqual(1, deleted)
            self.assertIsNone(get_target_state(project.database, 11))
        finally:
            project_manager.closeProject(project)

    def test_legacy_ai_state_migrates_into_target_state_and_legacy_reads_from_target_state(self):
        project_manager, project = self._create_project()
        try:
            upsert_host_ai_state(project.database, 22, {
                "host_ip": "10.0.0.22",
                "provider": "openai",
                "goal_profile": "internal_asset_discovery",
                "last_port": "445",
                "last_protocol": "tcp",
                "last_service": "smb",
                "hostname": "dc01.local",
                "hostname_confidence": 93,
                "os_match": "Windows",
                "os_confidence": 88,
                "next_phase": "safe_followup",
                "technologies": [{"name": "samba", "version": "4.x", "cpe": "cpe:/a:samba:samba:4", "evidence": "service"}],
                "findings": [{"title": "SMB signing not required", "severity": "high", "cvss": 7.5, "cve": "", "evidence": "smb-security-mode"}],
                "manual_tests": [{"why": "validate relay", "command": "ntlmrelayx.py -tf targets.txt", "scope_note": "approval"}],
                "raw": {"actions": [{"tool_id": "smb-enum-users.nse"}]},
            })

            target_state = get_target_state(project.database, 22)
            self.assertIsNotNone(target_state)
            self.assertEqual("ai", target_state["last_mode"])
            self.assertEqual("openai", target_state["provider"])
            self.assertEqual("samba", target_state["technologies"][0]["name"])
            self.assertEqual("SMB signing not required", target_state["findings"][0]["title"])

            legacy_view = get_host_ai_state(project.database, 22)
            self.assertIsNotNone(legacy_view)
            self.assertEqual("dc01.local", legacy_view["hostname"])
            self.assertEqual("safe_followup", legacy_view["next_phase"])
            self.assertEqual("samba", legacy_view["technologies"][0]["name"])
        finally:
            project_manager.closeProject(project)

    def test_upsert_target_state_filters_reference_titles_and_placeholder_findings(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            upsert_target_state(project.database, 33, {
                "host_ip": "10.0.0.33",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "findings": [
                    {
                        "title": "//cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192",
                        "severity": "medium",
                        "cve": "CVE-2011-3192",
                        "evidence": "//cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192",
                    },
                    {
                        "title": "Slowloris DOS attack",
                        "severity": "medium",
                        "cve": "CVE-2007-6750",
                        "evidence": "previous scan result",
                    },
                    {
                        "title": "Apache byterange filter DoS",
                        "severity": "medium",
                        "cve": "CVE-2011-3192",
                        "evidence": "IDs: CVE:CVE-2011-3192",
                    },
                ],
            })

            loaded = get_target_state(project.database, 33)
            titles = {str(item.get("title", "")).strip() for item in loaded.get("findings", [])}

            self.assertIn("Apache byterange filter DoS", titles)
            self.assertNotIn("//cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192", titles)
            self.assertNotIn("Slowloris DOS attack", titles)
        finally:
            project_manager.closeProject(project)

    def test_upsert_target_state_preserves_nuclei_quality_metadata_and_merges_quality_events(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            upsert_target_state(project.database, 44, {
                "host_ip": "10.0.0.44",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "raw": {"source": "initial-observation"},
            })

            upsert_target_state(project.database, 44, {
                "host_ip": "10.0.0.44",
                "last_port": "443",
                "last_protocol": "tcp",
                "last_service": "https",
                "findings": [
                    {
                        "title": "Reflected debug endpoint",
                        "severity": "info",
                        "evidence": "request payload reflected in response",
                        "quality_action": "downgraded",
                        "quality_reason": "reflection_only_response",
                        "severity_before": "high",
                    }
                ],
                "finding_quality_events": [
                    {
                        "title": "CVE-2026-2222",
                        "cve": "CVE-2026-2222",
                        "action": "suppressed",
                        "reason": "waf_block_page",
                        "severity_before": "critical",
                        "evidence": "Attention Required! Cloudflare - Sorry, you have been blocked",
                        "matched_url": "https://portal.example/login",
                    }
                ],
            })

            loaded = get_target_state(project.database, 44)
            self.assertEqual("initial-observation", loaded["raw"]["source"])
            finding = loaded["findings"][0]
            self.assertEqual("downgraded", finding["quality_action"])
            self.assertEqual("reflection_only_response", finding["quality_reason"])
            self.assertEqual("high", finding["severity_before"])

            quality_events = loaded.get("finding_quality_events", [])
            self.assertEqual(1, len(quality_events))
            self.assertEqual("suppressed", quality_events[0]["action"])
            self.assertEqual("waf_block_page", quality_events[0]["reason"])
            self.assertEqual("https://portal.example/login", quality_events[0]["matched_url"])
            self.assertEqual("waf_block_page", loaded["raw"]["finding_quality_events"][0]["reason"])
        finally:
            project_manager.closeProject(project)

    def test_upsert_target_state_classifies_device_categories_and_honors_manual_override(self):
        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            upsert_target_state(project.database, 55, {
                "host_ip": "10.0.0.55",
                "hostname": "dc01.local",
                "os_match": "Microsoft Windows Server 2022",
                "service_inventory": [
                    {"port": "135", "protocol": "tcp", "state": "open", "service": "msrpc", "service_product": "Microsoft Windows RPC"},
                    {"port": "445", "protocol": "tcp", "state": "open", "service": "microsoft-ds", "service_product": "Microsoft Directory Services"},
                    {"port": "443", "protocol": "tcp", "state": "open", "service": "https", "service_product": "Microsoft IIS httpd"},
                ],
                "technologies": [
                    {"name": "windows", "cpe": "cpe:/o:microsoft:windows", "evidence": "service detection"},
                    {"name": "Microsoft IIS httpd", "version": "10.0", "evidence": "banner"},
                ],
            })

            loaded = get_target_state(project.database, 55)
            category_names = {str(item.get("name", "")) for item in loaded.get("device_categories", [])}
            self.assertIn("Windows", category_names)
            self.assertIn("Server", category_names)
            self.assertFalse(bool(loaded.get("device_category_override", False)))

            upsert_target_state(project.database, 55, {
                "host_ip": "10.0.0.55",
                "manual_device_categories": ["Database"],
                "device_category_override": True,
            })
            overridden = get_target_state(project.database, 55)
            self.assertTrue(bool(overridden.get("device_category_override", False)))
            self.assertEqual(["Database"], [str(item.get("name", "")) for item in overridden.get("device_categories", [])])
            self.assertEqual(["Database"], [str(item.get("name", "")) for item in overridden.get("manual_device_categories", [])])
        finally:
            project_manager.closeProject(project)



class TargetStateLockTableTest(unittest.TestCase):
    def test_lock_entries_are_released_after_use(self):
        from app.scheduler import state as state_module

        database = object()
        with state_module._target_state_lock(database, 7):
            self.assertIn((id(database), 7), state_module._target_state_locks)
            with state_module._target_state_lock(database, 7):  # re-entrant
                pass
            self.assertIn((id(database), 7), state_module._target_state_locks)
        self.assertNotIn((id(database), 7), state_module._target_state_locks)


class DeviceCategoryRulesCacheTest(unittest.TestCase):
    def test_same_size_edit_within_one_mtime_tick_is_picked_up_after_max_age(self):
        import json
        import os
        import tempfile
        from unittest.mock import patch
        from app.scheduler import state as state_module

        def write_rules(path, name):
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"device_categories": [{"name": name, "match": {"hostname_contains": ["x"]}}]}, handle)
            os.utime(path, ns=(1_000_000_000, 1_000_000_000))  # identical mtime: a coarse filesystem clock

        clock = {"now": 100.0}
        state_module._device_category_rules_cache.clear()
        self.addCleanup(state_module._device_category_rules_cache.clear)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "scheduler-ai.json")
            write_rules(config_path, "alpha")
            with patch("app.paths.get_scheduler_config_path", return_value=config_path), \
                    patch.object(state_module.time, "monotonic", side_effect=lambda: clock["now"]):
                first = [rule["name"] for rule in state_module._load_custom_device_category_rules()]
                write_rules(config_path, "bravo")  # same size, same mtime
                clock["now"] += 0.5
                cached = [rule["name"] for rule in state_module._load_custom_device_category_rules()]
                clock["now"] += 5.0
                refreshed = [rule["name"] for rule in state_module._load_custom_device_category_rules()]

        self.assertIn("alpha", first)
        self.assertEqual(first, cached)
        self.assertIn("bravo", refreshed)

    def test_torn_rules_file_is_not_cached(self):
        import json
        import os
        import tempfile
        from unittest.mock import patch
        from app.scheduler import state as state_module

        def write_rules(path, name):
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"device_categories": [{"name": name, "match": {"hostname_contains": ["x"]}}]}, handle)

        clock = {"now": 100.0}
        state_module._device_category_rules_cache.clear()
        self.addCleanup(state_module._device_category_rules_cache.clear)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "scheduler-ai.json")
            write_rules(config_path, "alpha")
            with patch("app.paths.get_scheduler_config_path", return_value=config_path), \
                    patch.object(state_module.time, "monotonic", side_effect=lambda: clock["now"]):
                first = [rule["name"] for rule in state_module._load_custom_device_category_rules()]
                clock["now"] += 5.0
                # A save in progress (non-atomic writer / torn read): the file is not valid JSON right now.
                with open(config_path, "w", encoding="utf-8") as handle:
                    handle.write('{"device_categories": [{"name": "bra')
                torn = state_module._load_custom_device_category_rules()
                write_rules(config_path, "bravo")
                clock["now"] += 0.1  # well within the cache max age
                after = [rule["name"] for rule in state_module._load_custom_device_category_rules()]

        self.assertIn("alpha", first)
        self.assertNotIn("alpha", [rule.get("name") for rule in torn])
        self.assertIn("bravo", after)

if __name__ == "__main__":
    unittest.main()


class SchedulerTargetStateConcurrencyTest(unittest.TestCase):
    def _create_project(self):
        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)
        return project_manager, project

    def test_concurrent_upserts_for_same_host_do_not_drop_merged_rows(self):
        import threading

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            upsert_target_state(project.database, 21, {"host_ip": "10.0.0.21"})
            errors = []

            def worker(index):
                try:
                    upsert_target_state(project.database, 21, {
                        "host_ip": "10.0.0.21",
                        "findings": [{"title": f"Finding {index}", "severity": "low", "evidence": f"e{index}"}],
                    })
                except Exception as exc:  # pragma: no cover - surfaced through the assertion below
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual([], errors)
            titles = {item.get("title") for item in get_target_state(project.database, 21).get("findings", [])}
            self.assertEqual({f"Finding {index}" for index in range(6)}, titles)
        finally:
            project_manager.closeProject(project)

    def test_resync_without_changes_reports_no_graph_mutations(self):
        from app.scheduler.graph import sync_target_state_to_evidence_graph

        project_manager, project = self._create_project()
        try:
            state = upsert_target_state(project.database, 31, {
                "host_ip": "10.0.0.31",
                "hostname": "edge.local",
                "service_inventory": [{"port": "443", "protocol": "tcp", "state": "open", "service": "https"}],
            })
            sync_target_state_to_evidence_graph(project.database, host_id=31, target_state=state)
            mutations = sync_target_state_to_evidence_graph(project.database, host_id=31, target_state=state)
            self.assertEqual([], mutations)
        finally:
            project_manager.closeProject(project)

    def test_schema_ensure_is_cached_per_engine_once_tables_exist(self):
        from app.scheduler import schema_cache

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            ensure_scheduler_target_state_table(project.database)
            engine = project.database.session().get_bind()
            self.assertIn("target_state", schema_cache._ensured_by_engine.get(engine, set()))
        finally:
            project_manager.closeProject(project)

    def test_modify_target_state_does_not_lose_concurrent_scheduler_updates(self):
        import threading
        from app.scheduler.state import modify_target_state

        project_manager, project = self._create_project()
        try:
            upsert_target_state(project.database, 41, {
                "host_ip": "10.0.0.41",
                "screenshots": [
                    {"artifact_ref": "/tmp/a-80.png", "filename": "a-80.png", "port": "80", "protocol": "tcp"},
                    {"artifact_ref": "/tmp/a-443.png", "filename": "a-443.png", "port": "443", "protocol": "tcp"},
                ],
            })
            mutate_started = threading.Event()
            writer_done = threading.Event()
            errors = []

            def scheduler_writer():
                mutate_started.wait(5)
                try:
                    upsert_target_state(project.database, 41, {
                        "host_ip": "10.0.0.41",
                        "findings": [{"title": "Concurrent finding", "severity": "low", "evidence": "scheduler"}],
                    })
                except Exception as exc:  # pragma: no cover - surfaced through the assertion below
                    errors.append(exc)
                finally:
                    writer_done.set()

            writer = threading.Thread(target=scheduler_writer)
            writer.start()

            def drop_port_80(state):
                mutate_started.set()
                # The scheduler write must wait for this read-modify-write instead of landing in between.
                self.assertFalse(writer_done.wait(0.3))
                state["screenshots"] = [item for item in state.get("screenshots", []) if item.get("port") != "80"]
                return state

            stored = modify_target_state(project.database, 41, drop_port_80)
            writer.join(5)

            self.assertEqual([], errors)
            self.assertEqual(["443"], [item.get("port") for item in stored.get("screenshots", [])])
            final = get_target_state(project.database, 41)
            self.assertEqual(["443"], [item.get("port") for item in final.get("screenshots", [])])
            self.assertEqual(["Concurrent finding"], [item.get("title") for item in final.get("findings", [])])
        finally:
            project_manager.closeProject(project)

    def test_graph_sync_runs_under_the_per_host_lock(self):
        import threading
        from unittest.mock import patch
        from app.scheduler import state as state_module

        project_manager, project = self._create_project()
        try:
            ensure_scheduler_target_state_table(project.database)
            lock_key = (id(getattr(project.database, "engine", None) or project.database), 51)
            observed = {}

            def _sync(database, *, host_id, target_state=None):
                entry = state_module._target_state_locks.get(lock_key)
                observed["lock_present"] = entry is not None
                if entry is not None:
                    # Another thread must not be able to take the host lock while the sync runs.
                    acquired = []
                    probe = threading.Thread(target=lambda: acquired.append(entry[0].acquire(timeout=0.3)))
                    probe.start()
                    probe.join(5)
                    if acquired and acquired[0]:
                        entry[0].release()
                    observed["lock_free_during_sync"] = bool(acquired and acquired[0])
                return []

            with patch("app.scheduler.graph.sync_target_state_to_evidence_graph", side_effect=_sync):
                upsert_target_state(project.database, 51, {"host_ip": "10.0.0.51"})
                self.assertEqual({"lock_present": True, "lock_free_during_sync": False}, observed)
                observed.clear()
                state_module.modify_target_state(project.database, 51, lambda state: state)
                self.assertEqual({"lock_present": True, "lock_free_during_sync": False}, observed)
        finally:
            project_manager.closeProject(project)

    def test_modify_target_state_bumps_updated_at(self):
        from app.scheduler.state import modify_target_state

        project_manager, project = self._create_project()
        try:
            stored = upsert_target_state(project.database, 61, {
                "host_ip": "10.0.0.61",
                "updated_at": "2020-01-01T00:00:00+00:00",
                "screenshots": [
                    {"artifact_ref": "/tmp/a-80.png", "filename": "a-80.png", "port": "80", "protocol": "tcp"},
                ],
            })
            self.assertEqual("2020-01-01T00:00:00+00:00", stored["updated_at"])

            modified = modify_target_state(project.database, 61, lambda state: state)  # identity round-trip

            self.assertNotEqual("2020-01-01T00:00:00+00:00", modified["updated_at"])
            self.assertGreater(modified["updated_at"], "2020-01-01T00:00:00+00:00")
            self.assertEqual(modified["updated_at"], get_target_state(project.database, 61)["updated_at"])
            self.assertEqual(["80"], [item.get("port") for item in modified.get("screenshots", [])])
        finally:
            project_manager.closeProject(project)
