import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


class LogicHeadlessActionsTest(unittest.TestCase):
    @patch("app.screenshot_targets.socket.getaddrinfo")
    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_uses_port_id_and_service_lookup(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run,
            mock_getaddrinfo,
    ):
        from app.logic import Logic
        from app.screenshot_targets import resolve_hostname_addresses

        resolve_hostname_addresses.cache_clear()
        mock_getaddrinfo.return_value = [("family", "socktype", "proto", "", ("10.0.0.5", 0))]

        host = SimpleNamespace(id=1, ip="10.0.0.5", hostname="dc01.local")
        port = SimpleNamespace(portId="445", protocol="tcp", state="open", serviceId=9)
        service = SimpleNamespace(name="smb")

        repo_container = SimpleNamespace(
            hostRepository=SimpleNamespace(getAllHostObjs=lambda: [host]),
            portRepository=SimpleNamespace(getPortsByHostId=lambda _host_id: [port]),
            serviceRepository=SimpleNamespace(getServiceById=lambda _service_id: service),
        )

        settings = SimpleNamespace(
            automatedAttacks=[["smb-enum-users.nse", "smb", "tcp"]],
            portActions=[[
                "SMB Enum Users",
                "smb-enum-users.nse",
                "echo [IP]:[PORT] > [OUTPUT]",
                "smb"
            ]]
        )
        _mock_app_settings_cls._ensure_nmap_hostname_target_support.side_effect = lambda command, _target: command
        _mock_app_settings_cls._canonicalize_web_target_placeholders.side_effect = lambda command: command
        _mock_app_settings_cls._collapse_redundant_fallbacks.side_effect = lambda command: command
        mock_settings_cls.return_value = settings
        mock_subprocess_run.return_value = SimpleNamespace(stdout="", stderr="")

        logic = Logic(MagicMock(), MagicMock(), MagicMock())
        logic.activeProject = SimpleNamespace(
            repositoryContainer=repo_container,
            properties=SimpleNamespace(outputFolder="/tmp", runningFolder="/tmp"),
        )

        logic.run_scripted_actions()

        self.assertTrue(mock_subprocess_run.called)
        command = mock_subprocess_run.call_args[0][0]
        self.assertIn("dc01.local:445", command)

    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_persists_execution_record_for_real_project(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run,
    ):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.execution import list_execution_records
        from app.scheduler.state import get_target_state
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj
        from db.entities.port import portObj
        from db.entities.service import serviceObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            service = serviceObj(name="smb", host=host_id)
            session.add(service)
            session.commit()

            port = portObj("445", "tcp", "open", host_id, service.id)
            session.add(port)
            session.commit()
            session.close()

            settings = SimpleNamespace(
                automatedAttacks=[["smb-enum-users.nse", "smb", "tcp"]],
                portActions=[[
                    "SMB Enum Users",
                    "smb-enum-users.nse",
                    "echo [IP]:[PORT] > [OUTPUT]",
                    "smb",
                ]],
            )
            _mock_app_settings_cls._ensure_nmap_hostname_target_support.side_effect = lambda command, _target: command
            _mock_app_settings_cls._canonicalize_web_target_placeholders.side_effect = lambda command: command
            _mock_app_settings_cls._collapse_redundant_fallbacks.side_effect = lambda command: command
            mock_settings_cls.return_value = settings
            mock_subprocess_run.return_value = SimpleNamespace(stdout="ok", stderr="", returncode=0)

            logic = Logic(MagicMock(), MagicMock(), MagicMock())
            logic.activeProject = project

            logic.run_scripted_actions()

            records = list_execution_records(project.database, limit=10)

            self.assertEqual(1, len(records))
            self.assertEqual("smb-enum-users.nse", records[0]["tool_id"])
            self.assertEqual("deterministic", records[0]["scheduler_mode"])
            self.assertEqual("10.0.0.5", records[0]["host_ip"])
            self.assertEqual("445", records[0]["port"])
            self.assertEqual("completed", records[0]["exit_status"])
            target_state = get_target_state(project.database, host_id)
            self.assertIsNotNone(target_state)
            self.assertEqual("deterministic", target_state["last_mode"])
            self.assertEqual("445", target_state["last_port"])
            self.assertEqual("smb-enum-users.nse", target_state["attempted_actions"][0]["tool_id"])
            self.assertEqual("executed", target_state["attempted_actions"][0]["status"])
        finally:
            project_manager.closeProject(project)

    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_parses_tool_output_into_target_state(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run,
    ):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.state import get_target_state
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj
        from db.entities.port import portObj
        from db.entities.service import serviceObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            service = serviceObj(name="https", host=host_id)
            session.add(service)
            session.commit()

            port = portObj("443", "tcp", "open", host_id, service.id)
            session.add(port)
            session.commit()
            session.close()

            settings = SimpleNamespace(
                automatedAttacks=[["nuclei-web", "https", "tcp"]],
                portActions=[[
                    "Run nuclei web scan",
                    "nuclei-web",
                    "nuclei -u https://[IP]:[PORT] -o [OUTPUT].txt",
                    "https",
                ]],
            )
            _mock_app_settings_cls._ensure_nmap_hostname_target_support.side_effect = lambda command, _target: command
            _mock_app_settings_cls._canonicalize_web_target_placeholders.side_effect = lambda command: command
            _mock_app_settings_cls._collapse_redundant_fallbacks.side_effect = lambda command: command
            mock_settings_cls.return_value = settings
            mock_subprocess_run.return_value = SimpleNamespace(
                stdout="[CVE-2025-1111] [critical] https://10.0.0.5:443/admin authenticated admin panel exposure\n",
                stderr="",
                returncode=0,
            )

            logic = Logic(MagicMock(), MagicMock(), MagicMock())
            logic.activeProject = project

            logic.run_scripted_actions()

            target_state = get_target_state(project.database, host_id)
            self.assertIsNotNone(target_state)
            finding_cves = {str(item.get("cve", "")).strip().upper() for item in target_state["findings"]}
            discovered_urls = {str(item.get("url", "")).strip() for item in target_state["urls"]}
            self.assertIn("CVE-2025-1111", finding_cves)
            self.assertIn("https://10.0.0.5/admin", discovered_urls)
        finally:
            project_manager.closeProject(project)

    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_imports_discovered_subdomains(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run,
    ):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj
        from db.entities.port import portObj
        from db.entities.service import serviceObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="example.com", ipv4="example.com", hostname="example.com")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            service = serviceObj(name="https", host=host_id)
            session.add(service)
            session.commit()

            port = portObj("443", "tcp", "open", host_id, service.id)
            session.add(port)
            session.commit()
            session.close()

            settings = SimpleNamespace(
                automatedAttacks=[["subfinder", "host", "tcp"]],
                portActions=[[
                    "Run subfinder passive subdomain discovery",
                    "subfinder",
                    "printf 'api.example.com\\nadmin.example.com\\n'",
                    "host",
                ]],
            )
            _mock_app_settings_cls._ensure_nmap_hostname_target_support.side_effect = lambda command, _target: command
            _mock_app_settings_cls._canonicalize_web_target_placeholders.side_effect = lambda command: command
            _mock_app_settings_cls._collapse_redundant_fallbacks.side_effect = lambda command: command
            mock_settings_cls.return_value = settings
            mock_subprocess_run.return_value = SimpleNamespace(stdout="api.example.com\nadmin.example.com\n", stderr="", returncode=0)

            logic = Logic(MagicMock(), MagicMock(), MagicMock())
            logic.activeProject = project

            logic.run_scripted_actions()

            host_rows = project.repositoryContainer.hostRepository.getAllHostObjs()
            imported_hosts = {
                str(getattr(item, "hostname", "") or getattr(item, "ip", "") or "").strip()
                for item in list(host_rows or [])
            }
            self.assertIn("api.example.com", imported_hosts)
            self.assertIn("admin.example.com", imported_hosts)
        finally:
            project_manager.closeProject(project)

    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_bootstraps_discovered_hosts_with_httpx_and_runs_bounded_followup(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run,
    ):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.state import get_target_state
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            session = project.database.session()
            host = hostObj(ip="example.com", ipv4="example.com", hostname="example.com")
            session.add(host)
            session.commit()
            root_host_id = int(host.id)
            from db.entities.service import serviceObj
            from db.entities.port import portObj
            service = serviceObj(name="https", host=root_host_id)
            session.add(service)
            session.commit()
            port = portObj("443", "tcp", "open", root_host_id, service.id)
            session.add(port)
            session.commit()
            session.close()

            settings = SimpleNamespace(
                automatedAttacks=[["subfinder", "host", "tcp"]],
                portActions=[
                    [
                        "Run subfinder passive subdomain discovery",
                        "subfinder",
                        "printf 'api.example.com\\n'",
                        "host",
                    ],
                    [
                        "Run whatweb",
                        "whatweb",
                        "whatweb [WEB_URL] > [OUTPUT].txt",
                        "http,https,ssl,soap,http-proxy,http-alt,https-alt",
                    ],
                    [
                        "Run whatweb (http)",
                        "whatweb-http",
                        "whatweb [WEB_URL] > [OUTPUT].txt",
                        "http,https,ssl,soap,http-proxy,http-alt,https-alt",
                    ],
                    [
                        "Run whatweb (https)",
                        "whatweb-https",
                        "whatweb [WEB_URL] > [OUTPUT].txt",
                        "http,https,ssl,soap,http-proxy,http-alt,https-alt",
                    ],
                ],
            )
            _mock_app_settings_cls._ensure_nmap_hostname_target_support.side_effect = lambda command, _target: command
            _mock_app_settings_cls._canonicalize_web_target_placeholders.side_effect = lambda command: command
            _mock_app_settings_cls._collapse_redundant_fallbacks.side_effect = lambda command: command
            mock_settings_cls.return_value = settings

            commands_seen = []

            def fake_subprocess_run(command, *args, **kwargs):
                commands_seen.append(str(command))
                if "printf 'api.example.com" in str(command):
                    return SimpleNamespace(stdout="api.example.com\n", stderr="", returncode=0)
                if "httpx -silent -json" in str(command):
                    match = re.search(r"-o\s+('([^']+)'|\"([^\"]+)\"|(\S+))", str(command))
                    output_path = ""
                    if match:
                        output_path = next((group for group in match.groups()[1:] if group), "") or str(match.group(1) or "").strip("'\"")
                    if output_path:
                        with open(output_path, "w", encoding="utf-8") as handle:
                            handle.write(
                                '{"url":"https://api.example.com","host":"api.example.com","scheme":"https",'
                                '"port":"443","status-code":200,"title":"Portal","webserver":"nginx/1.25.3"}\n'
                            )
                    return SimpleNamespace(stdout="", stderr="", returncode=0)
                if "whatweb" in str(command):
                    return SimpleNamespace(
                        stdout="https://api.example.com [200 OK] HTTPServer[Apache/2.4.57 (Ubuntu)]\n",
                        stderr="",
                        returncode=0,
                    )
                return SimpleNamespace(stdout="", stderr="", returncode=0)

            mock_subprocess_run.side_effect = fake_subprocess_run

            logic = Logic(MagicMock(), MagicMock(), MagicMock())
            logic.activeProject = project

            with patch("app.scheduler.config.SchedulerConfigManager.load", return_value={
                "mode": "deterministic",
                "goal_profile": "external_pentest",
                "engagement_policy": {"preset": "external_recon"},
                "max_concurrency": 1,
                "runners": {
                    "container": {"enabled": False},
                    "browser": {"enabled": True, "use_xvfb": True, "delay": 5, "timeout": 180},
                },
            }):
                logic.run_scripted_actions()

            host_rows = project.repositoryContainer.hostRepository.getAllHostObjs()
            host_map = {
                str(getattr(item, "hostname", "") or getattr(item, "ip", "") or "").strip(): item
                for item in list(host_rows or [])
            }
            self.assertIn("api.example.com", host_map)

            api_host = host_map["api.example.com"]
            port_rows = project.repositoryContainer.portRepository.getPortsByHostId(int(getattr(api_host, "id", 0) or 0))
            port_map = {
                str(getattr(item, "portId", "") or "").strip(): item
                for item in list(port_rows or [])
            }
            self.assertIn("443", port_map)
            service_row = project.repositoryContainer.serviceRepository.getServiceById(getattr(port_map["443"], "serviceId", None))
            self.assertEqual("https", str(getattr(service_row, "name", "") or "").strip().lower())

            target_state = get_target_state(project.database, int(getattr(api_host, "id", 0) or 0)) or {}
            attempted_tool_ids = {
                str(item.get("tool_id", "") or "").strip().lower()
                for item in list(target_state.get("attempted_actions", []) or [])
            }
            self.assertIn("httpx", attempted_tool_ids)
            self.assertTrue({"whatweb", "whatweb-http", "whatweb-https"} & attempted_tool_ids)
            self.assertTrue(any("httpx -silent -json" in command for command in commands_seen))
            self.assertTrue(any("whatweb" in command for command in commands_seen))
        finally:
            project_manager.closeProject(project)

    @patch("app.scheduler.runners.shutil.which", return_value="/usr/bin/docker")
    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_can_use_container_runner_when_enabled(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run,
            _mock_which,
    ):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.scheduler.execution import list_execution_records
        from app.scheduler.policy import ensure_scheduler_engagement_policy_table, upsert_project_engagement_policy
        from app.shell.DefaultShell import DefaultShell
        from db.RepositoryFactory import RepositoryFactory
        from db.entities.host import hostObj
        from db.entities.port import portObj
        from db.entities.service import serviceObj

        repository_factory = RepositoryFactory(getDbLogger())
        project_manager = ProjectManager(DefaultShell(), repository_factory, getAppLogger())
        project = project_manager.createNewProject(projectType="legion", isTemp=True)

        try:
            ensure_scheduler_engagement_policy_table(project.database)
            upsert_project_engagement_policy(project.database, {
                "preset": "internal_recon",
                "scope": "internal",
                "intent": "recon",
                "allow_exploitation": False,
                "allow_lateral_movement": False,
                "credential_attack_mode": "blocked",
                "lockout_risk_mode": "blocked",
                "stability_risk_mode": "approval",
                "detection_risk_mode": "low",
                "approval_mode": "risky",
                "runner_preference": "container",
                "noise_budget": "low",
                "custom_overrides": {},
            })

            session = project.database.session()
            host = hostObj(ip="10.0.0.5", ipv4="10.0.0.5", hostname="")
            session.add(host)
            session.commit()
            host_id = int(host.id)

            service = serviceObj(name="smb", host=host_id)
            session.add(service)
            session.commit()

            port = portObj("445", "tcp", "open", host_id, service.id)
            session.add(port)
            session.commit()
            session.close()

            settings = SimpleNamespace(
                automatedAttacks=[["smb-enum-users.nse", "smb", "tcp"]],
                portActions=[[
                    "SMB Enum Users",
                    "smb-enum-users.nse",
                    "echo [IP]:[PORT] > [OUTPUT]",
                    "smb",
                ]],
            )
            _mock_app_settings_cls._ensure_nmap_hostname_target_support.side_effect = lambda command, _target: command
            _mock_app_settings_cls._canonicalize_web_target_placeholders.side_effect = lambda command: command
            _mock_app_settings_cls._collapse_redundant_fallbacks.side_effect = lambda command: command
            mock_settings_cls.return_value = settings
            mock_subprocess_run.return_value = SimpleNamespace(stdout="ok", stderr="", returncode=0)

            logic = Logic(MagicMock(), MagicMock(), MagicMock())
            logic.activeProject = project

            with patch("app.scheduler.config.SchedulerConfigManager.load", return_value={
                "mode": "deterministic",
                "goal_profile": "internal_asset_discovery",
                "engagement_policy": {"preset": "internal_recon"},
                "max_concurrency": 1,
                "runners": {
                    "container": {
                        "enabled": True,
                        "runtime": "docker",
                        "image": "kalilinux/kali-rolling",
                        "network_mode": "host",
                    },
                    "browser": {
                        "enabled": True,
                        "use_xvfb": True,
                        "delay": 5,
                        "timeout": 180,
                    },
                },
            }):
                logic.run_scripted_actions()

            self.assertTrue(mock_subprocess_run.called)
            command = mock_subprocess_run.call_args[0][0]
            self.assertIn("docker run --rm", command)
            self.assertIn("kalilinux/kali-rolling", command)

            records = list_execution_records(project.database, limit=10)
            self.assertEqual(1, len(records))
            self.assertEqual("container", records[0]["runner_type"])
        finally:
            project_manager.closeProject(project)


if __name__ == "__main__":
    unittest.main()
