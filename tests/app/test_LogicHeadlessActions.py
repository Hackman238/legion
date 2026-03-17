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
