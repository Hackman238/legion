import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


class LogicHeadlessActionsTest(unittest.TestCase):
    @patch("subprocess.run")
    @patch("app.settings.AppSettings")
    @patch("app.settings.Settings")
    def test_run_scripted_actions_uses_port_id_and_service_lookup(
            self,
            mock_settings_cls,
            _mock_app_settings_cls,
            mock_subprocess_run
    ):
        from app.logic import Logic

        host = SimpleNamespace(id=1, ip="10.0.0.5")
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
        self.assertIn("10.0.0.5:445", command)


if __name__ == "__main__":
    unittest.main()
