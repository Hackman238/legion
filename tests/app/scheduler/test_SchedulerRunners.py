import unittest
from types import SimpleNamespace
from unittest.mock import patch


class SchedulerRunnersTest(unittest.TestCase):
    def test_resolve_runner_selection_prefers_declared_browser_and_optional_container(self):
        from app.scheduler.runners import resolve_runner_selection

        browser = resolve_runner_selection("browser", runner_preference="container")
        local = resolve_runner_selection("local", runner_preference="container")
        manual = resolve_runner_selection("local", runner_preference="manual")
        disabled = resolve_runner_selection("local", runner_preference="container", allow_optional_runners=False)

        self.assertEqual("browser", browser.effective_runner_type)
        self.assertEqual("container", local.effective_runner_type)
        self.assertEqual("manual", manual.effective_runner_type)
        self.assertEqual("local", disabled.effective_runner_type)

    @patch("app.scheduler.runners.shutil.which", return_value="/usr/bin/docker")
    def test_container_runner_wraps_command_with_runtime_mounts_and_image(self, _mock_which):
        from app.scheduler.runners import ContainerRunner

        runner = ContainerRunner({
            "container": {
                "enabled": True,
                "runtime": "docker",
                "image": "kalilinux/kali-rolling",
                "network_mode": "host",
                "mount_workspace_paths": False,
            }
        })
        command, reason = runner.build_wrapped_command(
            "nmap -Pn -n 10.0.0.5 -oA /tmp/out",
            mount_paths=["/tmp", "/tmp"],
            workdir="/tmp",
        )

        self.assertEqual("", reason)
        self.assertIn("docker run --rm", command)
        self.assertIn("--network host", command)
        self.assertIn("-v /tmp:/tmp", command)
        self.assertIn("-w /tmp", command)
        self.assertIn("kalilinux/kali-rolling", command)
        self.assertIn("/bin/sh -lc", command)

    @patch("app.scheduler.runners.shutil.which", return_value=None)
    def test_execute_runner_request_returns_skip_when_container_backend_is_not_available(self, _mock_which):
        from app.scheduler.runners import RunnerExecutionRequest, execute_runner_request

        request = RunnerExecutionRequest(
            decision=SimpleNamespace(tool_id="smb-enum-users.nse"),
            tool_id="smb-enum-users.nse",
            command_template="nmap --script=smb-enum-users [IP] -p [PORT]",
            host_ip="10.0.0.5",
            port="445",
            protocol="tcp",
            timeout=300,
            declared_runner_type="local",
        )

        result = execute_runner_request(
            request,
            runner_preference="container",
            runner_settings={
                "container": {
                    "enabled": True,
                    "runtime": "docker",
                    "image": "kalilinux/kali-rolling",
                }
            },
            build_command=lambda _request: ("nmap --script=smb-enum-users 10.0.0.5 -p 445", "/tmp/out"),
            execute_local_command=lambda **_kwargs: None,
            execute_browser_action=lambda **_kwargs: None,
            mount_paths=["/tmp"],
            workdir="/tmp",
        )

        self.assertFalse(result.executed)
        self.assertEqual("container", result.runner_type)
        self.assertIn("container runtime 'docker' not available", result.reason)

    def test_execute_runner_request_disables_optional_runners_when_rollout_flag_is_off(self):
        from app.scheduler.runners import RunnerExecutionRequest, execute_runner_request

        request = RunnerExecutionRequest(
            decision=SimpleNamespace(tool_id="nuclei-web"),
            tool_id="nuclei-web",
            command_template="nuclei -u https://[IP]:[PORT] -silent",
            host_ip="198.51.100.25",
            port="443",
            protocol="tcp",
            timeout=300,
            declared_runner_type="local",
        )

        result = execute_runner_request(
            request,
            runner_preference="container",
            allow_optional_runners=False,
            runner_settings={
                "container": {
                    "enabled": True,
                    "runtime": "docker",
                    "image": "kalilinux/kali-rolling",
                }
            },
            build_command=lambda _request: ("nuclei -u https://198.51.100.25:443 -silent", "/tmp/out"),
            execute_local_command=lambda **kwargs: SimpleNamespace(
                executed=True,
                reason="completed",
                runner_type=kwargs["runner_type"],
                process_id=7,
                started_at="",
                finished_at="",
                stdout_ref="",
                stderr_ref="",
                artifact_refs=[],
                metadata={},
            ),
            execute_browser_action=lambda **_kwargs: None,
            mount_paths=["/tmp"],
            workdir="/tmp",
        )

        self.assertTrue(result.executed)
        self.assertEqual("local", result.runner_type)


if __name__ == "__main__":
    unittest.main()
