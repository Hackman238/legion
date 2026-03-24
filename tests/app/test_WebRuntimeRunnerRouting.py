import collections
import collections.abc
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

for legacy_name in ("Mapping", "MutableMapping", "Sequence", "Callable"):
    if not hasattr(collections, legacy_name):
        setattr(collections, legacy_name, getattr(collections.abc, legacy_name))


class WebRuntimeRunnerRoutingTest(unittest.TestCase):
    @patch("app.scheduler.runners.shutil.which", return_value="/usr/bin/docker")
    def test_execute_scheduler_decision_wraps_local_command_for_container_runner(self, _mock_which):
        from app.scheduler.models import PlanStep
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(
                runningFolder="/tmp/legion-test-running",
                outputFolder="/tmp/legion-test-output",
            )
        )
        runtime._hostname_for_ip = lambda _ip: "dc01.local"
        runtime._build_command = MagicMock(return_value=("echo 10.0.0.5:445 > /tmp/legion-test-running/out", "/tmp/legion-test-running/out"))
        runtime._run_command_with_tracking = MagicMock(return_value=(
            True,
            "completed",
            21,
            {
                "started_at": "2026-03-17T00:00:00Z",
                "finished_at": "2026-03-17T00:00:02Z",
                "stdout_ref": "process_output:21",
                "stderr_ref": "",
                "artifact_refs": ["/tmp/legion-test-running/out"],
            },
        ))

        decision = PlanStep.from_legacy_fields(
            tool_id="smb-enum-users.nse",
            label="SMB Enum Users",
            command_template="echo [IP]:[PORT] > [OUTPUT]",
            protocol="tcp",
            score=100.0,
            rationale="Enumerate SMB users.",
            mode="deterministic",
            goal_profile="internal_asset_discovery",
            family_id="smb-enum-users",
            target_ref={"host_ip": "10.0.0.5", "port": "445", "protocol": "tcp", "service": "smb"},
        )

        result = WebRuntime._execute_scheduler_decision(
            runtime,
            decision,
            host_ip="10.0.0.5",
            port="445",
            protocol="tcp",
            service_name="smb",
            command_template="echo [IP]:[PORT] > [OUTPUT]",
            timeout=300,
            capture_metadata=True,
            runner_preference="container",
            runner_settings={
                "container": {
                    "enabled": True,
                    "runtime": "docker",
                    "image": "kalilinux/kali-rolling",
                    "network_mode": "host",
                    "mount_workspace_paths": False,
                }
            },
        )

        rendered_command = runtime._run_command_with_tracking.call_args.kwargs["command"]
        self.assertIn("docker run --rm", rendered_command)
        self.assertIn("kalilinux/kali-rolling", rendered_command)
        self.assertEqual("container", result["execution_record"].runner_type)
        self.assertEqual("completed", result["reason"])

    @patch("app.web.runtime.update_scheduler_decision_for_approval")
    @patch("app.web.runtime.update_pending_approval")
    @patch("app.web.runtime.get_pending_approval")
    @patch("app.web.runtime.ensure_scheduler_approval_table")
    def test_approve_scheduler_approval_keeps_manual_runner_as_operator_step(
            self,
            _mock_ensure,
            mock_get_pending,
            mock_update_pending,
            mock_update_decision,
    ):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._lock = threading.RLock()
        database = object()
        runtime.settings = SimpleNamespace(
            automatedAttacks=[],
            portActions=[
                ["Prepare Responder capture workflow", "responder", "responder -I <interface> -w -F", "smb,ldap,kerberos"],
            ],
        )
        runtime._require_active_project = lambda: SimpleNamespace(database=database)
        runtime._apply_family_policy_action = lambda *args, **kwargs: ""
        runtime._emit_ui_invalidation = lambda *args, **kwargs: None
        runtime._start_job = MagicMock()

        mock_get_pending.return_value = {
            "id": 77,
            "status": "pending",
            "tool_id": "responder",
            "command_template": "responder -I <interface> -w -F",
            "family_policy_state": "",
        }

        def _update_side_effect(_database, _approval_id, **kwargs):
            return {
                "id": 77,
                "status": kwargs.get("status", "approved"),
                "decision_reason": kwargs.get("decision_reason", ""),
                "family_policy_state": kwargs.get("family_policy_state", ""),
            }

        mock_update_pending.side_effect = _update_side_effect

        result = WebRuntime.approve_scheduler_approval(runtime, 77)

        self.assertIsNone(result["job"])
        self.assertEqual("approved", result["approval"]["status"])
        self.assertEqual("approved for operator execution", result["approval"]["decision_reason"])
        runtime._start_job.assert_not_called()
        mock_update_decision.assert_called_with(
            database,
            77,
            approved=True,
            executed=False,
            reason="approved for operator execution",
        )


if __name__ == "__main__":
    unittest.main()
