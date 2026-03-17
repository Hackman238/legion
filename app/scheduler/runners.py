import os
import shlex
import shutil
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


VALID_RUNNER_TYPES = {"local", "container", "browser", "manual", "auto"}

DEFAULT_RUNNER_SETTINGS = {
    "container": {
        "enabled": False,
        "runtime": "docker",
        "image": "",
        "network_mode": "host",
        "extra_args": "",
        "workdir": "",
        "mount_workspace_paths": True,
    },
    "browser": {
        "enabled": True,
        "use_xvfb": True,
        "delay": 5,
        "timeout": 180,
    },
}


def _normalize_runner_type(value: Any, default: str = "local") -> str:
    token = str(value or "").strip().lower()
    if token not in VALID_RUNNER_TYPES:
        return str(default or "local")
    return token


def normalize_runner_settings(raw: Any) -> Dict[str, Any]:
    source = raw if isinstance(raw, dict) else {}
    config = {
        "container": dict(DEFAULT_RUNNER_SETTINGS["container"]),
        "browser": dict(DEFAULT_RUNNER_SETTINGS["browser"]),
    }

    for section in ("container", "browser"):
        incoming = source.get(section, {})
        if isinstance(incoming, dict):
            config[section].update(incoming)

    container = config["container"]
    container["enabled"] = bool(container.get("enabled", False))
    container["runtime"] = str(container.get("runtime", "docker") or "docker").strip() or "docker"
    container["image"] = str(container.get("image", "") or "").strip()
    container["network_mode"] = str(container.get("network_mode", "host") or "host").strip() or "host"
    container["extra_args"] = str(container.get("extra_args", "") or "").strip()
    container["workdir"] = str(container.get("workdir", "") or "").strip()
    container["mount_workspace_paths"] = bool(container.get("mount_workspace_paths", True))

    browser = config["browser"]
    browser["enabled"] = bool(browser.get("enabled", True))
    browser["use_xvfb"] = bool(browser.get("use_xvfb", True))
    try:
        browser["delay"] = max(0, min(int(browser.get("delay", 5)), 30))
    except (TypeError, ValueError):
        browser["delay"] = 5
    try:
        browser["timeout"] = max(15, min(int(browser.get("timeout", 180)), 900))
    except (TypeError, ValueError):
        browser["timeout"] = 180

    return config


@dataclass(frozen=True)
class RunnerExecutionRequest:
    decision: Any
    tool_id: str
    command_template: str
    host_ip: str = ""
    hostname: str = ""
    port: str = ""
    protocol: str = "tcp"
    service_name: str = ""
    timeout: int = 300
    job_id: int = 0
    approval_id: int = 0
    declared_runner_type: str = "local"


@dataclass(frozen=True)
class RunnerSelection:
    declared_runner_type: str
    requested_runner_preference: str
    effective_runner_type: str
    reason: str = ""


@dataclass
class RunnerExecutionResult:
    executed: bool
    reason: str
    runner_type: str
    process_id: int = 0
    started_at: str = ""
    finished_at: str = ""
    stdout_ref: str = ""
    stderr_ref: str = ""
    artifact_refs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def resolve_runner_selection(
        action_runner_type: Any,
        *,
        runner_preference: Any = "",
        runner_settings: Any = None,
) -> RunnerSelection:
    _ = normalize_runner_settings(runner_settings)
    declared = _normalize_runner_type(action_runner_type, "local")
    preferred = _normalize_runner_type(runner_preference, "auto" if str(runner_preference or "").strip().lower() == "auto" else "local")

    if declared in {"browser", "manual"}:
        return RunnerSelection(
            declared_runner_type=declared,
            requested_runner_preference=preferred,
            effective_runner_type=declared,
        )

    if preferred == "container":
        return RunnerSelection(
            declared_runner_type=declared,
            requested_runner_preference=preferred,
            effective_runner_type="container",
            reason="project policy prefers container execution",
        )

    if preferred == "manual":
        return RunnerSelection(
            declared_runner_type=declared,
            requested_runner_preference=preferred,
            effective_runner_type="manual",
            reason="project policy requires manual execution",
        )

    return RunnerSelection(
        declared_runner_type=declared,
        requested_runner_preference=preferred,
        effective_runner_type=declared if declared in {"local", "browser", "manual"} else "local",
    )


def _mountable_paths(paths: Sequence[Any]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for item in list(paths or []):
        path = os.path.abspath(str(item or "").strip())
        if not path or path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        normalized.append(path)
    return normalized


class LocalRunner:
    runner_type = "local"

    def execute(
            self,
            request: RunnerExecutionRequest,
            *,
            build_command: Callable[[RunnerExecutionRequest], Tuple[str, str]],
            execute_command: Callable[..., RunnerExecutionResult],
    ) -> RunnerExecutionResult:
        command, outputfile = build_command(request)
        if not str(command or "").strip():
            return RunnerExecutionResult(
                executed=False,
                reason="skipped: no matching command template",
                runner_type=self.runner_type,
            )
        return execute_command(
            request=request,
            rendered_command=str(command),
            outputfile=str(outputfile or ""),
            runner_type=self.runner_type,
        )


class ContainerRunner:
    runner_type = "container"

    def __init__(self, settings: Any):
        self.settings = normalize_runner_settings(settings)

    def build_wrapped_command(
            self,
            rendered_command: str,
            *,
            mount_paths: Optional[Sequence[Any]] = None,
            workdir: str = "",
    ) -> Tuple[str, str]:
        container = self.settings["container"]
        if not bool(container.get("enabled", False)):
            return "", "skipped: container runner disabled"

        runtime = str(container.get("runtime", "docker") or "docker").strip() or "docker"
        if shutil.which(runtime) is None:
            return "", f"skipped: container runtime '{runtime}' not available"

        image = str(container.get("image", "") or "").strip()
        if not image:
            return "", "skipped: container image not configured"

        resolved_workdir = str(container.get("workdir", "") or workdir or "").strip()
        mounts = list(_mountable_paths(mount_paths or []))
        if bool(container.get("mount_workspace_paths", True)):
            cwd = os.getcwd()
            if cwd:
                mounts = list(_mountable_paths(list(mounts) + [cwd]))
        if resolved_workdir and os.path.exists(resolved_workdir):
            mounts = list(_mountable_paths(list(mounts) + [resolved_workdir]))

        command_parts = [runtime, "run", "--rm"]
        network_mode = str(container.get("network_mode", "host") or "").strip()
        if network_mode:
            command_parts.extend(["--network", network_mode])
        for path in mounts:
            command_parts.extend(["-v", f"{path}:{path}"])
        if resolved_workdir:
            command_parts.extend(["-w", resolved_workdir])
        extra_args = str(container.get("extra_args", "") or "").strip()
        if extra_args:
            try:
                command_parts.extend(shlex.split(extra_args))
            except ValueError:
                return "", "skipped: invalid container extra_args"
        command_parts.append(image)
        command_parts.extend(["/bin/sh", "-lc", str(rendered_command or "")])
        return shlex.join(command_parts), ""

    def execute(
            self,
            request: RunnerExecutionRequest,
            *,
            build_command: Callable[[RunnerExecutionRequest], Tuple[str, str]],
            execute_command: Callable[..., RunnerExecutionResult],
            mount_paths: Optional[Sequence[Any]] = None,
            workdir: str = "",
    ) -> RunnerExecutionResult:
        command, outputfile = build_command(request)
        if not str(command or "").strip():
            return RunnerExecutionResult(
                executed=False,
                reason="skipped: no matching command template",
                runner_type=self.runner_type,
            )

        wrapped_command, skip_reason = self.build_wrapped_command(
            str(command),
            mount_paths=mount_paths,
            workdir=workdir,
        )
        if skip_reason:
            return RunnerExecutionResult(
                executed=False,
                reason=skip_reason,
                runner_type=self.runner_type,
            )

        return execute_command(
            request=request,
            rendered_command=str(wrapped_command),
            outputfile=str(outputfile or ""),
            runner_type=self.runner_type,
        )


class BrowserRunner:
    runner_type = "browser"

    def __init__(self, settings: Any):
        self.settings = normalize_runner_settings(settings)

    def execute(
            self,
            request: RunnerExecutionRequest,
            *,
            execute_browser: Callable[..., RunnerExecutionResult],
    ) -> RunnerExecutionResult:
        browser_settings = dict(self.settings.get("browser", {}))
        if not bool(browser_settings.get("enabled", True)):
            return RunnerExecutionResult(
                executed=False,
                reason="skipped: browser runner disabled",
                runner_type=self.runner_type,
            )
        return execute_browser(
            request=request,
            browser_settings=browser_settings,
            runner_type=self.runner_type,
        )


class ManualRunner:
    runner_type = "manual"

    def execute(self, request: RunnerExecutionRequest) -> RunnerExecutionResult:
        _ = request
        return RunnerExecutionResult(
            executed=False,
            reason="skipped: manual runner requires operator execution",
            runner_type=self.runner_type,
        )


def execute_runner_request(
        request: RunnerExecutionRequest,
        *,
        runner_preference: Any = "",
        runner_settings: Any = None,
        build_command: Callable[[RunnerExecutionRequest], Tuple[str, str]],
        execute_local_command: Callable[..., RunnerExecutionResult],
        execute_browser_action: Callable[..., RunnerExecutionResult],
        mount_paths: Optional[Sequence[Any]] = None,
        workdir: str = "",
) -> RunnerExecutionResult:
    selection = resolve_runner_selection(
        request.declared_runner_type,
        runner_preference=runner_preference,
        runner_settings=runner_settings,
    )
    settings = normalize_runner_settings(runner_settings)

    if selection.effective_runner_type == "browser":
        result = BrowserRunner(settings).execute(
            request,
            execute_browser=execute_browser_action,
        )
    elif selection.effective_runner_type == "container":
        result = ContainerRunner(settings).execute(
            request,
            build_command=build_command,
            execute_command=execute_local_command,
            mount_paths=mount_paths,
            workdir=workdir,
        )
    elif selection.effective_runner_type == "manual":
        result = ManualRunner().execute(request)
    else:
        result = LocalRunner().execute(
            request,
            build_command=build_command,
            execute_command=execute_local_command,
        )

    result.metadata.setdefault("declared_runner_type", selection.declared_runner_type)
    result.metadata.setdefault("requested_runner_preference", selection.requested_runner_preference)
    if selection.reason:
        result.metadata.setdefault("runner_selection_reason", selection.reason)
    return result
