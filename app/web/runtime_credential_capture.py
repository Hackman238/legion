from __future__ import annotations

import os
import re
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from sqlalchemy import text

from app.timing import getTimestamp


def default_credential_capture_config() -> Dict[str, Any]:
    return {
        "responder": {
            "interface_name": "",
            "mode": "active",
            "wpad": True,
            "force_wpad_auth": True,
            "proxy_auth": False,
            "dhcp": False,
            "dhcp_dns": False,
            "basic_auth": False,
            "extra_args": "",
        },
        "ntlmrelayx": {
            "target": "",
            "targets_file": "",
            "smb2support": True,
            "interactive": False,
            "socks": False,
            "interface_ip": "",
            "output_hashes": True,
            "extra_args": "",
        },
    }


def normalize_credential_capture_config(value: Any) -> Dict[str, Any]:
    defaults = default_credential_capture_config()
    source = value if isinstance(value, dict) else {}
    normalized = {
        "responder": dict(defaults["responder"]),
        "ntlmrelayx": dict(defaults["ntlmrelayx"]),
    }
    responder = source.get("responder") if isinstance(source.get("responder"), dict) else {}
    relay = source.get("ntlmrelayx") if isinstance(source.get("ntlmrelayx"), dict) else {}
    normalized["responder"].update({
        "interface_name": str(responder.get("interface_name", defaults["responder"]["interface_name"]) or "").strip()[:120],
        "mode": "passive" if str(responder.get("mode", defaults["responder"]["mode"]) or "").strip().lower() == "passive" else "active",
        "wpad": bool(responder.get("wpad", defaults["responder"]["wpad"])),
        "force_wpad_auth": bool(responder.get("force_wpad_auth", defaults["responder"]["force_wpad_auth"])),
        "proxy_auth": bool(responder.get("proxy_auth", defaults["responder"]["proxy_auth"])),
        "dhcp": bool(responder.get("dhcp", defaults["responder"]["dhcp"])),
        "dhcp_dns": bool(responder.get("dhcp_dns", defaults["responder"]["dhcp_dns"])),
        "basic_auth": bool(responder.get("basic_auth", defaults["responder"]["basic_auth"])),
        "extra_args": str(responder.get("extra_args", defaults["responder"]["extra_args"]) or "").strip(),
    })
    normalized["ntlmrelayx"].update({
        "target": str(relay.get("target", defaults["ntlmrelayx"]["target"]) or "").strip()[:320],
        "targets_file": str(relay.get("targets_file", defaults["ntlmrelayx"]["targets_file"]) or "").strip()[:512],
        "smb2support": bool(relay.get("smb2support", defaults["ntlmrelayx"]["smb2support"])),
        "interactive": bool(relay.get("interactive", defaults["ntlmrelayx"]["interactive"])),
        "socks": bool(relay.get("socks", defaults["ntlmrelayx"]["socks"])),
        "interface_ip": str(relay.get("interface_ip", defaults["ntlmrelayx"]["interface_ip"]) or "").strip()[:120],
        "output_hashes": bool(relay.get("output_hashes", defaults["ntlmrelayx"]["output_hashes"])),
        "extra_args": str(relay.get("extra_args", defaults["ntlmrelayx"]["extra_args"]) or "").strip(),
    })
    return normalized


def dedupe_credential_hashes(captures: List[Dict[str, Any]]) -> List[str]:
    seen: Set[str] = set()
    hashes: List[str] = []
    for capture in list(captures or []):
        hash_value = str((capture or {}).get("hash", "") or "").strip()
        if not hash_value:
            continue
        key = hash_value.lower()
        if key in seen:
            continue
        seen.add(key)
        hashes.append(hash_value)
    return hashes


def extract_credential_data(line: Any) -> Tuple[str, str]:
    text_value = str(line or "").strip()
    if not text_value:
        return "", ""
    username = ""
    hash_value = ""
    match = re.search(r"from\s+([^:]+):\s*(.+)", text_value, re.IGNORECASE)
    if match:
        candidate = str(match.group(1) or "").split("/")[-1].split("\\")[-1]
        username = candidate.strip()
        hash_value = str(match.group(2) or "").strip()
        return username, hash_value
    if "::" in text_value:
        left, right = text_value.split("::", 1)
        username = left.split()[-1]
        hash_value = right.strip()
    return username, hash_value


def normalize_credential_capture_source(source: Any) -> str:
    token = str(source or "").strip()
    if not token:
        return ""
    try:
        if "://" in token:
            parsed = urlparse(token)
            token = str(parsed.hostname or "").strip() or token
    except Exception:
        pass
    token = token.strip().strip("[]")
    if "/" in token and not re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
        token = token.rsplit("/", 1)[-1].strip()
    return token


def split_credential_principal(value: Any) -> Tuple[str, str]:
    principal = str(value or "").strip()
    if not principal:
        return "", ""
    if "\\" in principal:
        realm, username = principal.split("\\", 1)
        return realm.strip()[:160], username.strip()[:160]
    if "/" in principal and not principal.startswith("/"):
        realm, username = principal.split("/", 1)
        return realm.strip()[:160], username.strip()[:160]
    if "@" in principal:
        username, realm = principal.split("@", 1)
        return realm.strip()[:160], username.strip()[:160]
    return "", principal[:160]


def extract_cleartext_password(details: Any) -> str:
    match = re.search(
        r"\bclear\s+text\s+password\s*:\s*(?P<password>.+)$",
        str(details or "").strip(),
        flags=re.IGNORECASE,
    )
    return str(match.group("password") or "").strip() if match else ""


def get_workspace_credential_captures(runtime, limit: Optional[int] = None) -> Dict[str, Any]:
    with runtime._lock:
        state = credential_capture_state_locked(runtime, include_captures=True)
    captures = list(state.get("captures", []) or [])
    if limit is not None:
        try:
            resolved_limit = max(1, int(limit or 0))
        except (TypeError, ValueError):
            resolved_limit = 0
        if resolved_limit > 0:
            captures = captures[:resolved_limit]
    deduped_hashes = dedupe_credential_hashes(captures)
    return {
        "captures": captures,
        "capture_count": int(state.get("capture_count", len(captures)) or 0),
        "unique_hash_count": len(deduped_hashes),
        "deduped_hashes": deduped_hashes,
        "panel_enabled": bool(state.get("panel_enabled", True)),
    }


def latest_credential_capture_session_locked(runtime, tool_name: str) -> Dict[str, Any]:
    project = runtime._require_active_project()
    runtime._ensure_process_tables()
    session = project.database.session()
    try:
        result = session.execute(text(
            "SELECT p.id, COALESCE(p.name, '') AS name, COALESCE(p.status, '') AS status, "
            "COALESCE(p.startTime, '') AS startTime, COALESCE(p.endTime, '') AS endTime, "
            "COALESCE(p.command, '') AS command, COALESCE(p.outputfile, '') AS outputfile, "
            "COALESCE(p.percent, '') AS percent, p.estimatedRemaining AS estimatedRemaining, "
            "COALESCE(p.elapsed, 0) AS elapsed, COALESCE(p.progressMessage, '') AS progressMessage, "
            "COALESCE(p.progressSource, '') AS progressSource, COALESCE(p.progressUpdatedAt, '') AS progressUpdatedAt, "
            "COALESCE(p.hostIp, '') AS hostIp, COALESCE(p.port, '') AS port, COALESCE(p.protocol, '') AS protocol "
            "FROM process AS p "
            "WHERE LOWER(COALESCE(p.name, '')) = LOWER(:tool_name) "
            "ORDER BY p.id DESC LIMIT 1"
        ), {"tool_name": str(tool_name or "")})
        row = result.fetchone()
        if row is None:
            return {}
        data = dict(zip(result.keys(), row))
    finally:
        session.close()
    status = str(data.get("status", "") or "")
    return {
        "process_id": int(data.get("id", 0) or 0),
        "tool": str(data.get("name", "") or tool_name or ""),
        "status": status,
        "running": str(status).strip().lower() in {"running", "waiting"},
        "start_time": str(data.get("startTime", "") or ""),
        "end_time": str(data.get("endTime", "") or ""),
        "command": runtime._redact_command_secrets(data.get("command", "")),
        "outputfile": str(data.get("outputfile", "") or ""),
        "progress": runtime._build_process_progress_payload(
            status=status,
            percent=data.get("percent", ""),
            estimated_remaining=data.get("estimatedRemaining"),
            elapsed=data.get("elapsed", 0),
            progress_message=data.get("progressMessage", ""),
            progress_source=data.get("progressSource", ""),
            progress_updated_at=data.get("progressUpdatedAt", ""),
        ),
    }


def credential_capture_state_locked(runtime, *, include_captures: bool = False) -> Dict[str, Any]:
    project = getattr(runtime.logic, "activeProject", None)
    captures: List[Dict[str, Any]] = []
    config = normalize_credential_capture_config(
        runtime._get_workspace_setting_locked("credential_capture_config", default_credential_capture_config())
    ) if project else default_credential_capture_config()
    if project is not None:
        repo = getattr(getattr(project, "repositoryContainer", None), "credentialRepository", None)
        if repo is not None:
            try:
                captures = list(repo.getAllCaptures() or [])
            except Exception:
                captures = []
    deduped_hashes = dedupe_credential_hashes(captures)
    recent_captures = captures[:8]
    panel_enabled = bool(runtime._scheduler_preferences().get("feature_flags", {}).get("credential_capture_panel", True))
    responder_session = latest_credential_capture_session_locked(runtime, "responder") if project else {}
    relay_session = latest_credential_capture_session_locked(runtime, "ntlmrelayx") if project else {}
    state = {
        "panel_enabled": panel_enabled,
        "capture_count": len(captures),
        "unique_hash_count": len(deduped_hashes),
        "recent_captures": recent_captures,
        "responder": {
            "config": dict(config.get("responder", {})),
            "session": responder_session,
        },
        "ntlmrelayx": {
            "config": dict(config.get("ntlmrelayx", {})),
            "session": relay_session,
        },
    }
    if include_captures:
        state["captures"] = captures
        state["deduped_hashes"] = deduped_hashes
    return state


def save_credential_capture_config(runtime, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with runtime._lock:
        current = normalize_credential_capture_config(
            runtime._get_workspace_setting_locked("credential_capture_config", default_credential_capture_config())
        )
        incoming = updates if isinstance(updates, dict) else {}
        merged = {
            "responder": dict(current.get("responder", {})),
            "ntlmrelayx": dict(current.get("ntlmrelayx", {})),
        }
        if isinstance(incoming.get("responder"), dict):
            merged["responder"].update(incoming.get("responder", {}))
        if isinstance(incoming.get("ntlmrelayx"), dict):
            merged["ntlmrelayx"].update(incoming.get("ntlmrelayx", {}))
        normalized = normalize_credential_capture_config(merged)
        runtime._set_workspace_setting_locked("credential_capture_config", normalized)
        state = credential_capture_state_locked(runtime, include_captures=False)
    runtime._emit_ui_invalidation("overview", "credential_capture", throttle_seconds=0.1)
    return state


def start_credential_capture_session_job(runtime, tool_id: str) -> Dict[str, Any]:
    normalized_tool = str(tool_id or "").strip().lower()
    if normalized_tool not in {"responder", "ntlmrelayx"}:
        raise ValueError("Unsupported credential capture tool.")
    with runtime._lock:
        session_state = latest_credential_capture_session_locked(runtime, normalized_tool)
        if bool(session_state.get("running")):
            raise ValueError(f"{normalized_tool} is already running.")
        config = normalize_credential_capture_config(
            runtime._get_workspace_setting_locked("credential_capture_config", default_credential_capture_config())
        )
        payload = {
            "tool": normalized_tool,
            "config": dict(config.get(normalized_tool, {})),
        }
    return runtime._start_job(
        "credential-capture-session",
        lambda job_id: run_credential_capture_session(runtime, tool_id=normalized_tool, job_id=int(job_id or 0)),
        payload=payload,
    )


def stop_credential_capture_session(runtime, tool_id: str) -> Dict[str, Any]:
    normalized_tool = str(tool_id or "").strip().lower()
    if normalized_tool not in {"responder", "ntlmrelayx"}:
        raise ValueError("Unsupported credential capture tool.")
    with runtime._lock:
        session_state = latest_credential_capture_session_locked(runtime, normalized_tool)
        process_id = int(session_state.get("process_id", 0) or 0)
    if process_id <= 0 or not bool(session_state.get("running")):
        return {"stopped": False, "tool": normalized_tool, "reason": "not running"}
    result = runtime.kill_process(int(process_id))
    runtime._emit_ui_invalidation("processes", "overview", "credential_capture", throttle_seconds=0.1)
    return {
        "stopped": True,
        "tool": normalized_tool,
        "process_id": int(process_id),
        **result,
    }


def get_credential_capture_log_payload(runtime, tool_id: str) -> Dict[str, Any]:
    normalized_tool = str(tool_id or "").strip().lower()
    if normalized_tool not in {"responder", "ntlmrelayx"}:
        raise ValueError("Unsupported credential capture tool.")
    with runtime._lock:
        session_state = latest_credential_capture_session_locked(runtime, normalized_tool)
    process_id = int(session_state.get("process_id", 0) or 0)
    if process_id <= 0:
        raise KeyError(f"No {normalized_tool} session found.")
    output = runtime.get_process_output(process_id, offset=0, max_chars=50000)
    full_text = str(output.get("output", "") or "")
    chunk = str(output.get("output_chunk", "") or "")
    if full_text:
        text_value = full_text
    else:
        text_value = chunk
        next_offset = int(output.get("next_offset", len(chunk)) or len(chunk))
        output_length = int(output.get("output_length", len(chunk)) or len(chunk))
        while next_offset < output_length:
            next_payload = runtime.get_process_output(process_id, offset=next_offset, max_chars=50000)
            next_chunk = str(next_payload.get("output_chunk", "") or "")
            if not next_chunk:
                break
            text_value += next_chunk
            next_offset = int(next_payload.get("next_offset", next_offset + len(next_chunk)) or (next_offset + len(next_chunk)))
    return {
        "tool": normalized_tool,
        "process_id": process_id,
        "status": str(output.get("status", "") or session_state.get("status", "")),
        "text": text_value,
    }


def run_credential_capture_session(runtime, *, tool_id: str, job_id: int = 0) -> Dict[str, Any]:
    with runtime._lock:
        state = credential_capture_state_locked(runtime, include_captures=False)
        config = dict((state.get(tool_id, {}) or {}).get("config", {}))
        command, outputfile = build_credential_capture_command(runtime, tool_id, config)
        target_label = credential_capture_target_label(tool_id, config)
    result = runtime._run_command_with_tracking(
        tool_name=str(tool_id),
        tab_title=f"{tool_id} ({target_label})" if target_label else str(tool_id),
        host_ip=str(target_label or ""),
        port="",
        protocol="",
        command=command,
        outputfile=outputfile,
        timeout=0,
        job_id=int(job_id or 0),
        return_metadata=True,
    )
    executed, reason, process_id, metadata = result
    runtime._emit_ui_invalidation("processes", "overview", "credential_capture", throttle_seconds=0.1)
    return {
        "executed": bool(executed),
        "reason": str(reason or ""),
        "process_id": int(process_id or 0),
        "tool": str(tool_id),
        "started_at": str((metadata or {}).get("started_at", "") or ""),
        "finished_at": str((metadata or {}).get("finished_at", "") or ""),
    }


def build_credential_capture_command(runtime, tool_id: str, config: Dict[str, Any]) -> Tuple[str, str]:
    normalized_tool = str(tool_id or "").strip().lower()
    running_dir = str(getattr(runtime._require_active_project().properties, "runningFolder", "") or "")
    timestamp = getTimestamp(True).replace(":", "").replace("-", "").replace("T", "").replace("Z", "")
    if normalized_tool == "responder":
        inventory = runtime.get_capture_interface_inventory()
        configured_interface = str(config.get("interface_name", "") or "").strip()
        default_interface = str(inventory.get("default_interface", "") or "").strip()
        interface_name = configured_interface or default_interface
        if not interface_name:
            raise ValueError("Responder requires a capture interface.")
        outputfile = os.path.join(running_dir, f"{timestamp}-responder.log")
        tool_path = shlex.quote(str(getattr(runtime._get_settings(), "tools_path_responder", "responder") or "responder"))
        command_parts = [tool_path, "-I", shlex.quote(interface_name)]
        if str(config.get("mode", "active") or "").strip().lower() == "passive":
            command_parts.append("-A")
        if bool(config.get("wpad")):
            command_parts.append("-w")
        if bool(config.get("force_wpad_auth")):
            command_parts.append("-F")
        if bool(config.get("proxy_auth")):
            command_parts.append("-P")
        if bool(config.get("dhcp")):
            command_parts.append("-d")
        if bool(config.get("dhcp_dns")):
            command_parts.append("-D")
        if bool(config.get("basic_auth")):
            command_parts.append("-b")
        extra_args = str(config.get("extra_args", "") or "").strip()
        if extra_args:
            command_parts.append(extra_args)
        return " ".join(command_parts), outputfile

    if normalized_tool == "ntlmrelayx":
        target = str(config.get("target", "") or "").strip()
        targets_file = str(config.get("targets_file", "") or "").strip()
        if not target and not targets_file:
            raise ValueError("ntlmrelayx requires a relay target or targets file.")
        output_base = os.path.join(running_dir, f"{timestamp}-ntlmrelayx")
        outputfile = f"{output_base}.log"
        tool_path = shlex.quote(str(getattr(runtime._get_settings(), "tools_path_ntlmrelay", "impacket-ntlmrelayx") or "impacket-ntlmrelayx"))
        command_parts = [tool_path]
        if target:
            command_parts.extend(["-t", shlex.quote(target)])
        if targets_file:
            command_parts.extend(["-tf", shlex.quote(targets_file)])
        if bool(config.get("smb2support", True)):
            command_parts.append("-smb2support")
        if bool(config.get("interactive")):
            command_parts.append("-i")
        if bool(config.get("socks")):
            command_parts.append("-socks")
        interface_ip = str(config.get("interface_ip", "") or "").strip()
        if interface_ip:
            command_parts.extend(["-ip", shlex.quote(interface_ip)])
        if bool(config.get("output_hashes", True)):
            command_parts.extend(["-of", shlex.quote(f"{output_base}.hashes")])
        extra_args = str(config.get("extra_args", "") or "").strip()
        if extra_args:
            command_parts.append(extra_args)
        return " ".join(command_parts), outputfile
    raise ValueError("Unsupported credential capture tool.")


def credential_capture_target_label(tool_id: str, config: Dict[str, Any]) -> str:
    normalized_tool = str(tool_id or "").strip().lower()
    if normalized_tool == "responder":
        return str(config.get("interface_name", "") or "").strip()
    if normalized_tool == "ntlmrelayx":
        return str(config.get("target", "") or config.get("targets_file", "") or "").strip()
    return ""
