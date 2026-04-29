from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence


DEFAULT_PIPETTES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "pipettes"))
_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_PARAMETER_FLAG_RE = re.compile(r"^--[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_DEFAULT_PARAMETER_VALUE_RE = r"^[A-Za-z0-9._:@/-]{1,256}$"


def _normalize_list(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    rows: List[str] = []
    seen = set()
    for value in list(values or []):
        token = str(value or "").strip()
        key = token.lower()
        if not token or key in seen:
            continue
        seen.add(key)
        rows.append(token)
    return rows


def _safe_int(value: Any, default: int = 300, minimum: int = 1, maximum: int = 3600) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(int(minimum), min(int(parsed), int(maximum)))


def _normalize_parameters(values: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for value in list(values or []):
        if not isinstance(value, dict):
            continue
        name = str(value.get("name", "") or "").strip()
        flag = str(value.get("flag", "") or "").strip()
        if not _PARAMETER_NAME_RE.match(name) or not _PARAMETER_FLAG_RE.match(flag):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        pattern = str(value.get("value_pattern", "") or "").strip() or _DEFAULT_PARAMETER_VALUE_RE
        try:
            re.compile(pattern)
        except re.error:
            pattern = _DEFAULT_PARAMETER_VALUE_RE
        rows.append({
            "name": name,
            "label": str(value.get("label", name) or name).strip() or name,
            "description": str(value.get("description", "") or "").strip(),
            "placeholder": str(value.get("placeholder", "") or "").strip(),
            "flag": flag,
            "required": bool(value.get("required", False)),
            "value_pattern": pattern,
        })
    return rows


def _candidate_pipette_roots(extra_roots: Optional[Sequence[Any]] = None) -> List[str]:
    candidates = [DEFAULT_PIPETTES_DIR]
    env_value = str(os.environ.get("LEGION_PIPETTES_PATH", "") or "").strip()
    if env_value:
        candidates.extend(part for part in env_value.split(os.pathsep) if str(part or "").strip())
    candidates.extend(str(item or "") for item in list(extra_roots or []) if str(item or "").strip())

    roots: List[str] = []
    seen = set()
    for candidate in candidates:
        root = os.path.abspath(os.path.expanduser(str(candidate or "").strip()))
        if not root or root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        roots.append(root)
    return roots


@dataclass(frozen=True)
class PipetteSpec:
    pipette_id: str
    label: str
    description: str
    entrypoint: str
    service_scope: List[str] = field(default_factory=list)
    protocol_scope: List[str] = field(default_factory=lambda: ["tcp"])
    target_ports: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    optional_tools: List[str] = field(default_factory=list)
    risk_tags: List[str] = field(default_factory=list)
    impact_level: str = "low"
    noise_level: str = "low"
    mode: str = "check"
    default_timeout: int = 300
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    source_dir: str = ""

    @property
    def tool_id(self) -> str:
        return self.pipette_id

    @property
    def command_template(self) -> str:
        return (
            f"bash {shlex.quote(self.entrypoint)} "
            "--target '[IP]' --port '[PORT]' --output '[OUTPUT].txt'"
        )

    def validate_parameter_values(self, values: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        source = values if isinstance(values, dict) else {}
        resolved: Dict[str, str] = {}
        for parameter in self.parameters:
            name = str(parameter.get("name", "") or "").strip()
            if not name:
                continue
            raw_value = str(source.get(name, "") or "").strip()
            if not raw_value:
                if bool(parameter.get("required", False)):
                    raise ValueError(f"{name} is required for {self.tool_id}.")
                continue
            pattern = str(parameter.get("value_pattern", "") or "") or _DEFAULT_PARAMETER_VALUE_RE
            if not re.fullmatch(pattern, raw_value):
                raise ValueError(f"{name} has an invalid value.")
            resolved[name] = raw_value
        return resolved

    def command_template_for_values(self, values: Optional[Dict[str, Any]] = None) -> str:
        command = self.command_template
        resolved = self.validate_parameter_values(values)
        for parameter in self.parameters:
            name = str(parameter.get("name", "") or "").strip()
            if name not in resolved:
                continue
            command = f"{command} {str(parameter.get('flag'))} {shlex.quote(resolved[name])}"
        return command

    def as_port_action(self) -> List[str]:
        return [
            self.label,
            self.tool_id,
            self.command_template,
            ",".join(self.service_scope),
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipette_id": self.pipette_id,
            "tool_id": self.tool_id,
            "label": self.label,
            "description": self.description,
            "entrypoint": self.entrypoint,
            "service_scope": list(self.service_scope),
            "protocol_scope": list(self.protocol_scope),
            "target_ports": list(self.target_ports),
            "required_tools": list(self.required_tools),
            "optional_tools": list(self.optional_tools),
            "risk_tags": list(self.risk_tags),
            "impact_level": self.impact_level,
            "noise_level": self.noise_level,
            "mode": self.mode,
            "default_timeout": int(self.default_timeout),
            "parameters": [dict(item) for item in self.parameters],
            "source_dir": self.source_dir,
        }


def _load_pipette_manifest(manifest_path: str) -> Optional[PipetteSpec]:
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception:
        return None
    if not isinstance(manifest, dict):
        return None

    pipette_id = str(manifest.get("id", "") or "").strip()
    label = str(manifest.get("label", "") or "").strip()
    entrypoint_name = str(manifest.get("entrypoint", "") or "").strip()
    if not pipette_id or not label or not entrypoint_name:
        return None
    entrypoint_parts = entrypoint_name.replace("\\", "/").split("/")
    if os.path.isabs(entrypoint_name) or ".." in entrypoint_parts:
        return None

    source_dir = os.path.abspath(os.path.dirname(manifest_path))
    entrypoint = os.path.abspath(os.path.join(source_dir, entrypoint_name))
    if os.path.commonpath([source_dir, entrypoint]) != source_dir:
        return None
    if not os.path.isfile(entrypoint):
        return None

    return PipetteSpec(
        pipette_id=pipette_id,
        label=label,
        description=str(manifest.get("description", "") or "").strip(),
        entrypoint=entrypoint,
        service_scope=_normalize_list(manifest.get("service_scope", [])),
        protocol_scope=_normalize_list(manifest.get("protocol_scope", ["tcp"])) or ["tcp"],
        target_ports=_normalize_list(manifest.get("target_ports", [])),
        required_tools=_normalize_list(manifest.get("required_tools", [])),
        optional_tools=_normalize_list(manifest.get("optional_tools", [])),
        risk_tags=_normalize_list(manifest.get("risk_tags", [])),
        impact_level=str(manifest.get("impact_level", "low") or "low").strip().lower() or "low",
        noise_level=str(manifest.get("noise_level", "low") or "low").strip().lower() or "low",
        mode=str(manifest.get("mode", "check") or "check").strip().lower() or "check",
        default_timeout=_safe_int(manifest.get("default_timeout", 300), default=300, minimum=1, maximum=7200),
        parameters=_normalize_parameters(manifest.get("parameters", [])),
        source_dir=source_dir,
    )


def list_pipettes(extra_roots: Optional[Sequence[Any]] = None) -> List[PipetteSpec]:
    specs: List[PipetteSpec] = []
    seen = set()
    for root in _candidate_pipette_roots(extra_roots):
        for dirpath, _dirnames, filenames in os.walk(root):
            if "manifest.json" not in filenames:
                continue
            spec = _load_pipette_manifest(os.path.join(dirpath, "manifest.json"))
            if spec is None or spec.tool_id in seen:
                continue
            seen.add(spec.tool_id)
            specs.append(spec)
    return sorted(specs, key=lambda item: item.label.lower())


def find_pipette(tool_id: str, extra_roots: Optional[Sequence[Any]] = None) -> Optional[PipetteSpec]:
    normalized = str(tool_id or "").strip().lower()
    if not normalized:
        return None
    for spec in list_pipettes(extra_roots):
        if spec.tool_id.lower() == normalized:
            return spec
    return None


def is_pipette_tool_id(tool_id: str) -> bool:
    return find_pipette(tool_id) is not None


def pipette_port_actions(extra_roots: Optional[Sequence[Any]] = None) -> List[List[str]]:
    return [spec.as_port_action() for spec in list_pipettes(extra_roots)]
