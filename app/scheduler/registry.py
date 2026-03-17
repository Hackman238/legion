from typing import Any, Dict, List, Optional

from app.scheduler.family import build_command_family_id
from app.scheduler.models import ActionSpec, WEB_SERVICE_IDS
from app.scheduler.risk import classify_command_danger


def _normalize_list(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    result = []
    seen = set()
    for item in list(values or []):
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _merge_lists(*groups: Any) -> List[str]:
    merged = []
    seen = set()
    for group in groups:
        for item in _normalize_list(group):
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
    return merged


def _extract_parameter_schema(command_template: str) -> Dict[str, Any]:
    from app.scheduler.models import _extract_parameter_schema as _shared_extract_parameter_schema

    return _shared_extract_parameter_schema(command_template)


def _infer_runner_type(tool_id: str, service_scope: List[str], command_template: str) -> str:
    tool_text = " ".join([
        str(tool_id or ""),
        str(command_template or ""),
        " ".join(str(item or "") for item in list(service_scope or [])),
    ]).lower()
    if str(tool_id or "").strip().lower() in {"screenshooter", "x11screen"}:
        return "browser"
    if any(token in tool_text for token in ["manual", "operator", "clipboard"]):
        return "manual"
    return "local"


def _infer_artifact_types(tool_id: str, command_template: str) -> List[str]:
    tool_norm = str(tool_id or "").strip().lower()
    command_text = str(command_template or "").lower()
    artifact_types = []
    if tool_norm in {"screenshooter", "x11screen"}:
        artifact_types.append("screenshot")
    if "-oa" in command_text or "nmap" in command_text:
        artifact_types.append("nmap")
    if "[output]" in command_text or ".txt" in command_text:
        artifact_types.append("text")
    return artifact_types


def _infer_impact_level(risk_tags: List[str]) -> str:
    tag_set = {str(item or "").strip().lower() for item in list(risk_tags or [])}
    if {"exploit_execution", "destructive_write_actions"} & tag_set:
        return "high"
    if {"credential_bruteforce", "network_flooding"} & tag_set:
        return "medium"
    return "low"


def _infer_noise_level(tool_id: str, command_template: str, risk_tags: List[str]) -> str:
    tag_set = {str(item or "").strip().lower() for item in list(risk_tags or [])}
    tool_text = " ".join([str(tool_id or ""), str(command_template or "")]).lower()
    if "network_flooding" in tag_set:
        return "high"
    if "credential_bruteforce" in tag_set:
        return "medium"
    if any(token in tool_text for token in ["gobuster", "feroxbuster", "nikto", "nuclei", "whatweb", "sslscan", "sslyze"]):
        return "medium"
    return "low"


def _infer_default_timeout(tool_id: str, command_template: str) -> int:
    tool_text = " ".join([str(tool_id or ""), str(command_template or "")]).lower()
    if str(tool_id or "").strip().lower() in {"screenshooter", "x11screen"}:
        return 180
    if any(token in tool_text for token in ["nmap", "nuclei", "gobuster", "feroxbuster", "nikto", "sslyze", "sslscan"]):
        return 600
    return 300


def _infer_methodology_tags(tool_id: str, service_scope: List[str], risk_tags: List[str]) -> List[str]:
    tool_text = str(tool_id or "").strip().lower()
    service_set = {str(item or "").strip().lower() for item in list(service_scope or [])}
    tags = []
    if service_set & WEB_SERVICE_IDS or any(token in tool_text for token in ["http", "ssl", "tls", "web", "nikto", "whatweb", "nuclei"]):
        tags.append("web")
    if any(token in tool_text for token in ["enum", "discover", "info", "banner"]):
        tags.append("enumeration")
    if any(token in tool_text for token in ["vuln", "cve", "nuclei", "nikto"]):
        tags.append("validation")
    if "credential_bruteforce" in {str(item).lower() for item in list(risk_tags or [])}:
        tags.append("credential_access")
    return tags


def _infer_pack_tags(service_scope: List[str]) -> List[str]:
    service_set = {str(item or "").strip().lower() for item in list(service_scope or [])}
    tags = []
    if service_set & WEB_SERVICE_IDS:
        tags.append("web_app_api")
        tags.append("external_surface")
    if service_set & {"smb", "ldap", "kerberos", "msrpc", "rdp", "ms-wbt-server"}:
        tags.append("internal_network")
    if service_set & {"ssl", "https", "https-alt"}:
        tags.append("tls_and_exposure")
    return tags


class ActionRegistry:
    def __init__(self, specs: List[ActionSpec]):
        self._specs = list(specs or [])
        self._by_action_id = {spec.action_id: spec for spec in self._specs}
        self._by_tool_id = {spec.tool_id: spec for spec in self._specs}

    @classmethod
    def from_settings(cls, settings, dangerous_categories: Optional[List[str]] = None) -> "ActionRegistry":
        dangerous = list(dangerous_categories or [])
        port_actions = {}
        for row in list(getattr(settings, "portActions", []) or []):
            tool_id = str(row[1])
            port_actions[tool_id] = {
                "label": str(row[0]),
                "command_template": str(row[2]),
                "service_scope": _normalize_list(str(row[3] if len(row) > 3 else "")),
            }

        scheduler_actions = {}
        for row in list(getattr(settings, "automatedAttacks", []) or []):
            tool_id = str(row[0])
            scheduler_actions[tool_id] = {
                "service_scope": _normalize_list(str(row[1] if len(row) > 1 else "")),
                "protocol_scope": _normalize_list(str(row[2] if len(row) > 2 else "tcp")) or ["tcp"],
            }

        ordered_tool_ids = []
        for tool_id in list(scheduler_actions.keys()) + list(port_actions.keys()):
            if tool_id not in ordered_tool_ids:
                ordered_tool_ids.append(tool_id)

        specs = []
        for tool_id in ordered_tool_ids:
            port_row = port_actions.get(tool_id, {})
            scheduler_row = scheduler_actions.get(tool_id, {})
            command_template = str(port_row.get("command_template", "") or "")
            service_scope = _merge_lists(
                port_row.get("service_scope", []),
                scheduler_row.get("service_scope", []),
            )
            protocol_scope = _merge_lists(scheduler_row.get("protocol_scope", [])) or ["tcp"]
            risk_tags = classify_command_danger(command_template, dangerous)
            requires_web_context = bool({str(item).lower() for item in service_scope} & WEB_SERVICE_IDS)
            action = ActionSpec(
                action_id=str(tool_id),
                tool_id=str(tool_id),
                label=str(port_row.get("label", "") or tool_id),
                description=str(port_row.get("label", "") or tool_id),
                command_template=command_template,
                parameter_schema=_extract_parameter_schema(command_template),
                service_scope=service_scope,
                protocol_scope=protocol_scope,
                runner_type=_infer_runner_type(tool_id, service_scope, command_template),
                artifact_types=_infer_artifact_types(tool_id, command_template),
                risk_tags=risk_tags,
                impact_level=_infer_impact_level(risk_tags),
                noise_level=_infer_noise_level(tool_id, command_template, risk_tags),
                default_timeout=_infer_default_timeout(tool_id, command_template),
                family_id=build_command_family_id(tool_id, ",".join(protocol_scope), command_template or tool_id),
                requires_credentials=bool("credential_bruteforce" in {str(item).lower() for item in risk_tags}),
                requires_web_context=requires_web_context,
                supports_deterministic=tool_id in scheduler_actions,
                supports_ai_selection=tool_id in port_actions or tool_id in scheduler_actions,
                methodology_tags=_infer_methodology_tags(tool_id, service_scope, risk_tags),
                pack_tags=_infer_pack_tags(service_scope),
            )
            specs.append(action)
        return cls(specs)

    def all(self) -> List[ActionSpec]:
        return list(self._specs)

    def get(self, action_id: str) -> Optional[ActionSpec]:
        return self._by_action_id.get(str(action_id or ""))

    def get_by_tool_id(self, tool_id: str) -> Optional[ActionSpec]:
        return self._by_tool_id.get(str(tool_id or ""))

    def for_deterministic(self, service: str, protocol: str) -> List[ActionSpec]:
        return [
            spec for spec in self._specs
            if spec.supports_deterministic and self._matches_scope(spec, service=service, protocol=protocol)
        ]

    def for_ai_selection(self, service: str, protocol: str) -> List[ActionSpec]:
        return [
            spec for spec in self._specs
            if spec.supports_ai_selection and self._matches_scope(spec, service=service, protocol=protocol)
        ]

    @staticmethod
    def _matches_scope(spec: ActionSpec, *, service: str, protocol: str) -> bool:
        service_name = str(service or "").strip().rstrip("?")
        protocol_name = str(protocol or "tcp").strip().lower()
        service_scope = {str(item or "").strip() for item in list(spec.service_scope or []) if str(item or "").strip()}
        protocol_scope = {str(item or "").strip().lower() for item in list(spec.protocol_scope or []) if str(item or "").strip()}
        service_match = not service_scope or service_name in service_scope or "*" in service_scope
        protocol_match = not protocol_scope or protocol_name in protocol_scope or "*" in protocol_scope
        return bool(service_match and protocol_match)
