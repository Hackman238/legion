import hashlib
import re


def _normalize_template(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[IPV4]", text)
    text = re.sub(r"\b\d{1,5}\b", "[NUM]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_command_family_id(tool_id: str, protocol: str, command_template: str) -> str:
    normalized = "|".join([
        str(tool_id or "").strip().lower(),
        str(protocol or "").strip().lower(),
        _normalize_template(command_template),
    ])
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return digest[:16]
