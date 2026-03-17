import re
from typing import Any, Dict, Iterable, List, Optional, Set


VALID_RISK_TAGS = {
    "exploit_execution",
    "credential_bruteforce",
    "password_spray",
    "account_lockout_risk",
    "service_instability",
    "network_flooding",
    "destructive_write",
    "persistence_action",
    "lateral_movement",
    "high_detection_likelihood",
    "credential_capture_side_effect",
    "browser_state_change",
    "data_exfiltration_risk",
}

RISK_TAG_PATTERNS = {
    "exploit_execution": [
        r"\bmsfconsole\b",
        r"\bmetasploit\b",
        r"\bexploit\b",
        r"\bpsexec\b",
        r"\bwmiexec\b",
        r"\bsmbexec\b",
        r"\batexec\b",
        r"\bxp-cmdshell\b",
        r"--os-shell\b",
        r"\bcommix\b",
    ],
    "credential_bruteforce": [
        r"\bhydra\b",
        r"\bmedusa\b",
        r"\bncrack\b",
        r"\bpatator\b",
        r"\bbruteforce\b",
        r"\bdefault(?:[-_\s]credentials|[-_\s]login|[-_\s]passwords?)\b",
        r"\b(default|defaults)\b",
    ],
    "password_spray": [
        r"\bpasswordspray\b",
        r"\bpassword[-_\s]?spray\b",
        r"\bspray\b",
        r"\bkerbrute\b",
    ],
    "service_instability": [
        r"\bdos\b",
        r"\bdenial[-_\s]?of[-_\s]?service\b",
        r"\bcrash\b",
        r"\bfuzz(?:ing)?\b",
        r"\boverflow\b",
        r"\bslowloris\b",
    ],
    "network_flooding": [
        r"\bflood\b",
        r"--min-rate\b",
        r"--max-rate\b",
        r"\b-T5\b",
        r"\bslowloris\b",
        r"\bmasscan\b",
        r"\bhping3\b",
        r"\bnping\b.+--flood\b",
    ],
    "destructive_write": [
        r"\brm\s+-rf\b",
        r"\bdel\s+/f\b",
        r"\btruncate\b",
        r"\bmkfs\b",
        r"\bformat\s+[a-z]:\b",
        r"\bdrop\s+table\b",
    ],
    "persistence_action": [
        r"\bpersistence\b",
        r"\bschtasks?\b",
        r"\bcron\b",
        r"\bcrontab\b",
        r"\bsc\s+create\b",
        r"\bnew-service\b",
        r"\bstartup\b",
        r"\brun[-_\s]?key\b",
    ],
    "lateral_movement": [
        r"\bpsexec\b",
        r"\bwmiexec\b",
        r"\bsmbexec\b",
        r"\batexec\b",
        r"\bevil-winrm\b",
        r"\bwinrm\b",
        r"\bpivot\b",
        r"\blateral\b",
        r"\bpass-the-hash\b",
        r"\bpth\b",
        r"\bntlmrelayx\b",
    ],
    "high_detection_likelihood": [
        r"\bslowloris\b",
        r"\bmasscan\b",
        r"\bnikto\b",
        r"\bsqlmap\b",
        r"\bresponder\b",
        r"\bntlmrelayx\b",
        r"--threads?\s+(?:[4-9]\d|\d{3,})\b",
        r"\b-T5\b",
    ],
    "credential_capture_side_effect": [
        r"\bresponder\b",
        r"\bntlmrelayx\b",
        r"\bmitm6\b",
        r"\binveigh\b",
        r"\bllmnr\b",
        r"\bnbns\b",
        r"\bwpad\b",
        r"\bcapture\b",
    ],
    "browser_state_change": [
        r"\bplaywright\b",
        r"\bselenium\b",
        r"\bsubmit\b",
        r"\blogin\b",
        r"\bpost\b",
        r"\bfill\b",
        r"\bclick\b",
    ],
    "data_exfiltration_risk": [
        r"\bsecretsdump\b",
        r"\bsamdump\b",
        r"\bntds\b",
        r"\bmimikatz\b",
        r"\bprocdump\b.+\blsass\b",
        r"\bexfil\b",
        r"\bdump\b",
    ],
}

RISK_DESCRIPTIONS = {
    "exploit_execution": "Runs exploitation logic against the target service.",
    "credential_bruteforce": "Attempts repeated credential guesses against a live service.",
    "password_spray": "Tries shared passwords across multiple accounts and may trigger detections or lockouts.",
    "account_lockout_risk": "Could lock or throttle real user accounts.",
    "service_instability": "Could crash, hang, or degrade the target service.",
    "network_flooding": "Can generate unusually high request or packet volume.",
    "destructive_write": "May modify or delete target data.",
    "persistence_action": "Attempts to establish persistent access on the target.",
    "lateral_movement": "Attempts to pivot or execute on additional systems.",
    "high_detection_likelihood": "Likely to trigger monitoring or defensive tooling.",
    "credential_capture_side_effect": "May intercept or capture credentials from nearby systems or users.",
    "browser_state_change": "Could change remote application state through an automated browser session.",
    "data_exfiltration_risk": "May collect or export sensitive credential or data material.",
}

RISK_FAMILY_SAFE_ALTERNATIVES = (
    (
        {"credential_bruteforce", "password_spray", "account_lockout_risk"},
        "Prefer credential validation against known accounts or low-impact enumeration first.",
    ),
    (
        {"exploit_execution", "service_instability", "lateral_movement"},
        "Prefer enumeration, offline validation, or operator-reviewed proof steps before active exploitation.",
    ),
    (
        {"network_flooding", "high_detection_likelihood"},
        "Prefer narrower scope and rate-limited validation.",
    ),
    (
        {"credential_capture_side_effect"},
        "Prefer passive checks or operator-reviewed relay testing.",
    ),
    (
        {"destructive_write", "persistence_action", "data_exfiltration_risk"},
        "Prefer read-only validation and artifact collection.",
    ),
    (
        {"browser_state_change"},
        "Prefer read-only screenshoting or a manual browser session.",
    ),
)

LEGACY_CATEGORY_ALIASES = {
    "destructive_write_actions": "destructive_write",
}

LEGACY_CATEGORY_TO_RISK_TAGS = {
    "exploit_execution": {"exploit_execution"},
    "credential_bruteforce": {
        "credential_bruteforce",
        "password_spray",
        "account_lockout_risk",
    },
    "network_flooding": {"network_flooding"},
    "destructive_write_actions": {"destructive_write"},
}


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def normalize_risk_tags(values: Optional[Iterable[Any]]) -> List[str]:
    normalized = []
    seen: Set[str] = set()
    for item in list(values or []):
        tag = LEGACY_CATEGORY_ALIASES.get(_normalize_text(item), _normalize_text(item))
        if not tag or tag not in VALID_RISK_TAGS or tag in seen:
            continue
        seen.add(tag)
        normalized.append(tag)
    return normalized


def risk_tag_description(tag: str) -> str:
    return RISK_DESCRIPTIONS.get(_normalize_text(tag), "")


def summarize_risk_tags(tags: Optional[Iterable[Any]]) -> str:
    parts = [risk_tag_description(tag) for tag in normalize_risk_tags(tags)]
    return " ".join(part for part in parts if part)


def safer_alternative_for_risk_tags(tags: Optional[Iterable[Any]]) -> str:
    tag_set = set(normalize_risk_tags(tags))
    if not tag_set:
        return ""
    for family_tags, message in RISK_FAMILY_SAFE_ALTERNATIVES:
        if family_tags & tag_set:
            return message
    return "Prefer lower-impact validation before escalating to this action."


def risk_tags_to_legacy_categories(
        risk_tags: Optional[Iterable[Any]],
        enabled_categories: Optional[Iterable[Any]] = None,
) -> List[str]:
    normalized_tags = set(normalize_risk_tags(risk_tags))
    if enabled_categories is None:
        requested = list(LEGACY_CATEGORY_TO_RISK_TAGS.keys())
    else:
        requested = []
        for item in list(enabled_categories or []):
            category = _normalize_text(item)
            if category in LEGACY_CATEGORY_TO_RISK_TAGS and category not in requested:
                requested.append(category)

    categories = []
    for category in requested:
        if LEGACY_CATEGORY_TO_RISK_TAGS.get(category, set()) & normalized_tags:
            categories.append(category)
    return categories


def classify_risk_tags(
        command: str,
        *,
        tool_id: str = "",
        label: str = "",
        service_scope: Optional[Iterable[Any]] = None,
        runner_type: str = "",
) -> List[str]:
    service_text = " ".join(str(item or "") for item in list(service_scope or []))
    combined_text = " ".join([
        str(tool_id or ""),
        str(label or ""),
        str(command or ""),
        str(service_text or ""),
        str(runner_type or ""),
    ])
    tags = []
    for tag, patterns in RISK_TAG_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined_text, re.IGNORECASE):
                tags.append(tag)
                break

    normalized_tool = _normalize_text(tool_id)
    normalized_label = _normalize_text(label)
    text = combined_text.lower()

    if "browser" in _normalize_text(runner_type) and any(token in text for token in ("login", "submit", "fill", "click", "post")):
        tags.append("browser_state_change")
    if "screenshooter" in normalized_tool or "eyewitness" in text:
        tags = [tag for tag in tags if tag != "browser_state_change"]

    if {"credential_bruteforce", "password_spray"} & set(tags):
        tags.append("account_lockout_risk")
        tags.append("high_detection_likelihood")
    if "network_flooding" in tags:
        tags.append("high_detection_likelihood")
        tags.append("service_instability")
    if "exploit_execution" in tags:
        tags.append("service_instability")
    if "credential_capture_side_effect" in tags:
        tags.append("high_detection_likelihood")
    if "ntlmrelayx" in text:
        tags.append("lateral_movement")
    if any(token in normalized_tool for token in ("-default", "_default")) or " default " in f" {normalized_label} ":
        tags.append("credential_bruteforce")
        tags.append("account_lockout_risk")

    return normalize_risk_tags(tags)


def classify_command_danger(command: str, enabled_categories: List[str]) -> List[str]:
    risk_tags = classify_risk_tags(command)
    return risk_tags_to_legacy_categories(risk_tags, enabled_categories=enabled_categories)
