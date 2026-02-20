import re
from typing import List


DANGEROUS_PATTERNS = {
    "exploit_execution": [
        r"\bmsfconsole\b",
        r"\bexploit\b",
        r"\bpsexec\b",
        r"\bxp-cmdshell\b",
    ],
    "credential_bruteforce": [
        r"\bhydra\b",
        r"\bmedusa\b",
        r"\bbrute\b",
        r"\bpassword\b",
    ],
    "network_flooding": [
        r"\bflood\b",
        r"--min-rate",
        r"\b-T5\b",
        r"\bslowloris\b",
    ],
    "destructive_write_actions": [
        r"\brm\s+-rf\b",
        r"\bdel\s+/f\b",
        r"\btruncate\b",
        r"\bmkfs\b",
    ],
}


def classify_command_danger(command: str, enabled_categories: List[str]) -> List[str]:
    command_text = str(command or "")
    categories = []
    for category, patterns in DANGEROUS_PATTERNS.items():
        if category not in enabled_categories:
            continue
        for pattern in patterns:
            if re.search(pattern, command_text, re.IGNORECASE):
                categories.append(category)
                break
    return categories
