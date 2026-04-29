import re
from typing import Any, Dict, Iterable, List, Optional, Set


DEFAULT_DEVICE_CATEGORY_RULES: List[Dict[str, Any]] = [
    {
        "name": "Windows",
        "ports": [135, 139, 445, 3389, 5985, 5986],
        "fingerprint_fragments": [
            "windows",
            "microsoft windows rpc",
            "microsoft-ds",
            "iis",
            "winrm",
            "rdp",
            "smb",
            "ntlm",
        ],
        "cpe": [
            "cpe:/o:microsoft:windows",
            "cpe:2.3:o:microsoft:windows",
        ],
    },
    {
        "name": "Linux",
        "ports": [22, 111, 2049, 6000, 6001],
        "fingerprint_fragments": [
            "linux",
            "openssh",
            "x11",
            "x.org",
            "rpcbind",
            "nfs",
            "unix",
            "ubuntu",
            "debian",
            "centos",
            "red hat",
        ],
        "cpe": [
            "cpe:/o:linux:linux_kernel",
            "cpe:2.3:o:linux:linux_kernel",
            "ubuntu",
            "debian",
            "centos",
            "redhat",
        ],
    },
    {
        "name": "Network",
        "ports": [23, 161, 162, 4786, 8291],
        "fingerprint_fragments": [
            "cisco",
            "routeros",
            "mikrotik",
            "junos",
            "aruba",
            "ubiquiti",
            "ubnt",
            "fortinet",
            "palo alto",
            "sonicwall",
            "switch",
            "router",
            "firewall",
            "load balancer",
        ],
        "cpe": [
            "cisco",
            "juniper",
            "aruba",
            "fortinet",
            "ubiquiti",
            "mikrotik",
            "paloalto",
        ],
    },
    {
        "name": "Phone",
        "ports": [1720, 2000, 2427, 2727, 4569, 5060, 5061],
        "fingerprint_fragments": [
            "sip",
            "sip-tls",
            "sips",
            "rtp",
            "rtcp",
            "srtp",
            "voip",
            "ip phone",
            "ip-phone",
            "asterisk",
            "freepbx",
            "3cx",
            "cisco ip phone",
            "cucm",
            "skinny",
            "sccp",
            "h.323",
            "h323",
            "mgcp",
            "iax2",
            "polycom",
            "yealink",
            "grandstream",
            "avaya",
        ],
        "cpe": [
            "asterisk",
            "freepbx",
            "3cx",
            "cisco:unified_communications",
            "cisco:ip_phone",
            "polycom",
            "yealink",
            "grandstream",
            "avaya",
        ],
        "min_score": 1,
        "suppresses": ["Server"],
    },
    {
        "name": "Storage",
        "ports": [111, 139, 445, 2049, 3260, 548],
        "fingerprint_fragments": [
            "nfs",
            "iscsi",
            "netapp",
            "synology",
            "qnap",
            "nas",
            "storage",
            "samba",
            "file server",
            "minio",
            "gluster",
            "ceph",
        ],
        "cpe": [
            "netapp",
            "synology",
            "qnap",
            "minio",
            "ceph",
            "gluster",
        ],
    },
    {
        "name": "Database",
        "ports": [1433, 1521, 3306, 33060, 5432, 5433, 27017, 5984, 6379, 9200],
        "fingerprint_fragments": [
            "mysql",
            "mariadb",
            "postgres",
            "postgresql",
            "ms-sql",
            "sql server",
            "oracle",
            "mongodb",
            "redis",
            "elasticsearch",
            "couchdb",
            "cosmos db",
            "aurora",
            "rds",
            "cloud sql",
        ],
        "cpe": [
            "mysql",
            "mariadb",
            "postgresql",
            "microsoft:sql_server",
            "oracle:database",
            "mongodb",
            "redis",
            "elasticsearch",
            "couchdb",
            "azure:cosmos_db",
            "amazon:aurora",
            "amazon:rds",
            "google:cloud_sql",
        ],
    },
    {
        "name": "Printer",
        "ports": [515, 631, 9100],
        "fingerprint_fragments": [
            "printer",
            "ipp",
            "jetdirect",
            "cups",
            "laserjet",
            "officejet",
            "mfp",
            "multifunction",
        ],
        "cpe": [
            "hp",
            "brother",
            "canon",
            "epson",
            "xerox",
            "ricoh",
            "lexmark",
        ],
    },
    {
        "name": "Server",
        "ports": [22, 80, 88, 111, 135, 139, 443, 445, 3389, 8080, 8443],
        "fingerprint_fragments": [
            "apache",
            "nginx",
            "iis",
            "tomcat",
            "jetty",
            "jboss",
            "weblogic",
            "websphere",
            "ad domain controller",
            "active directory",
            "terminal services",
        ],
        "cpe": [
            "apache:http_server",
            "nginx:nginx",
            "microsoft:iis",
            "tomcat",
            "jetty",
            "jboss",
        ],
    },
]


_UNKNOWN_TOKENS = {"", "unknown", "n/a", "na", "none", "null", "nil"}


def _clean_text(value: Any, *, lower: bool = False, limit: int = 160) -> str:
    text = str(value or "").strip()
    if lower:
        text = text.lower()
    if len(text) > int(limit):
        text = text[: int(limit)].strip()
    return text


def slugify_device_category(value: Any) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", _clean_text(value, lower=True, limit=120))
    return token.strip("-")


def built_in_device_category_rules() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in list(DEFAULT_DEVICE_CATEGORY_RULES):
        row = normalize_device_category_rule(item, built_in=True)
        if row:
            rows.append(row)
    return rows


def normalize_device_category_rule(item: Any, *, built_in: bool = False) -> Optional[Dict[str, Any]]:
    if not isinstance(item, dict):
        return None
    name = _clean_text(item.get("name", ""), limit=80)
    if not name:
        return None
    ports: List[int] = []
    seen_ports: Set[int] = set()
    for raw_port in list(item.get("ports", []) or []):
        try:
            port = int(str(raw_port).strip())
        except (TypeError, ValueError):
            continue
        if port <= 0 or port > 65535 or port in seen_ports:
            continue
        seen_ports.add(port)
        ports.append(port)
    fingerprint_fragments: List[str] = []
    seen_fragments: Set[str] = set()
    for raw_fragment in list(item.get("fingerprint_fragments", []) or []):
        fragment = _clean_text(raw_fragment, lower=True, limit=120)
        if not fragment or fragment in seen_fragments:
            continue
        seen_fragments.add(fragment)
        fingerprint_fragments.append(fragment)
    cpe_fragments: List[str] = []
    seen_cpes: Set[str] = set()
    for raw_cpe in list(item.get("cpe", []) or []):
        fragment = _clean_text(raw_cpe, lower=True, limit=180)
        if not fragment or fragment in seen_cpes:
            continue
        seen_cpes.add(fragment)
        cpe_fragments.append(fragment)
    suppresses: List[str] = []
    seen_suppresses: Set[str] = set()
    for raw_suppressed in list(item.get("suppresses", []) or []):
        suppressed = slugify_device_category(raw_suppressed)
        if not suppressed or suppressed in seen_suppresses:
            continue
        seen_suppresses.add(suppressed)
        suppresses.append(suppressed)
    min_score = 2
    try:
        min_score = int(item.get("min_score", 2) or 2)
    except (TypeError, ValueError):
        min_score = 2
    min_score = max(1, min(min_score, 8))
    return {
        "id": slugify_device_category(name) or f"category-{abs(hash(name)) % 100000}",
        "name": name,
        "ports": ports,
        "fingerprint_fragments": fingerprint_fragments,
        "cpe": cpe_fragments,
        "min_score": min_score,
        "suppresses": suppresses,
        "built_in": bool(built_in or item.get("built_in", False)),
    }


def normalize_custom_device_category_rules(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for item in list(raw):
        row = normalize_device_category_rule(item, built_in=False)
        if not row:
            continue
        key = str(row.get("id", "") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows[:64]


def combined_device_category_rules(custom_rules: Any = None) -> List[Dict[str, Any]]:
    rows = built_in_device_category_rules()
    existing = {str(item.get("id", "") or "") for item in rows}
    for item in normalize_custom_device_category_rules(custom_rules):
        key = str(item.get("id", "") or "")
        if key in existing:
            continue
        existing.add(key)
        rows.append(item)
    return rows


def device_category_options(custom_rules: Any = None) -> List[Dict[str, Any]]:
    return [
        {
            "id": str(item.get("id", "") or ""),
            "name": str(item.get("name", "") or ""),
            "built_in": bool(item.get("built_in", False)),
        }
        for item in combined_device_category_rules(custom_rules)
    ]


def normalize_manual_device_categories(raw: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for item in list(raw or []):
        if isinstance(item, dict):
            name = _clean_text(item.get("name", ""), limit=80)
            confidence = item.get("confidence", 100.0)
        else:
            name = _clean_text(item, limit=80)
            confidence = 100.0
        if not name:
            continue
        key = slugify_device_category(name)
        if not key or key in seen:
            continue
        seen.add(key)
        try:
            numeric_confidence = float(confidence or 100.0)
        except (TypeError, ValueError):
            numeric_confidence = 100.0
        rows.append({
            "id": key,
            "name": name,
            "confidence": max(1.0, min(numeric_confidence, 100.0)),
            "source_kind": "user_entered",
            "origin": "manual",
            "reasons": ["manual classification"],
        })
    return rows[:32]


def _iter_text_tokens(context: Dict[str, Any]) -> Iterable[str]:
    for key in ("hostname", "os_match"):
        yield _clean_text(context.get(key, ""), lower=True, limit=220)
    for item in list(context.get("service_inventory", []) or []):
        if not isinstance(item, dict):
            continue
        for key in ("service", "service_product", "service_version", "service_extrainfo", "state"):
            yield _clean_text(item.get(key, ""), lower=True, limit=220)
    for item in list(context.get("technologies", []) or []):
        if not isinstance(item, dict):
            continue
        for key in ("name", "version", "evidence"):
            yield _clean_text(item.get(key, ""), lower=True, limit=220)
    for item in list(context.get("findings", []) or []):
        if not isinstance(item, dict):
            continue
        for key in ("title", "evidence"):
            yield _clean_text(item.get(key, ""), lower=True, limit=220)


def _collect_context(context: Dict[str, Any]) -> Dict[str, Any]:
    ports: Set[int] = set()
    cpes: List[str] = []
    tokens: List[str] = []
    for item in list(context.get("service_inventory", []) or []):
        if not isinstance(item, dict):
            continue
        try:
            port_value = int(str(item.get("port", "")).strip())
        except (TypeError, ValueError):
            port_value = 0
        if port_value > 0:
            ports.add(port_value)
    for item in list(context.get("technologies", []) or []):
        if not isinstance(item, dict):
            continue
        cpe = _clean_text(item.get("cpe", ""), lower=True, limit=220)
        if cpe:
            cpes.append(cpe)
    tokens = [token for token in _iter_text_tokens(context) if token and token not in _UNKNOWN_TOKENS]
    return {
        "ports": ports,
        "cpes": cpes,
        "tokens": tokens,
    }


def classify_device_categories(context: Optional[Dict[str, Any]], custom_rules: Any = None) -> List[Dict[str, Any]]:
    payload = context if isinstance(context, dict) else {}
    signals = _collect_context(payload)
    rows: List[Dict[str, Any]] = []
    for rule in combined_device_category_rules(custom_rules):
        score = 0
        reasons: List[str] = []
        matched_ports: List[int] = []
        for port in list(rule.get("ports", []) or []):
            if int(port or 0) in signals["ports"]:
                matched_ports.append(int(port))
        if matched_ports:
            score += min(len(matched_ports), 4)
            reasons.extend([f"port {port}" for port in matched_ports[:4]])

        matched_fingerprints: List[str] = []
        for fragment in list(rule.get("fingerprint_fragments", []) or []):
            normalized_fragment = _clean_text(fragment, lower=True, limit=120)
            if not normalized_fragment:
                continue
            if any(normalized_fragment in token for token in signals["tokens"]):
                matched_fingerprints.append(normalized_fragment)
        if matched_fingerprints:
            score += min(len(matched_fingerprints) * 2, 6)
            reasons.extend([f"fingerprint '{item}'" for item in matched_fingerprints[:3]])

        matched_cpes: List[str] = []
        for fragment in list(rule.get("cpe", []) or []):
            normalized_fragment = _clean_text(fragment, lower=True, limit=180)
            if not normalized_fragment:
                continue
            if any(normalized_fragment in cpe for cpe in signals["cpes"]):
                matched_cpes.append(normalized_fragment)
        if matched_cpes:
            score += min(len(matched_cpes) * 3, 6)
            reasons.extend([f"cpe '{item}'" for item in matched_cpes[:2]])

        strong_match = bool(matched_fingerprints or matched_cpes)
        min_score = int(rule.get("min_score", 2) or 2)
        if not strong_match and score < min_score:
            continue
        confidence = min(98.0, 48.0 + float(score * 10))
        rows.append({
            "id": str(rule.get("id", "") or ""),
            "name": str(rule.get("name", "") or ""),
            "confidence": confidence,
            "source_kind": "observed",
            "origin": "auto",
            "score": score,
            "reasons": reasons[:8],
            "matched_ports": matched_ports[:8],
            "matched_fingerprint_fragments": matched_fingerprints[:6],
            "matched_cpe_fragments": matched_cpes[:4],
            "suppresses": list(rule.get("suppresses", []) or []),
            "built_in": bool(rule.get("built_in", False)),
        })
    suppressed_categories: Set[str] = set()
    for item in rows:
        suppressed_categories.update(
            slugify_device_category(value)
            for value in list(item.get("suppresses", []) or [])
            if slugify_device_category(value)
        )
    if suppressed_categories:
        rows = [
            item for item in rows
            if slugify_device_category(item.get("name", "") or item.get("id", "")) not in suppressed_categories
        ]
    rows.sort(key=lambda item: (-float(item.get("confidence", 0.0) or 0.0), str(item.get("name", "")).lower()))
    return rows[:16]


def merge_effective_device_categories(
    auto_categories: Any,
    manual_categories: Any,
    *,
    override_auto: bool = False,
) -> List[Dict[str, Any]]:
    auto_rows = list(auto_categories or []) if isinstance(auto_categories, list) else []
    manual_rows = normalize_manual_device_categories(manual_categories)
    if override_auto:
        return manual_rows
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for source in (manual_rows, auto_rows):
        for item in list(source or []):
            if not isinstance(item, dict):
                continue
            key = slugify_device_category(item.get("name", "") or item.get("id", ""))
            if not key or key in seen:
                continue
            seen.add(key)
            row = dict(item)
            row["id"] = key
            rows.append(row)
    return rows[:16]


def category_names(items: Any) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()
    for item in list(items or []):
        name = _clean_text(item.get("name", "") if isinstance(item, dict) else item, limit=80)
        if not name:
            continue
        key = slugify_device_category(name)
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
    return names
