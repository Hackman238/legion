import datetime
import hashlib
import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from sqlalchemy import text

from app.url_normalization import normalize_discovered_url


GRAPH_SOURCE_KINDS = {"observed", "inferred", "ai_suggested", "user_entered"}
_SOURCE_PRIORITY = {
    "ai_suggested": 1,
    "inferred": 2,
    "user_entered": 3,
    "observed": 4,
}
_UNKNOWN_TOKENS = {"", "unknown", "n/a", "na", "none", "null", "nil"}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _graph_artifact_filename(item: Dict[str, Any]) -> str:
    if not isinstance(item, dict):
        return ""
    props = item.get("properties", {}) if isinstance(item.get("properties", {}), dict) else {}
    tokens = [
        props.get("filename", ""),
        props.get("ref", ""),
        props.get("artifact_ref", ""),
        item.get("label", ""),
    ]
    for token in tokens:
        text = str(token or "").strip().replace("\\", "/")
        if not text:
            continue
        return text.rsplit("/", 1)[-1]
    return ""


def _graph_should_hide_artifact_node(item: Dict[str, Any], *, hide_nmap_xml_artifacts: bool = False) -> bool:
    if str(item.get("type", "") or "").strip().lower() != "artifact":
        return False
    props = item.get("properties", {}) if isinstance(item.get("properties", {}), dict) else {}
    filename = _graph_artifact_filename(item).lower()
    ref = str(props.get("ref", "") or props.get("artifact_ref", "") or "").strip().lower()
    label = str(item.get("label", "") or "").strip().lower()
    tool_id = str(props.get("tool_id", "") or "").strip().lower()
    source_ref = str(item.get("source_ref", "") or "").strip().lower()

    if filename.endswith(".gnmap") or filename.endswith(".nmap"):
        return True

    if not hide_nmap_xml_artifacts or not filename.endswith(".xml"):
        return False

    signals = [filename, ref, label, tool_id, source_ref]
    return any("nmap" in token for token in signals if token)


def _ensure_column(session, table_name: str, column_name: str, column_type: str):
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if str(column_name) in existing:
        return
    session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _stable_id(prefix: str, payload: Dict[str, Any]) -> str:
    rendered = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    return f"{str(prefix or '').strip().lower()}-{digest[:16]}"


def _ensure_tables(session):
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS graph_node ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "node_id TEXT UNIQUE,"
        "node_key TEXT UNIQUE,"
        "type TEXT,"
        "label TEXT,"
        "confidence REAL,"
        "source_kind TEXT,"
        "source_ref TEXT,"
        "first_seen TEXT,"
        "last_seen TEXT,"
        "properties_json TEXT"
        ")"
    ))
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS graph_edge ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "edge_id TEXT UNIQUE,"
        "edge_key TEXT UNIQUE,"
        "type TEXT,"
        "from_node_id TEXT,"
        "to_node_id TEXT,"
        "confidence REAL,"
        "source_kind TEXT,"
        "source_ref TEXT,"
        "first_seen TEXT,"
        "last_seen TEXT,"
        "properties_json TEXT"
        ")"
    ))
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS graph_evidence_ref ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "owner_kind TEXT,"
        "owner_id TEXT,"
        "evidence_ref TEXT,"
        "created_at TEXT"
        ")"
    ))
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS graph_layout_state ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "layout_id TEXT UNIQUE,"
        "view_id TEXT,"
        "name TEXT,"
        "layout_json TEXT,"
        "updated_at TEXT"
        ")"
    ))
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS graph_annotation ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "annotation_id TEXT UNIQUE,"
        "target_kind TEXT,"
        "target_ref TEXT,"
        "body TEXT,"
        "created_by TEXT,"
        "created_at TEXT,"
        "updated_at TEXT,"
        "source_ref TEXT"
        ")"
    ))
    for column_name, column_type in (
            ("node_id", "TEXT"),
            ("node_key", "TEXT"),
            ("type", "TEXT"),
            ("label", "TEXT"),
            ("confidence", "REAL"),
            ("source_kind", "TEXT"),
            ("source_ref", "TEXT"),
            ("first_seen", "TEXT"),
            ("last_seen", "TEXT"),
            ("properties_json", "TEXT"),
    ):
        _ensure_column(session, "graph_node", column_name, column_type)
    for column_name, column_type in (
            ("edge_id", "TEXT"),
            ("edge_key", "TEXT"),
            ("type", "TEXT"),
            ("from_node_id", "TEXT"),
            ("to_node_id", "TEXT"),
            ("confidence", "REAL"),
            ("source_kind", "TEXT"),
            ("source_ref", "TEXT"),
            ("first_seen", "TEXT"),
            ("last_seen", "TEXT"),
            ("properties_json", "TEXT"),
    ):
        _ensure_column(session, "graph_edge", column_name, column_type)
    for column_name, column_type in (
            ("owner_kind", "TEXT"),
            ("owner_id", "TEXT"),
            ("evidence_ref", "TEXT"),
            ("created_at", "TEXT"),
    ):
        _ensure_column(session, "graph_evidence_ref", column_name, column_type)
    for column_name, column_type in (
            ("layout_id", "TEXT"),
            ("view_id", "TEXT"),
            ("name", "TEXT"),
            ("layout_json", "TEXT"),
            ("updated_at", "TEXT"),
    ):
        _ensure_column(session, "graph_layout_state", column_name, column_type)
    for column_name, column_type in (
            ("annotation_id", "TEXT"),
            ("target_kind", "TEXT"),
            ("target_ref", "TEXT"),
            ("body", "TEXT"),
            ("created_by", "TEXT"),
            ("created_at", "TEXT"),
            ("updated_at", "TEXT"),
            ("source_ref", "TEXT"),
    ):
        _ensure_column(session, "graph_annotation", column_name, column_type)


def _from_json(value: Any, fallback: Any):
    raw = str(value or "").strip()
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def _to_json(value: Any, fallback: Any) -> str:
    try:
        return json.dumps(value if value is not None else fallback, ensure_ascii=False)
    except Exception:
        return json.dumps(fallback, ensure_ascii=False)


def _sql_in_clause(prefix: str, values: Iterable[str]) -> Tuple[str, Dict[str, Any]]:
    params: Dict[str, Any] = {}
    placeholders: List[str] = []
    for index, value in enumerate(list(values or [])):
        key = f"{prefix}_{index}"
        placeholders.append(f":{key}")
        params[key] = str(value or "")
    if not placeholders:
        return "", {}
    return ", ".join(placeholders), params


def _delete_url_nodes(session, node_ids: List[str]):
    resolved_node_ids = [str(item or "").strip() for item in list(node_ids or []) if str(item or "").strip()]
    if not resolved_node_ids:
        return

    node_placeholders, node_params = _sql_in_clause("node_id", resolved_node_ids)
    if not node_placeholders:
        return

    edge_rows = session.execute(text(
        f"SELECT edge_id FROM graph_edge "
        f"WHERE from_node_id IN ({node_placeholders}) OR to_node_id IN ({node_placeholders})"
    ), dict(node_params)).fetchall()
    edge_ids = [str(row[0] or "").strip() for row in edge_rows if row and str(row[0] or "").strip()]

    if edge_ids:
        edge_placeholders, edge_params = _sql_in_clause("edge_id", edge_ids)
        session.execute(text(
            f"DELETE FROM graph_evidence_ref WHERE owner_kind = 'edge' AND owner_id IN ({edge_placeholders})"
        ), edge_params)
        session.execute(text(
            f"DELETE FROM graph_annotation WHERE target_kind = 'edge' AND target_ref IN ({edge_placeholders})"
        ), edge_params)
        session.execute(text(
            f"DELETE FROM graph_edge WHERE edge_id IN ({edge_placeholders})"
        ), edge_params)

    session.execute(text(
        f"DELETE FROM graph_evidence_ref WHERE owner_kind = 'node' AND owner_id IN ({node_placeholders})"
    ), node_params)
    session.execute(text(
        f"DELETE FROM graph_annotation WHERE target_kind = 'node' AND target_ref IN ({node_placeholders})"
    ), node_params)
    session.execute(text(
        f"DELETE FROM graph_node WHERE node_id IN ({node_placeholders})"
    ), node_params)


def _delete_stale_host_url_nodes(session, *, host_id: int, keep_node_keys: Iterable[str]):
    resolved_host_id = int(host_id or 0)
    keep = {str(item or "").strip() for item in list(keep_node_keys or []) if str(item or "").strip()}
    rows = session.execute(text(
        "SELECT node_id, node_key FROM graph_node "
        "WHERE type = 'url' AND node_key LIKE :prefix"
    ), {"prefix": f"url:{resolved_host_id}:%"}).fetchall()
    stale_node_ids = [
        str(row[0] or "").strip()
        for row in rows
        if row and str(row[0] or "").strip() and str(row[1] or "").strip() not in keep
    ]
    _delete_url_nodes(session, stale_node_ids)


def _safe_float(value: Any, default: float = 0.0, minimum: float = 0.0, maximum: float = 100.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = float(default)
    if parsed < minimum:
        return float(minimum)
    if parsed > maximum:
        return float(maximum)
    return float(parsed)


def _clean_text(value: Any, *, limit: int = 240, lower: bool = False, allow_unknown: bool = False) -> str:
    text_value = str(value or "").strip()
    if lower:
        text_value = text_value.lower()
    if not allow_unknown and text_value.lower() in _UNKNOWN_TOKENS:
        return ""
    return text_value[:limit]


def _normalize_source_kind(value: Any, default: str = "observed") -> str:
    token = _clean_text(value or default, limit=32, lower=True, allow_unknown=True) or str(default or "observed")
    return token if token in GRAPH_SOURCE_KINDS else str(default or "observed")


def _choose_source_kind(existing: Any, incoming: Any) -> str:
    existing_token = _normalize_source_kind(existing, "observed")
    incoming_token = _normalize_source_kind(incoming, "observed")
    if _SOURCE_PRIORITY.get(incoming_token, 0) >= _SOURCE_PRIORITY.get(existing_token, 0):
        return incoming_token
    return existing_token


def _merge_values(existing: Any, incoming: Any):
    if isinstance(existing, dict) and isinstance(incoming, dict):
        merged = dict(existing)
        for key, value in incoming.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = _merge_values(merged.get(key), value)
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                combined = []
                seen = set()
                for item in list(value) + list(merged.get(key) or []):
                    marker = json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))
                    if marker in seen:
                        continue
                    seen.add(marker)
                    combined.append(item)
                merged[key] = combined[:240]
            elif value not in [None, "", [], {}]:
                merged[key] = value
        return merged
    return incoming if incoming not in [None, "", [], {}] else existing


def _dedupe_tokens(values: Iterable[Any], *, limit: int = 64, token_limit: int = 320) -> List[str]:
    rows: List[str] = []
    seen = set()
    for value in values:
        token = _clean_text(value, limit=token_limit, allow_unknown=True)
        if not token or token in seen:
            continue
        seen.add(token)
        rows.append(token)
        if len(rows) >= int(limit):
            break
    return rows


def _normalize_filter_list(values: Any, *, limit: int = 32, lower: bool = True) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    rows: List[str] = []
    seen = set()
    for value in list(values or []):
        token = _clean_text(value, limit=96, lower=lower, allow_unknown=True)
        if not token or token in seen:
            continue
        seen.add(token)
        rows.append(token)
        if len(rows) >= int(limit):
            break
    return rows


def _node_matches_search(node: Dict[str, Any], search_token: str) -> bool:
    token = str(search_token or "").strip().lower()
    if not token:
        return True
    props = node.get("properties", {}) if isinstance(node.get("properties", {}), dict) else {}
    haystack = " ".join([
        str(node.get("type", "") or ""),
        str(node.get("label", "") or ""),
        str(node.get("source_ref", "") or ""),
        json.dumps(props, sort_keys=True, default=str),
    ]).lower()
    return token in haystack


def _edge_matches_search(edge: Dict[str, Any], search_token: str) -> bool:
    token = str(search_token or "").strip().lower()
    if not token:
        return True
    props = edge.get("properties", {}) if isinstance(edge.get("properties", {}), dict) else {}
    haystack = " ".join([
        str(edge.get("type", "") or ""),
        str(edge.get("source_ref", "") or ""),
        json.dumps(props, sort_keys=True, default=str),
    ]).lower()
    return token in haystack


def _remember_mutation(mutations: List[str], kind: str, ref: str):
    token = f"{str(kind or '').strip().lower()}:{str(ref or '').strip()}"
    if token and token not in mutations:
        mutations.append(token)


def _upsert_node(
        session,
        *,
        node_key: str,
        node_type: str,
        label: str,
        confidence: float,
        source_kind: str,
        source_ref: str,
        properties: Optional[Dict[str, Any]] = None,
        evidence_refs: Optional[List[str]] = None,
) -> Tuple[str, bool]:
    now = _utc_now()
    key = _clean_text(node_key, limit=320, allow_unknown=True)
    if not key:
        return "", False
    node_id = _stable_id("graph-node", {"node_key": key})
    result = session.execute(text(
        "SELECT node_id, label, confidence, source_kind, source_ref, first_seen, properties_json "
        "FROM graph_node WHERE node_key = :node_key LIMIT 1"
    ), {"node_key": key}).fetchone()
    changed = False
    incoming_props = dict(properties or {})
    if result is None:
        session.execute(text(
            "INSERT INTO graph_node ("
            "node_id, node_key, type, label, confidence, source_kind, source_ref, first_seen, last_seen, properties_json"
            ") VALUES ("
            ":node_id, :node_key, :type, :label, :confidence, :source_kind, :source_ref, :first_seen, :last_seen, :properties_json"
            ")"
        ), {
            "node_id": node_id,
            "node_key": key,
            "type": _clean_text(node_type, limit=80, lower=True, allow_unknown=True),
            "label": _clean_text(label, limit=240, allow_unknown=True),
            "confidence": _safe_float(confidence),
            "source_kind": _normalize_source_kind(source_kind),
            "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
            "first_seen": now,
            "last_seen": now,
            "properties_json": _to_json(incoming_props, {}),
        })
        changed = True
    else:
        existing_props = _from_json(result[6], {})
        merged_props = _merge_values(existing_props if isinstance(existing_props, dict) else {}, incoming_props)
        resolved_label = _clean_text(label, limit=240, allow_unknown=True) or _clean_text(result[1], limit=240, allow_unknown=True)
        resolved_kind = _choose_source_kind(result[3], source_kind)
        resolved_ref = (
            _clean_text(source_ref, limit=320, allow_unknown=True)
            if _SOURCE_PRIORITY.get(resolved_kind, 0) >= _SOURCE_PRIORITY.get(_normalize_source_kind(result[3], "observed"), 0)
            and _clean_text(source_ref, limit=320, allow_unknown=True)
            else _clean_text(result[4], limit=320, allow_unknown=True)
        )
        resolved_conf = max(_safe_float(result[2]), _safe_float(confidence))
        session.execute(text(
            "UPDATE graph_node SET "
            "type = :type, label = :label, confidence = :confidence, source_kind = :source_kind, "
            "source_ref = :source_ref, last_seen = :last_seen, properties_json = :properties_json "
            "WHERE node_key = :node_key"
        ), {
            "type": _clean_text(node_type, limit=80, lower=True, allow_unknown=True),
            "label": resolved_label,
            "confidence": resolved_conf,
            "source_kind": resolved_kind,
            "source_ref": resolved_ref,
            "last_seen": now,
            "properties_json": _to_json(merged_props, {}),
            "node_key": key,
        })
        changed = True
    _attach_evidence_refs(session, "node", node_id, evidence_refs or [])
    return node_id, changed


def _upsert_edge(
        session,
        *,
        edge_type: str,
        from_node_id: str,
        to_node_id: str,
        confidence: float,
        source_kind: str,
        source_ref: str,
        properties: Optional[Dict[str, Any]] = None,
        evidence_refs: Optional[List[str]] = None,
) -> Tuple[str, bool]:
    from_ref = _clean_text(from_node_id, limit=80, allow_unknown=True)
    to_ref = _clean_text(to_node_id, limit=80, allow_unknown=True)
    edge_kind = _clean_text(edge_type, limit=80, lower=True, allow_unknown=True)
    if not edge_kind or not from_ref or not to_ref:
        return "", False
    edge_key = f"{edge_kind}:{from_ref}:{to_ref}"
    edge_id = _stable_id("graph-edge", {"edge_key": edge_key})
    now = _utc_now()
    result = session.execute(text(
        "SELECT edge_id, confidence, source_kind, source_ref, properties_json "
        "FROM graph_edge WHERE edge_key = :edge_key LIMIT 1"
    ), {"edge_key": edge_key}).fetchone()
    changed = False
    incoming_props = dict(properties or {})
    if result is None:
        session.execute(text(
            "INSERT INTO graph_edge ("
            "edge_id, edge_key, type, from_node_id, to_node_id, confidence, source_kind, source_ref, first_seen, last_seen, properties_json"
            ") VALUES ("
            ":edge_id, :edge_key, :type, :from_node_id, :to_node_id, :confidence, :source_kind, :source_ref, :first_seen, :last_seen, :properties_json"
            ")"
        ), {
            "edge_id": edge_id,
            "edge_key": edge_key,
            "type": edge_kind,
            "from_node_id": from_ref,
            "to_node_id": to_ref,
            "confidence": _safe_float(confidence),
            "source_kind": _normalize_source_kind(source_kind),
            "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
            "first_seen": now,
            "last_seen": now,
            "properties_json": _to_json(incoming_props, {}),
        })
        changed = True
    else:
        existing_props = _from_json(result[4], {})
        merged_props = _merge_values(existing_props if isinstance(existing_props, dict) else {}, incoming_props)
        resolved_kind = _choose_source_kind(result[2], source_kind)
        resolved_ref = (
            _clean_text(source_ref, limit=320, allow_unknown=True)
            if _SOURCE_PRIORITY.get(resolved_kind, 0) >= _SOURCE_PRIORITY.get(_normalize_source_kind(result[2], "observed"), 0)
            and _clean_text(source_ref, limit=320, allow_unknown=True)
            else _clean_text(result[3], limit=320, allow_unknown=True)
        )
        resolved_conf = max(_safe_float(result[1]), _safe_float(confidence))
        session.execute(text(
            "UPDATE graph_edge SET "
            "confidence = :confidence, source_kind = :source_kind, source_ref = :source_ref, "
            "last_seen = :last_seen, properties_json = :properties_json "
            "WHERE edge_key = :edge_key"
        ), {
            "confidence": resolved_conf,
            "source_kind": resolved_kind,
            "source_ref": resolved_ref,
            "last_seen": now,
            "properties_json": _to_json(merged_props, {}),
            "edge_key": edge_key,
        })
        changed = True
    _attach_evidence_refs(session, "edge", edge_id, evidence_refs or [])
    return edge_id, changed


def _attach_evidence_refs(session, owner_kind: str, owner_id: str, evidence_refs: List[str]):
    now = _utc_now()
    for token in _dedupe_tokens(evidence_refs, limit=32, token_limit=320):
        existing = session.execute(text(
            "SELECT id FROM graph_evidence_ref "
            "WHERE owner_kind = :owner_kind AND owner_id = :owner_id AND evidence_ref = :evidence_ref LIMIT 1"
        ), {
            "owner_kind": _clean_text(owner_kind, limit=16, lower=True, allow_unknown=True),
            "owner_id": _clean_text(owner_id, limit=80, allow_unknown=True),
            "evidence_ref": token,
        }).fetchone()
        if existing is not None:
            continue
        session.execute(text(
            "INSERT INTO graph_evidence_ref (owner_kind, owner_id, evidence_ref, created_at) "
            "VALUES (:owner_kind, :owner_id, :evidence_ref, :created_at)"
        ), {
            "owner_kind": _clean_text(owner_kind, limit=16, lower=True, allow_unknown=True),
            "owner_id": _clean_text(owner_id, limit=80, allow_unknown=True),
            "evidence_ref": token,
            "created_at": now,
        })


def ensure_scheduler_graph_tables(database):
    session = database.session()
    try:
        _ensure_tables(session)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _subnet_for_host(host_ip: str) -> str:
    token = _clean_text(host_ip, limit=128, allow_unknown=True)
    if not token:
        return ""
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return ""
    if isinstance(address, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{token}/24", strict=False))
    return str(ipaddress.ip_network(f"{token}/64", strict=False))


def _load_host_context(database, host_id: int) -> Dict[str, Any]:
    from app.scheduler.state import build_target_urls, get_target_state, load_observed_service_inventory

    session = database.session()
    try:
        host_row = session.execute(text(
            "SELECT id, COALESCE(ip, '') AS ip, COALESCE(hostname, '') AS hostname, COALESCE(osMatch, '') AS os_match "
            "FROM hostObj WHERE id = :host_id LIMIT 1"
        ), {"host_id": int(host_id or 0)}).fetchone()
        base = {
            "host_id": int(host_id or 0),
            "host_ip": "",
            "hostname": "",
            "os_match": "",
            "service_inventory": [],
            "urls": [],
            "technologies": [],
            "findings": [],
            "manual_tests": [],
            "coverage_gaps": [],
            "attempted_actions": [],
            "credentials": [],
            "sessions": [],
            "screenshots": [],
            "artifacts": [],
            "raw": {},
        }
        if host_row is not None:
            base.update({
                "host_ip": _clean_text(host_row[1], limit=160),
                "hostname": _clean_text(host_row[2], limit=200),
                "os_match": _clean_text(host_row[3], limit=120),
            })
        target_state = get_target_state(database, int(host_id or 0))
        if isinstance(target_state, dict) and target_state:
            base.update({key: value for key, value in target_state.items() if value not in [None, ""]})
        service_inventory = load_observed_service_inventory(database, int(host_id or 0))
        if service_inventory:
            base["service_inventory"] = service_inventory
        if not isinstance(base.get("urls", []), list) or not base.get("urls"):
            base["urls"] = build_target_urls(
                str(base.get("host_ip", "") or ""),
                str(base.get("hostname", "") or ""),
                base.get("service_inventory", []) if isinstance(base.get("service_inventory", []), list) else [],
            )
        cve_rows = session.execute(text(
            "SELECT id, COALESCE(name, '') AS name, COALESCE(url, '') AS url, COALESCE(product, '') AS product, "
            "COALESCE(severity, '') AS severity, COALESCE(source, '') AS source, COALESCE(version, '') AS version, "
            "COALESCE(exploitId, 0) AS exploit_id, COALESCE(exploit, '') AS exploit, COALESCE(exploitUrl, '') AS exploit_url, "
            "COALESCE(serviceId, '') AS service_id "
            "FROM cve WHERE CAST(hostId AS TEXT) = :host_id ORDER BY id ASC"
        ), {"host_id": str(int(host_id or 0))}).fetchall()
        base["cves"] = [
            {
                "id": int(row[0] or 0),
                "name": _clean_text(row[1], limit=120, allow_unknown=True),
                "url": _clean_text(row[2], limit=320, allow_unknown=True),
                "product": _clean_text(row[3], limit=120, allow_unknown=True),
                "severity": _clean_text(row[4], limit=32, lower=True, allow_unknown=True),
                "source": _clean_text(row[5], limit=80, allow_unknown=True),
                "version": _clean_text(row[6], limit=80, allow_unknown=True),
                "exploit_id": int(row[7] or 0),
                "exploit": _clean_text(row[8], limit=220, allow_unknown=True),
                "exploit_url": _clean_text(row[9], limit=320, allow_unknown=True),
                "service_id": _clean_text(row[10], limit=40, allow_unknown=True),
            }
            for row in cve_rows
        ]
        note_rows = session.execute(text(
            "SELECT id, COALESCE(text, '') AS text FROM note WHERE hostId = :host_id ORDER BY id ASC"
        ), {"host_id": int(host_id or 0)}).fetchall()
        base["notes"] = [
            {"id": int(row[0] or 0), "text": _clean_text(row[1], limit=2000, allow_unknown=True)}
            for row in note_rows
            if _clean_text(row[1], limit=2000, allow_unknown=True)
        ]
        return base
    finally:
        session.close()


def _upsert_annotation(
        session,
        *,
        target_kind: str,
        target_ref: str,
        body: str,
        created_by: str = "system",
        source_ref: str = "",
) -> Tuple[str, bool]:
    target_token = _clean_text(target_ref, limit=80, allow_unknown=True)
    body_token = _clean_text(body, limit=4000, allow_unknown=True)
    if not target_token or not body_token:
        return "", False
    annotation_id = _stable_id("graph-annotation", {
        "target_kind": _clean_text(target_kind, limit=32, lower=True, allow_unknown=True),
        "target_ref": target_token,
        "body": body_token,
        "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
    })
    now = _utc_now()
    existing = session.execute(text(
        "SELECT annotation_id FROM graph_annotation WHERE annotation_id = :annotation_id LIMIT 1"
    ), {"annotation_id": annotation_id}).fetchone()
    if existing is None:
        session.execute(text(
            "INSERT INTO graph_annotation ("
            "annotation_id, target_kind, target_ref, body, created_by, created_at, updated_at, source_ref"
            ") VALUES ("
            ":annotation_id, :target_kind, :target_ref, :body, :created_by, :created_at, :updated_at, :source_ref"
            ")"
        ), {
            "annotation_id": annotation_id,
            "target_kind": _clean_text(target_kind, limit=32, lower=True, allow_unknown=True),
            "target_ref": target_token,
            "body": body_token,
            "created_by": _clean_text(created_by, limit=80, allow_unknown=True),
            "created_at": now,
            "updated_at": now,
            "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
        })
        return annotation_id, True
    session.execute(text(
        "UPDATE graph_annotation SET body = :body, updated_at = :updated_at, source_ref = :source_ref "
        "WHERE annotation_id = :annotation_id"
    ), {
        "body": body_token,
        "updated_at": now,
        "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
        "annotation_id": annotation_id,
    })
    return annotation_id, True


def upsert_graph_layout_state(
        database,
        *,
        view_id: str,
        name: str,
        layout_state: Dict[str, Any],
        layout_id: str = "",
) -> Dict[str, Any]:
    session = database.session()
    try:
        _ensure_tables(session)
        resolved_layout_id = _clean_text(layout_id, limit=80, allow_unknown=True) or _stable_id("graph-layout", {
            "view_id": _clean_text(view_id, limit=80, allow_unknown=True),
            "name": _clean_text(name, limit=160, allow_unknown=True),
        })
        payload = {
            "layout_id": resolved_layout_id,
            "view_id": _clean_text(view_id, limit=80, allow_unknown=True),
            "name": _clean_text(name, limit=160, allow_unknown=True),
            "layout_json": _to_json(layout_state if isinstance(layout_state, dict) else {}, {}),
            "updated_at": _utc_now(),
        }
        existing = session.execute(text(
            "SELECT layout_id FROM graph_layout_state WHERE layout_id = :layout_id LIMIT 1"
        ), {"layout_id": resolved_layout_id}).fetchone()
        if existing is None:
            session.execute(text(
                "INSERT INTO graph_layout_state (layout_id, view_id, name, layout_json, updated_at) "
                "VALUES (:layout_id, :view_id, :name, :layout_json, :updated_at)"
            ), payload)
        else:
            session.execute(text(
                "UPDATE graph_layout_state SET view_id = :view_id, name = :name, layout_json = :layout_json, "
                "updated_at = :updated_at WHERE layout_id = :layout_id"
            ), payload)
        session.commit()
        return {
            "layout_id": resolved_layout_id,
            "view_id": payload["view_id"],
            "name": payload["name"],
            "layout": layout_state if isinstance(layout_state, dict) else {},
            "updated_at": payload["updated_at"],
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def list_graph_layout_states(database) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_tables(session)
        result = session.execute(text(
            "SELECT layout_id, view_id, name, layout_json, updated_at FROM graph_layout_state ORDER BY id ASC"
        ))
        rows = []
        for row in result.fetchall():
            rows.append({
                "layout_id": _clean_text(row[0], limit=80, allow_unknown=True),
                "view_id": _clean_text(row[1], limit=80, allow_unknown=True),
                "name": _clean_text(row[2], limit=160, allow_unknown=True),
                "layout": _from_json(row[3], {}),
                "updated_at": _clean_text(row[4], limit=64, allow_unknown=True),
            })
        return rows
    finally:
        session.close()


def upsert_graph_annotation(
        database,
        *,
        target_kind: str,
        target_ref: str,
        body: str,
        created_by: str = "operator",
        source_ref: str = "",
        annotation_id: str = "",
) -> Dict[str, Any]:
    session = database.session()
    try:
        _ensure_tables(session)
        resolved_annotation_id = _clean_text(annotation_id, limit=80, allow_unknown=True)
        if not resolved_annotation_id:
            resolved_annotation_id = _stable_id("graph-annotation", {
                "target_kind": _clean_text(target_kind, limit=32, lower=True, allow_unknown=True),
                "target_ref": _clean_text(target_ref, limit=80, allow_unknown=True),
                "body": _clean_text(body, limit=4000, allow_unknown=True),
                "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
            })
        now = _utc_now()
        payload = {
            "annotation_id": resolved_annotation_id,
            "target_kind": _clean_text(target_kind, limit=32, lower=True, allow_unknown=True),
            "target_ref": _clean_text(target_ref, limit=80, allow_unknown=True),
            "body": _clean_text(body, limit=4000, allow_unknown=True),
            "created_by": _clean_text(created_by, limit=80, allow_unknown=True),
            "created_at": now,
            "updated_at": now,
            "source_ref": _clean_text(source_ref, limit=320, allow_unknown=True),
        }
        existing = session.execute(text(
            "SELECT annotation_id, created_at FROM graph_annotation WHERE annotation_id = :annotation_id LIMIT 1"
        ), {"annotation_id": resolved_annotation_id}).fetchone()
        if existing is None:
            session.execute(text(
                "INSERT INTO graph_annotation ("
                "annotation_id, target_kind, target_ref, body, created_by, created_at, updated_at, source_ref"
                ") VALUES ("
                ":annotation_id, :target_kind, :target_ref, :body, :created_by, :created_at, :updated_at, :source_ref"
                ")"
            ), payload)
        else:
            payload["created_at"] = _clean_text(existing[1], limit=64, allow_unknown=True) or now
            session.execute(text(
                "UPDATE graph_annotation SET target_kind = :target_kind, target_ref = :target_ref, body = :body, "
                "created_by = :created_by, updated_at = :updated_at, source_ref = :source_ref "
                "WHERE annotation_id = :annotation_id"
            ), payload)
        session.commit()
        return {
            "annotation_id": resolved_annotation_id,
            "target_kind": payload["target_kind"],
            "target_ref": payload["target_ref"],
            "body": payload["body"],
            "created_by": payload["created_by"],
            "created_at": payload["created_at"],
            "updated_at": payload["updated_at"],
            "source_ref": payload["source_ref"],
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def list_graph_annotations(database, *, target_ref: str = "", target_kind: str = "") -> List[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_tables(session)
        query = (
            "SELECT annotation_id, target_kind, target_ref, body, created_by, created_at, updated_at, source_ref "
            "FROM graph_annotation WHERE 1=1"
        )
        params: Dict[str, Any] = {}
        if _clean_text(target_ref, limit=80, allow_unknown=True):
            query += " AND target_ref = :target_ref"
            params["target_ref"] = _clean_text(target_ref, limit=80, allow_unknown=True)
        if _clean_text(target_kind, limit=32, lower=True, allow_unknown=True):
            query += " AND target_kind = :target_kind"
            params["target_kind"] = _clean_text(target_kind, limit=32, lower=True, allow_unknown=True)
        query += " ORDER BY id ASC"
        result = session.execute(text(query), params)
        rows = []
        for row in result.fetchall():
            rows.append({
                "annotation_id": _clean_text(row[0], limit=80, allow_unknown=True),
                "target_kind": _clean_text(row[1], limit=32, lower=True, allow_unknown=True),
                "target_ref": _clean_text(row[2], limit=80, allow_unknown=True),
                "body": _clean_text(row[3], limit=4000, allow_unknown=True),
                "created_by": _clean_text(row[4], limit=80, allow_unknown=True),
                "created_at": _clean_text(row[5], limit=64, allow_unknown=True),
                "updated_at": _clean_text(row[6], limit=64, allow_unknown=True),
                "source_ref": _clean_text(row[7], limit=320, allow_unknown=True),
            })
        return rows
    finally:
        session.close()


def sync_target_state_to_evidence_graph(
        database,
        *,
        host_id: int,
        target_state: Optional[Dict[str, Any]] = None,
) -> List[str]:
    context = _load_host_context(database, int(host_id or 0))
    if isinstance(target_state, dict) and target_state:
        for key, value in target_state.items():
            if value not in [None, ""]:
                context[key] = value
    if int(context.get("host_id", 0) or host_id or 0) <= 0 and not _clean_text(context.get("host_ip", ""), limit=160):
        return []

    mutations: List[str] = []
    session = database.session()
    try:
        _ensure_tables(session)
        resolved_host_id = int(context.get("host_id", 0) or host_id or 0)
        host_ip = _clean_text(context.get("host_ip", ""), limit=160)
        hostname = _clean_text(context.get("hostname", ""), limit=200)
        os_match = _clean_text(context.get("os_match", ""), limit=120)
        goal_profile = _clean_text(context.get("goal_profile", ""), limit=80, allow_unknown=True)
        engagement_preset = _clean_text(context.get("engagement_preset", ""), limit=80, allow_unknown=True)
        last_mode = _clean_text(context.get("last_mode", ""), limit=32, lower=True, allow_unknown=True)
        scope_node_id, changed = _upsert_node(
            session,
            node_key="scope:project",
            node_type="scope",
            label="Project Scope",
            confidence=100.0,
            source_kind="user_entered",
            source_ref="project:active",
            properties={},
        )
        if changed:
            _remember_mutation(mutations, "node", scope_node_id)

        host_label = hostname or host_ip or f"host-{resolved_host_id}"
        host_node_id, changed = _upsert_node(
            session,
            node_key=f"host:{host_ip or resolved_host_id}",
            node_type="host",
            label=host_label,
            confidence=95.0 if host_ip else 75.0,
            source_kind="observed",
            source_ref=f"host:{resolved_host_id}" if resolved_host_id > 0 else f"host_ip:{host_ip}",
            properties={
                "host_id": resolved_host_id,
                "ip": host_ip,
                "hostname": hostname,
                "os_match": os_match,
                "goal_profile": goal_profile,
                "engagement_preset": engagement_preset,
                "last_mode": last_mode,
            },
            evidence_refs=[f"host:{host_ip}" if host_ip else ""],
        )
        if changed:
            _remember_mutation(mutations, "node", host_node_id)

        subnet = _subnet_for_host(host_ip)
        if subnet:
            subnet_node_id, changed = _upsert_node(
                session,
                node_key=f"subnet:{subnet}",
                node_type="subnet",
                label=subnet,
                confidence=100.0,
                source_kind="observed",
                source_ref=f"host:{resolved_host_id}" if resolved_host_id > 0 else f"host_ip:{host_ip}",
                properties={"cidr": subnet},
            )
            if changed:
                _remember_mutation(mutations, "node", subnet_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=scope_node_id,
                to_node_id=subnet_node_id,
                confidence=100.0,
                source_kind="observed",
                source_ref="project:scope",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=subnet_node_id,
                to_node_id=host_node_id,
                confidence=100.0,
                source_kind="observed",
                source_ref=f"host:{resolved_host_id}" if resolved_host_id > 0 else host_ip,
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
        else:
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=scope_node_id,
                to_node_id=host_node_id,
                confidence=100.0,
                source_kind="observed",
                source_ref="project:scope",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)

        if hostname:
            fqdn_node_id, changed = _upsert_node(
                session,
                node_key=f"fqdn:{hostname.lower()}",
                node_type="fqdn",
                label=hostname,
                confidence=_safe_float(context.get("hostname_confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(context.get("hostname_source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}" if resolved_host_id > 0 else host_ip,
                properties={"hostname": hostname},
            )
            if changed:
                _remember_mutation(mutations, "node", fqdn_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="resolves_to",
                from_node_id=fqdn_node_id,
                to_node_id=host_node_id,
                confidence=_safe_float(context.get("hostname_confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(context.get("hostname_source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}" if resolved_host_id > 0 else host_ip,
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)

        service_nodes: Dict[str, str] = {}
        for item in list(context.get("service_inventory", []) or []):
            if not isinstance(item, dict):
                continue
            port = _clean_text(item.get("port", ""), limit=20, allow_unknown=True)
            protocol = _clean_text(item.get("protocol", "tcp"), limit=12, lower=True, allow_unknown=True) or "tcp"
            service_name = _clean_text(item.get("service", ""), limit=64)
            service_product = _clean_text(item.get("service_product", ""), limit=120)
            service_version = _clean_text(item.get("service_version", ""), limit=80)
            service_banner = _clean_text(item.get("banner", ""), limit=320, allow_unknown=True)
            if not port:
                continue
            port_node_id, changed = _upsert_node(
                session,
                node_key=f"port:{resolved_host_id}:{port}/{protocol}",
                node_type="port",
                label=f"{port}/{protocol}",
                confidence=_safe_float(item.get("confidence", 95.0), 95.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:port:{port}/{protocol}",
                properties={
                    "host_id": resolved_host_id,
                    "port": port,
                    "protocol": protocol,
                    "state": _clean_text(item.get("state", ""), limit=32, lower=True, allow_unknown=True),
                },
            )
            if changed:
                _remember_mutation(mutations, "node", port_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=port_node_id,
                confidence=_safe_float(item.get("confidence", 95.0), 95.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:port:{port}/{protocol}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            service_node_id, changed = _upsert_node(
                session,
                node_key=f"service:{resolved_host_id}:{port}/{protocol}:{service_name or service_product or 'unknown'}",
                node_type="service",
                label=service_name or service_product or f"service:{port}/{protocol}",
                confidence=_safe_float(item.get("confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:service:{port}/{protocol}",
                properties={
                    "host_id": resolved_host_id,
                    "port": port,
                    "protocol": protocol,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                    "banner": service_banner,
                },
            )
            service_nodes[f"{port}/{protocol}"] = service_node_id
            if changed:
                _remember_mutation(mutations, "node", service_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="exposes",
                from_node_id=port_node_id,
                to_node_id=service_node_id,
                confidence=_safe_float(item.get("confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:service:{port}/{protocol}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)

        normalized_url_keys = set()
        for item in list(context.get("urls", []) or []):
            if not isinstance(item, dict):
                continue
            url = normalize_discovered_url(item.get("url", ""))
            url = _clean_text(url, limit=320, allow_unknown=True)
            if not url:
                continue
            port = _clean_text(item.get("port", ""), limit=20, allow_unknown=True)
            protocol = _clean_text(item.get("protocol", "tcp"), limit=12, lower=True, allow_unknown=True) or "tcp"
            node_key = f"url:{resolved_host_id}:{url}"
            normalized_url_keys.add(node_key)
            url_node_id, changed = _upsert_node(
                session,
                node_key=node_key,
                node_type="url",
                label=url,
                confidence=_safe_float(item.get("confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"url:{url}",
                properties={
                    "host_id": resolved_host_id,
                    "url": url,
                    "port": port,
                    "protocol": protocol,
                    "service": _clean_text(item.get("service", ""), limit=64),
                },
            )
            if changed:
                _remember_mutation(mutations, "node", url_node_id)
            parent_service_id = service_nodes.get(f"{port}/{protocol}") or host_node_id
            edge_id, changed = _upsert_edge(
                session,
                edge_type="exposes",
                from_node_id=parent_service_id,
                to_node_id=url_node_id,
                confidence=_safe_float(item.get("confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"url:{url}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)

        _delete_stale_host_url_nodes(
            session,
            host_id=resolved_host_id,
            keep_node_keys=normalized_url_keys,
        )

        for item in list(context.get("technologies", []) or []):
            if not isinstance(item, dict):
                continue
            name = _clean_text(item.get("name", ""), limit=120)
            cpe = _clean_text(item.get("cpe", ""), limit=180, allow_unknown=True)
            if not name and not cpe:
                continue
            tech_node_id, changed = _upsert_node(
                session,
                node_key=f"technology:{resolved_host_id}:{name.lower()}:{_clean_text(item.get('version', ''), limit=80, allow_unknown=True)}:{cpe.lower()}",
                node_type="technology",
                label=" ".join(part for part in [name, _clean_text(item.get("version", ""), limit=80, allow_unknown=True)] if part) or cpe,
                confidence=_safe_float(item.get("confidence", 72.0), 72.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:technology:{name or cpe}",
                properties={
                    "host_id": resolved_host_id,
                    "name": name,
                    "version": _clean_text(item.get("version", ""), limit=80, allow_unknown=True),
                    "cpe": cpe,
                },
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "node", tech_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="fingerprinted_as",
                from_node_id=host_node_id,
                to_node_id=tech_node_id,
                confidence=_safe_float(item.get("confidence", 72.0), 72.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:technology:{name or cpe}",
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            evidence_text = _clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)
            if evidence_text:
                evidence_node_id, changed = _upsert_node(
                    session,
                    node_key=f"evidence:technology:{resolved_host_id}:{name.lower()}:{hashlib.sha1(evidence_text.encode('utf-8')).hexdigest()[:12]}",
                    node_type="evidence_record",
                    label=evidence_text[:120],
                    confidence=100.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:technology:evidence",
                    properties={"host_id": resolved_host_id, "evidence": evidence_text, "entity_type": "technology"},
                )
                if changed:
                    _remember_mutation(mutations, "node", evidence_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="derived_from",
                    from_node_id=tech_node_id,
                    to_node_id=evidence_node_id,
                    confidence=100.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:technology:evidence",
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)
            if cpe:
                cpe_node_id, changed = _upsert_node(
                    session,
                    node_key=f"cpe:{cpe.lower()}",
                    node_type="cpe",
                    label=cpe,
                    confidence=_safe_float(item.get("confidence", 82.0), 82.0),
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:cpe:{cpe}",
                    properties={"cpe": cpe},
                )
                if changed:
                    _remember_mutation(mutations, "node", cpe_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="mapped_to_cpe",
                    from_node_id=tech_node_id,
                    to_node_id=cpe_node_id,
                    confidence=_safe_float(item.get("confidence", 82.0), 82.0),
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:cpe:{cpe}",
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)

        for item in list(context.get("findings", []) or []):
            if not isinstance(item, dict):
                continue
            title = _clean_text(item.get("title", ""), limit=220, allow_unknown=True)
            cve_id = _clean_text(item.get("cve", ""), limit=64, allow_unknown=True).upper()
            if not title and not cve_id:
                continue
            finding_node_id, changed = _upsert_node(
                session,
                node_key=f"finding:{resolved_host_id}:{title.lower()}:{cve_id.lower()}",
                node_type="finding",
                label=title or cve_id,
                confidence=_safe_float(item.get("confidence", 80.0), 80.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:finding:{title or cve_id}",
                properties={
                    "host_id": resolved_host_id,
                    "title": title,
                    "severity": _clean_text(item.get("severity", "info"), limit=16, lower=True, allow_unknown=True),
                    "cvss": _safe_float(item.get("cvss", 0.0)),
                    "cve": cve_id,
                },
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "node", finding_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=finding_node_id,
                confidence=_safe_float(item.get("confidence", 80.0), 80.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:finding:{title or cve_id}",
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            if cve_id:
                cve_node_id, changed = _upsert_node(
                    session,
                    node_key=f"cve:{cve_id.lower()}",
                    node_type="cve",
                    label=cve_id,
                    confidence=95.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"cve:{cve_id}",
                    properties={"cve": cve_id},
                )
                if changed:
                    _remember_mutation(mutations, "node", cve_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="affected_by",
                    from_node_id=finding_node_id,
                    to_node_id=cve_node_id,
                    confidence=95.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"cve:{cve_id}",
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)
            evidence_text = _clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)
            if evidence_text:
                evidence_node_id, changed = _upsert_node(
                    session,
                    node_key=f"evidence:finding:{resolved_host_id}:{hashlib.sha1(evidence_text.encode('utf-8')).hexdigest()[:12]}",
                    node_type="evidence_record",
                    label=evidence_text[:120],
                    confidence=100.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:finding:evidence",
                    properties={"host_id": resolved_host_id, "evidence": evidence_text, "entity_type": "finding"},
                )
                if changed:
                    _remember_mutation(mutations, "node", evidence_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="derived_from",
                    from_node_id=finding_node_id,
                    to_node_id=evidence_node_id,
                    confidence=100.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:finding:evidence",
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)

        for row in list(context.get("cves", []) or []):
            if not isinstance(row, dict):
                continue
            cve_name = _clean_text(row.get("name", ""), limit=120, allow_unknown=True).upper()
            if not cve_name:
                continue
            finding_node_id, changed = _upsert_node(
                session,
                node_key=f"finding:{resolved_host_id}:{cve_name.lower()}",
                node_type="finding",
                label=cve_name,
                confidence=96.0,
                source_kind="observed",
                source_ref=f"cve_row:{int(row.get('id', 0) or 0)}",
                properties={
                    "host_id": resolved_host_id,
                    "title": cve_name,
                    "severity": _clean_text(row.get("severity", "info"), limit=16, lower=True, allow_unknown=True),
                    "product": _clean_text(row.get("product", ""), limit=120, allow_unknown=True),
                    "version": _clean_text(row.get("version", ""), limit=80, allow_unknown=True),
                    "source": _clean_text(row.get("source", ""), limit=80, allow_unknown=True),
                    "cve": cve_name if cve_name.startswith("CVE-") else "",
                },
                evidence_refs=[_clean_text(row.get("url", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "node", finding_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=finding_node_id,
                confidence=96.0,
                source_kind="observed",
                source_ref=f"cve_row:{int(row.get('id', 0) or 0)}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            if cve_name.startswith("CVE-"):
                cve_node_id, changed = _upsert_node(
                    session,
                    node_key=f"cve:{cve_name.lower()}",
                    node_type="cve",
                    label=cve_name,
                    confidence=98.0,
                    source_kind="observed",
                    source_ref=f"cve:{cve_name}",
                    properties={"cve": cve_name, "url": _clean_text(row.get("url", ""), limit=320, allow_unknown=True)},
                )
                if changed:
                    _remember_mutation(mutations, "node", cve_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="affected_by",
                    from_node_id=finding_node_id,
                    to_node_id=cve_node_id,
                    confidence=98.0,
                    source_kind="observed",
                    source_ref=f"cve_row:{int(row.get('id', 0) or 0)}",
                    evidence_refs=[_clean_text(row.get("url", ""), limit=320, allow_unknown=True)],
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)
                exploit_ref = _clean_text(row.get("exploit_url", ""), limit=320, allow_unknown=True) or _clean_text(
                    row.get("exploit", ""), limit=220, allow_unknown=True
                )
                if exploit_ref:
                    exploit_node_id, changed = _upsert_node(
                        session,
                        node_key=f"exploit:{hashlib.sha1(exploit_ref.encode('utf-8')).hexdigest()[:16]}",
                        node_type="exploit_reference",
                        label=exploit_ref[:160],
                        confidence=84.0,
                        source_kind="observed",
                        source_ref=f"cve_row:{int(row.get('id', 0) or 0)}",
                        properties={
                            "exploit_id": int(row.get("exploit_id", 0) or 0),
                            "exploit": _clean_text(row.get("exploit", ""), limit=220, allow_unknown=True),
                            "exploit_url": _clean_text(row.get("exploit_url", ""), limit=320, allow_unknown=True),
                        },
                    )
                    if changed:
                        _remember_mutation(mutations, "node", exploit_node_id)
                    edge_id, changed = _upsert_edge(
                        session,
                        edge_type="supports_exploit",
                        from_node_id=cve_node_id,
                        to_node_id=exploit_node_id,
                        confidence=84.0,
                        source_kind="observed",
                        source_ref=f"cve_row:{int(row.get('id', 0) or 0)}",
                        evidence_refs=[exploit_ref],
                    )
                    if changed:
                        _remember_mutation(mutations, "edge", edge_id)

        for item in list(context.get("credentials", []) or []):
            if not isinstance(item, dict):
                continue
            username = _clean_text(item.get("username", ""), limit=160, allow_unknown=True)
            realm = _clean_text(item.get("realm", ""), limit=160, allow_unknown=True)
            if not username and not _clean_text(item.get("secret_ref", ""), limit=240, allow_unknown=True):
                continue
            cred_node_id, changed = _upsert_node(
                session,
                node_key=f"credential:{resolved_host_id}:{username.lower()}:{realm.lower()}:{_clean_text(item.get('type', ''), limit=64, lower=True, allow_unknown=True)}:{_clean_text(item.get('secret_ref', ''), limit=240, allow_unknown=True)}",
                node_type="credential",
                label=username or _clean_text(item.get("secret_ref", ""), limit=120, allow_unknown=True),
                confidence=_safe_float(item.get("confidence", 75.0), 75.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:credential:{username or realm}",
                properties={
                    "host_id": resolved_host_id,
                    "username": username,
                    "realm": realm,
                    "type": _clean_text(item.get("type", ""), limit=64, lower=True, allow_unknown=True),
                    "secret_ref": _clean_text(item.get("secret_ref", ""), limit=240, allow_unknown=True),
                },
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "node", cred_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=cred_node_id,
                confidence=_safe_float(item.get("confidence", 75.0), 75.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:credential:{username or realm}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            identity_node_id, changed = _upsert_node(
                session,
                node_key=f"identity:{username.lower()}:{realm.lower()}",
                node_type="identity",
                label="\\".join(part for part in [realm, username] if part) or username or realm,
                confidence=_safe_float(item.get("confidence", 75.0), 75.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"identity:{username or realm}",
                properties={"username": username, "realm": realm},
            )
            if changed:
                _remember_mutation(mutations, "node", identity_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="authenticated_as",
                from_node_id=cred_node_id,
                to_node_id=identity_node_id,
                confidence=_safe_float(item.get("confidence", 75.0), 75.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"identity:{username or realm}",
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            evidence_text = _clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)
            if evidence_text:
                evidence_node_id, changed = _upsert_node(
                    session,
                    node_key=f"evidence:credential:{resolved_host_id}:{hashlib.sha1(evidence_text.encode('utf-8')).hexdigest()[:12]}",
                    node_type="evidence_record",
                    label=evidence_text[:120],
                    confidence=100.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:credential:evidence",
                    properties={"host_id": resolved_host_id, "evidence": evidence_text, "entity_type": "credential"},
                )
                if changed:
                    _remember_mutation(mutations, "node", evidence_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="derived_from",
                    from_node_id=cred_node_id,
                    to_node_id=evidence_node_id,
                    confidence=100.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"host:{resolved_host_id}:credential:evidence",
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)

        for item in list(context.get("sessions", []) or []):
            if not isinstance(item, dict):
                continue
            username = _clean_text(item.get("username", ""), limit=160, allow_unknown=True)
            pivot_host = _clean_text(item.get("host", ""), limit=160, allow_unknown=True)
            session_port = _clean_text(item.get("port", ""), limit=20, allow_unknown=True)
            session_protocol = _clean_text(item.get("protocol", ""), limit=12, lower=True, allow_unknown=True)
            session_type = _clean_text(item.get("session_type", ""), limit=64, lower=True, allow_unknown=True)
            if not any([username, pivot_host, session_type]):
                continue
            session_node_id, changed = _upsert_node(
                session,
                node_key=f"session:{resolved_host_id}:{session_type}:{username.lower()}:{pivot_host.lower()}:{session_port}/{session_protocol}",
                node_type="session",
                label=session_type or username or pivot_host,
                confidence=_safe_float(item.get("confidence", 78.0), 78.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:session:{session_type}:{username}",
                properties={
                    "host_id": resolved_host_id,
                    "session_type": session_type,
                    "username": username,
                    "host": pivot_host,
                    "port": session_port,
                    "protocol": session_protocol,
                    "obtained_at": _clean_text(item.get("obtained_at", ""), limit=64, allow_unknown=True),
                },
                evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
            )
            if changed:
                _remember_mutation(mutations, "node", session_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=session_node_id,
                confidence=_safe_float(item.get("confidence", 78.0), 78.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:session:{session_type}:{username}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            identity_node_id, changed = _upsert_node(
                session,
                node_key=f"identity:{username.lower()}",
                node_type="identity",
                label=username or session_type,
                confidence=_safe_float(item.get("confidence", 78.0), 78.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"identity:{username}",
                properties={"username": username},
            )
            if changed:
                _remember_mutation(mutations, "node", identity_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="authenticated_as",
                from_node_id=session_node_id,
                to_node_id=identity_node_id,
                confidence=_safe_float(item.get("confidence", 78.0), 78.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"identity:{username}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            if pivot_host:
                pivot_node_id, changed = _upsert_node(
                    session,
                    node_key=f"host:pivot:{pivot_host.lower()}",
                    node_type="host",
                    label=pivot_host,
                    confidence=_safe_float(item.get("confidence", 68.0), 68.0),
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"pivot:{pivot_host}",
                    properties={"ip": pivot_host},
                )
                if changed:
                    _remember_mutation(mutations, "node", pivot_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="pivoted_to",
                    from_node_id=session_node_id,
                    to_node_id=pivot_node_id,
                    confidence=_safe_float(item.get("confidence", 78.0), 78.0),
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"pivot:{pivot_host}",
                    evidence_refs=[_clean_text(item.get("evidence", ""), limit=320, allow_unknown=True)],
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)

        artifact_nodes: Dict[str, str] = {}
        for item in list(context.get("artifacts", []) or []):
            if not isinstance(item, dict):
                continue
            ref = _clean_text(item.get("ref", ""), limit=320, allow_unknown=True)
            if not ref:
                continue
            artifact_node_id, changed = _upsert_node(
                session,
                node_key=f"artifact:{resolved_host_id}:{ref}",
                node_type="artifact",
                label=ref.split("/")[-1] or ref,
                confidence=_safe_float(item.get("confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"artifact:{ref}",
                properties={
                    "host_id": resolved_host_id,
                    "ref": ref,
                    "kind": _clean_text(item.get("kind", ""), limit=64, lower=True, allow_unknown=True),
                    "tool_id": _clean_text(item.get("tool_id", ""), limit=96, lower=True, allow_unknown=True),
                    "port": _clean_text(item.get("port", ""), limit=20, allow_unknown=True),
                    "protocol": _clean_text(item.get("protocol", "tcp"), limit=12, lower=True, allow_unknown=True),
                },
            )
            artifact_nodes[ref] = artifact_node_id
            if changed:
                _remember_mutation(mutations, "node", artifact_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=artifact_node_id,
                confidence=_safe_float(item.get("confidence", 90.0), 90.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"artifact:{ref}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)

        for item in list(context.get("screenshots", []) or []):
            if not isinstance(item, dict):
                continue
            artifact_ref = _clean_text(item.get("artifact_ref", ""), limit=320, allow_unknown=True)
            if not artifact_ref:
                continue
            screenshot_node_id, changed = _upsert_node(
                session,
                node_key=f"screenshot:{resolved_host_id}:{artifact_ref}",
                node_type="screenshot",
                label=_clean_text(item.get("filename", ""), limit=200, allow_unknown=True) or artifact_ref.split("/")[-1] or artifact_ref,
                confidence=_safe_float(item.get("confidence", 96.0), 96.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"screenshot:{artifact_ref}",
                properties={
                    "host_id": resolved_host_id,
                    "artifact_ref": artifact_ref,
                    "filename": _clean_text(item.get("filename", ""), limit=200, allow_unknown=True),
                    "port": _clean_text(item.get("port", ""), limit=20, allow_unknown=True),
                    "protocol": _clean_text(item.get("protocol", "tcp"), limit=12, lower=True, allow_unknown=True),
                },
            )
            if changed:
                _remember_mutation(mutations, "node", screenshot_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="captured",
                from_node_id=host_node_id,
                to_node_id=screenshot_node_id,
                confidence=_safe_float(item.get("confidence", 96.0), 96.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"screenshot:{artifact_ref}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            artifact_node_id = artifact_nodes.get(artifact_ref)
            if artifact_node_id:
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="captured",
                    from_node_id=artifact_node_id,
                    to_node_id=screenshot_node_id,
                    confidence=96.0,
                    source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                    source_ref=f"screenshot:{artifact_ref}",
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)

        for item in list(context.get("attempted_actions", []) or []):
            if not isinstance(item, dict):
                continue
            tool_id = _clean_text(item.get("tool_id", ""), limit=96, lower=True, allow_unknown=True)
            if not tool_id:
                continue
            action_port = _clean_text(item.get("port", ""), limit=20, allow_unknown=True)
            action_protocol = _clean_text(item.get("protocol", "tcp"), limit=12, lower=True, allow_unknown=True) or "tcp"
            action_node_id, changed = _upsert_node(
                session,
                node_key=f"action:{host_ip}:{tool_id}:{action_port}:{action_protocol}",
                node_type="action",
                label=_clean_text(item.get("label", ""), limit=140, allow_unknown=True) or tool_id,
                confidence=_safe_float(item.get("confidence", 94.0), 94.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:action:{tool_id}",
                properties={
                    "host_id": resolved_host_id,
                    "tool_id": tool_id,
                    "action_id": _clean_text(item.get("action_id", ""), limit=120, allow_unknown=True),
                    "status": _clean_text(item.get("status", ""), limit=32, lower=True, allow_unknown=True),
                    "attempted_at": _clean_text(item.get("attempted_at", ""), limit=64, allow_unknown=True),
                    "port": action_port,
                    "protocol": action_protocol,
                    "service": _clean_text(item.get("service", ""), limit=64, allow_unknown=True),
                    "origin_mode": _clean_text(item.get("origin_mode", ""), limit=24, lower=True, allow_unknown=True),
                    "approval_state": _clean_text(item.get("approval_state", ""), limit=32, lower=True, allow_unknown=True),
                    "reason": _clean_text(item.get("reason", ""), limit=320, allow_unknown=True),
                    "coverage_gap": _clean_text(item.get("coverage_gap", ""), limit=96, lower=True, allow_unknown=True),
                    "pack_ids": _dedupe_tokens(item.get("pack_ids", []) if isinstance(item.get("pack_ids", []), list) else [], limit=8, token_limit=64),
                },
                evidence_refs=list(item.get("artifact_refs", []) or []),
            )
            if changed:
                _remember_mutation(mutations, "node", action_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="contains",
                from_node_id=host_node_id,
                to_node_id=action_node_id,
                confidence=_safe_float(item.get("confidence", 94.0), 94.0),
                source_kind=_normalize_source_kind(item.get("source_kind", "observed"), "observed"),
                source_ref=f"host:{resolved_host_id}:action:{tool_id}",
                evidence_refs=list(item.get("artifact_refs", []) or []),
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
            for artifact_ref in list(item.get("artifact_refs", []) or []):
                artifact_token = _clean_text(artifact_ref, limit=320, allow_unknown=True)
                if not artifact_token:
                    continue
                artifact_node_id = artifact_nodes.get(artifact_token)
                if not artifact_node_id:
                    artifact_node_id, changed = _upsert_node(
                        session,
                        node_key=f"artifact:{resolved_host_id}:{artifact_token}",
                        node_type="artifact",
                        label=artifact_token.split("/")[-1] or artifact_token,
                        confidence=90.0,
                        source_kind="observed",
                        source_ref=f"artifact:{artifact_token}",
                        properties={"host_id": resolved_host_id, "ref": artifact_token, "tool_id": tool_id},
                    )
                    artifact_nodes[artifact_token] = artifact_node_id
                    if changed:
                        _remember_mutation(mutations, "node", artifact_node_id)
                edge_id, changed = _upsert_edge(
                    session,
                    edge_type="produced",
                    from_node_id=action_node_id,
                    to_node_id=artifact_node_id,
                    confidence=96.0,
                    source_kind="observed",
                    source_ref=f"host:{resolved_host_id}:action:{tool_id}",
                    evidence_refs=[artifact_token],
                )
                if changed:
                    _remember_mutation(mutations, "edge", edge_id)

        for note in list(context.get("notes", []) or []):
            if not isinstance(note, dict):
                continue
            annotation_id, changed = _upsert_annotation(
                session,
                target_kind="node",
                target_ref=host_node_id,
                body=_clean_text(note.get("text", ""), limit=4000, allow_unknown=True),
                created_by="legacy_note_import",
                source_ref=f"note:{int(note.get('id', 0) or 0)}",
            )
            if changed:
                _remember_mutation(mutations, "annotation", annotation_id)

        session.commit()
        return mutations
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def sync_execution_record_to_evidence_graph(
        database,
        *,
        execution_record: Any,
        step: Any = None,
        host_ip: str = "",
        port: str = "",
        protocol: str = "",
        service: str = "",
) -> List[str]:
    if execution_record is None:
        return []
    mutations: List[str] = []
    session = database.session()
    try:
        _ensure_tables(session)
        host_token = _clean_text(host_ip, limit=160, allow_unknown=True)
        if not host_token:
            host_token = _clean_text(getattr(step, "target_ref", {}).get("host_ip", "") if hasattr(step, "target_ref") else "", limit=160, allow_unknown=True)
        if not host_token:
            return []
        host_node_id, changed = _upsert_node(
            session,
            node_key=f"host:{host_token}",
            node_type="host",
            label=host_token,
            confidence=88.0,
            source_kind="observed",
            source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
            properties={"ip": host_token},
        )
        if changed:
            _remember_mutation(mutations, "node", host_node_id)
        tool_id = _clean_text(getattr(getattr(step, "action", None), "tool_id", "") or getattr(step, "tool_id", ""), limit=96, lower=True, allow_unknown=True)
        action_label = _clean_text(getattr(getattr(step, "action", None), "label", "") or getattr(step, "label", ""), limit=140, allow_unknown=True) or tool_id
        action_node_id, changed = _upsert_node(
            session,
            node_key=f"action:{host_token}:{tool_id}:{_clean_text(port, limit=20, allow_unknown=True)}:{_clean_text(protocol or 'tcp', limit=12, lower=True, allow_unknown=True)}",
            node_type="action",
            label=action_label,
            confidence=98.0,
            source_kind="observed",
            source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
            properties={
                "execution_id": _clean_text(getattr(execution_record, "execution_id", ""), limit=80, allow_unknown=True),
                "step_id": _clean_text(getattr(execution_record, "step_id", ""), limit=80, allow_unknown=True),
                "tool_id": tool_id,
                "port": _clean_text(port, limit=20, allow_unknown=True),
                "protocol": _clean_text(protocol or "tcp", limit=12, lower=True, allow_unknown=True),
                "service": _clean_text(service, limit=64, allow_unknown=True),
                "runner_type": _clean_text(getattr(execution_record, "runner_type", ""), limit=32, lower=True, allow_unknown=True),
                "exit_status": _clean_text(getattr(execution_record, "exit_status", ""), limit=160, allow_unknown=True),
                "approval_id": _clean_text(getattr(execution_record, "approval_id", ""), limit=80, allow_unknown=True),
                "started_at": _clean_text(getattr(execution_record, "started_at", ""), limit=64, allow_unknown=True),
                "finished_at": _clean_text(getattr(execution_record, "finished_at", ""), limit=64, allow_unknown=True),
                "origin_mode": _clean_text(getattr(step, "origin_mode", "") or getattr(step, "mode", ""), limit=24, lower=True, allow_unknown=True),
            },
            evidence_refs=list(getattr(step, "linked_evidence_refs", []) or []),
        )
        if changed:
            _remember_mutation(mutations, "node", action_node_id)
        edge_id, changed = _upsert_edge(
            session,
            edge_type="contains",
            from_node_id=host_node_id,
            to_node_id=action_node_id,
            confidence=98.0,
            source_kind="observed",
            source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
            evidence_refs=list(getattr(step, "linked_evidence_refs", []) or []),
        )
        if changed:
            _remember_mutation(mutations, "edge", edge_id)
        for artifact_ref in list(getattr(execution_record, "artifact_refs", []) or []):
            artifact_token = _clean_text(artifact_ref, limit=320, allow_unknown=True)
            if not artifact_token:
                continue
            node_type = "screenshot" if artifact_token.lower().endswith(".png") else "artifact"
            artifact_node_id, changed = _upsert_node(
                session,
                node_key=f"{node_type}:{host_token}:{artifact_token}",
                node_type=node_type,
                label=artifact_token.split("/")[-1] or artifact_token,
                confidence=96.0,
                source_kind="observed",
                source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
                properties={
                    "execution_id": _clean_text(getattr(execution_record, "execution_id", ""), limit=80, allow_unknown=True),
                    "ref": artifact_token,
                    "tool_id": tool_id,
                    "port": _clean_text(port, limit=20, allow_unknown=True),
                    "protocol": _clean_text(protocol or "tcp", limit=12, lower=True, allow_unknown=True),
                },
            )
            if changed:
                _remember_mutation(mutations, "node", artifact_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="produced",
                from_node_id=action_node_id,
                to_node_id=artifact_node_id,
                confidence=96.0,
                source_kind="observed",
                source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
                evidence_refs=[artifact_token],
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
        for ref_name, ref_value in (
                ("stdout", _clean_text(getattr(execution_record, "stdout_ref", ""), limit=320, allow_unknown=True)),
                ("stderr", _clean_text(getattr(execution_record, "stderr_ref", ""), limit=320, allow_unknown=True)),
        ):
            if not ref_value:
                continue
            evidence_node_id, changed = _upsert_node(
                session,
                node_key=f"evidence:execution:{ref_name}:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
                node_type="evidence_record",
                label=ref_value[:120],
                confidence=100.0,
                source_kind="observed",
                source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
                properties={
                    "execution_id": _clean_text(getattr(execution_record, "execution_id", ""), limit=80, allow_unknown=True),
                    "ref_type": ref_name,
                    "ref": ref_value,
                },
            )
            if changed:
                _remember_mutation(mutations, "node", evidence_node_id)
            edge_id, changed = _upsert_edge(
                session,
                edge_type="produced",
                from_node_id=action_node_id,
                to_node_id=evidence_node_id,
                confidence=100.0,
                source_kind="observed",
                source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
                evidence_refs=[ref_value] + list(getattr(step, "linked_evidence_refs", []) or []),
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
        for finding_id in list(getattr(step, "linked_graph_nodes", []) or []):
            target_finding = _clean_text(finding_id, limit=80, allow_unknown=True)
            if not target_finding:
                continue
            edge_id, changed = _upsert_edge(
                session,
                edge_type="validated_by",
                from_node_id=target_finding,
                to_node_id=action_node_id,
                confidence=92.0,
                source_kind="observed",
                source_ref=f"execution:{_clean_text(getattr(execution_record, 'execution_id', ''), limit=80, allow_unknown=True)}",
            )
            if changed:
                _remember_mutation(mutations, "edge", edge_id)
        session.commit()
        return mutations
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def rebuild_evidence_graph(database, *, host_id: Optional[int] = None) -> List[str]:
    ensure_scheduler_graph_tables(database)
    session = database.session()
    try:
        params: Dict[str, Any] = {}
        query = "SELECT id FROM hostObj"
        if host_id is not None:
            query += " WHERE id = :host_id"
            params["host_id"] = int(host_id or 0)
        query += " ORDER BY id ASC"
        host_rows = session.execute(text(query), params).fetchall()
    finally:
        session.close()

    mutations: List[str] = []
    for row in host_rows:
        for token in sync_target_state_to_evidence_graph(database, host_id=int(row[0] or 0)):
            _remember_mutation(mutations, token.split(":", 1)[0], token.split(":", 1)[1] if ":" in token else token)

    session = database.session()
    try:
        _ensure_tables(session)
        query = (
            "SELECT execution_id, step_id, action_id, tool_id, label, scheduler_mode, goal_profile, host_ip, port, protocol, service, "
            "started_at, finished_at, runner_type, exit_status, stdout_ref, stderr_ref, artifact_refs_json, approval_id, "
            "observations_created_json, graph_mutations_json, operator_notes "
            "FROM scheduler_execution_record ORDER BY id ASC"
        )
        rows = session.execute(text(query)).fetchall()
        keys = [
            "execution_id", "step_id", "action_id", "tool_id", "label", "scheduler_mode", "goal_profile", "host_ip", "port", "protocol",
            "service", "started_at", "finished_at", "runner_type", "exit_status", "stdout_ref", "stderr_ref", "artifact_refs_json",
            "approval_id", "observations_created_json", "graph_mutations_json", "operator_notes",
        ]
    except Exception:
        session.close()
        return mutations
    finally:
        try:
            session.close()
        except Exception:
            pass

    for row in rows:
        item = dict(zip(keys, row))
        proxy = type("ExecutionProxy", (), {
            "execution_id": item.get("execution_id", ""),
            "step_id": item.get("step_id", ""),
            "started_at": item.get("started_at", ""),
            "finished_at": item.get("finished_at", ""),
            "runner_type": item.get("runner_type", ""),
            "exit_status": item.get("exit_status", ""),
            "stdout_ref": item.get("stdout_ref", ""),
            "stderr_ref": item.get("stderr_ref", ""),
            "artifact_refs": _from_json(item.get("artifact_refs_json"), []),
            "approval_id": item.get("approval_id", ""),
            "observations_created": _from_json(item.get("observations_created_json"), []),
            "graph_mutations": _from_json(item.get("graph_mutations_json"), []),
            "operator_notes": item.get("operator_notes", ""),
        })()
        step_proxy = type("StepProxy", (), {
            "action": type("ActionProxy", (), {
                "tool_id": item.get("tool_id", ""),
                "label": item.get("label", ""),
            })(),
            "origin_mode": item.get("scheduler_mode", ""),
            "linked_evidence_refs": _dedupe_tokens(_from_json(item.get("observations_created_json"), []), limit=16, token_limit=320),
            "linked_graph_nodes": [],
        })()
        for token in sync_execution_record_to_evidence_graph(
                database,
                execution_record=proxy,
                step=step_proxy,
                host_ip=item.get("host_ip", ""),
                port=item.get("port", ""),
                protocol=item.get("protocol", ""),
                service=item.get("service", ""),
        ):
            _remember_mutation(mutations, token.split(":", 1)[0], token.split(":", 1)[1] if ":" in token else token)
    return mutations


def query_evidence_graph(
        database,
        *,
        node_types: Any = None,
        edge_types: Any = None,
        source_kinds: Any = None,
        min_confidence: float = 0.0,
        search: str = "",
        include_ai_suggested: bool = True,
        hide_nmap_xml_artifacts: bool = False,
        hide_down_hosts: bool = False,
        host_id: Optional[int] = None,
        limit_nodes: int = 600,
        limit_edges: int = 1200,
) -> Dict[str, Any]:
    snapshot = get_evidence_graph_snapshot(database)
    requested_node_types = set(_normalize_filter_list(node_types, limit=24, lower=True))
    requested_edge_types = set(_normalize_filter_list(edge_types, limit=24, lower=True))
    requested_source_kinds = set(_normalize_filter_list(source_kinds, limit=12, lower=True))
    resolved_host_id = int(host_id or 0)
    resolved_search = str(search or "").strip().lower()
    min_conf = _safe_float(min_confidence, default=0.0, minimum=0.0, maximum=100.0)
    max_nodes = max(1, min(int(limit_nodes or 600), 10000))
    max_edges = max(1, min(int(limit_edges or 1200), 30000))
    down_host_ids = _list_down_host_ids(database) if hide_down_hosts else set()

    nodes = []
    for item in list(snapshot.get("nodes", []) or []):
        if not isinstance(item, dict):
            continue
        source_kind = _normalize_source_kind(item.get("source_kind", "observed"), "observed")
        if not include_ai_suggested and source_kind == "ai_suggested":
            continue
        if requested_node_types and str(item.get("type", "") or "").strip().lower() not in requested_node_types:
            continue
        if requested_source_kinds and source_kind not in requested_source_kinds:
            continue
        if float(item.get("confidence", 0.0) or 0.0) < min_conf:
            continue
        item_host_id = int((item.get("properties", {}) or {}).get("host_id", 0) or 0) if isinstance(item.get("properties", {}), dict) else 0
        if down_host_ids and item_host_id in down_host_ids:
            continue
        if _graph_should_hide_artifact_node(item, hide_nmap_xml_artifacts=bool(hide_nmap_xml_artifacts)):
            continue
        if not _node_matches_search(item, resolved_search):
            continue
        nodes.append(dict(item))

    if resolved_host_id > 0:
        base_node_ids = {
            str(item.get("node_id", "") or "")
            for item in nodes
            if isinstance(item.get("properties", {}), dict)
            and int(item.get("properties", {}).get("host_id", 0) or 0) == resolved_host_id
        }
        expanded_ids = set(base_node_ids)
        for edge in list(snapshot.get("edges", []) or []):
            if not isinstance(edge, dict):
                continue
            from_node_id = str(edge.get("from_node_id", "") or "")
            to_node_id = str(edge.get("to_node_id", "") or "")
            if from_node_id in base_node_ids or to_node_id in base_node_ids:
                expanded_ids.add(from_node_id)
                expanded_ids.add(to_node_id)
        if expanded_ids:
            nodes = [item for item in nodes if str(item.get("node_id", "") or "") in expanded_ids]

    node_ids = {str(item.get("node_id", "") or "") for item in nodes}
    edges = []
    for item in list(snapshot.get("edges", []) or []):
        if not isinstance(item, dict):
            continue
        source_kind = _normalize_source_kind(item.get("source_kind", "observed"), "observed")
        if not include_ai_suggested and source_kind == "ai_suggested":
            continue
        if requested_edge_types and str(item.get("type", "") or "").strip().lower() not in requested_edge_types:
            continue
        if requested_source_kinds and source_kind not in requested_source_kinds:
            continue
        if float(item.get("confidence", 0.0) or 0.0) < min_conf:
            continue
        if not _edge_matches_search(item, resolved_search):
            continue
        if str(item.get("from_node_id", "") or "") not in node_ids or str(item.get("to_node_id", "") or "") not in node_ids:
            continue
        edges.append(dict(item))

    nodes = nodes[:max_nodes]
    node_ids = {str(item.get("node_id", "") or "") for item in nodes}
    edges = [
        item for item in edges
        if str(item.get("from_node_id", "") or "") in node_ids and str(item.get("to_node_id", "") or "") in node_ids
    ][:max_edges]

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "total_nodes": len(snapshot.get("nodes", []) or []),
            "total_edges": len(snapshot.get("edges", []) or []),
            "returned_nodes": len(nodes),
            "returned_edges": len(edges),
            "filters": {
                "node_types": sorted(requested_node_types),
                "edge_types": sorted(requested_edge_types),
                "source_kinds": sorted(requested_source_kinds),
                "min_confidence": min_conf,
                "search": resolved_search,
                "include_ai_suggested": bool(include_ai_suggested),
                "hide_nmap_xml_artifacts": bool(hide_nmap_xml_artifacts),
                "hide_down_hosts": bool(hide_down_hosts),
                "host_id": int(resolved_host_id or 0) or None,
                "limit_nodes": max_nodes,
                "limit_edges": max_edges,
            },
        },
    }


def _list_down_host_ids(database) -> set:
    session = database.session()
    try:
        rows = session.execute(text(
            "SELECT id FROM hostObj WHERE LOWER(TRIM(COALESCE(status, ''))) = 'down'"
        )).fetchall()
        host_ids = set()
        for row in rows:
            try:
                host_id = int(row[0] or 0)
            except (TypeError, ValueError, IndexError):
                host_id = 0
            if host_id > 0:
                host_ids.add(host_id)
        return host_ids
    finally:
        session.close()


def _list_evidence_refs(session) -> Dict[str, List[str]]:
    result = session.execute(text(
        "SELECT owner_kind, owner_id, evidence_ref FROM graph_evidence_ref ORDER BY id ASC"
    ))
    grouped: Dict[str, List[str]] = {}
    for row in result.fetchall():
        key = f"{_clean_text(row[0], limit=16, lower=True, allow_unknown=True)}:{_clean_text(row[1], limit=80, allow_unknown=True)}"
        grouped.setdefault(key, []).append(_clean_text(row[2], limit=320, allow_unknown=True))
    return grouped


def get_evidence_graph_snapshot(database) -> Dict[str, Any]:
    session = database.session()
    try:
        _ensure_tables(session)
        evidence_map = _list_evidence_refs(session)
        node_result = session.execute(text(
            "SELECT node_id, node_key, type, label, confidence, source_kind, source_ref, first_seen, last_seen, properties_json "
            "FROM graph_node ORDER BY id ASC"
        ))
        nodes = []
        for row in node_result.fetchall():
            node_id = _clean_text(row[0], limit=80, allow_unknown=True)
            nodes.append({
                "node_id": node_id,
                "node_key": _clean_text(row[1], limit=320, allow_unknown=True),
                "type": _clean_text(row[2], limit=80, lower=True, allow_unknown=True),
                "label": _clean_text(row[3], limit=240, allow_unknown=True),
                "confidence": _safe_float(row[4]),
                "source_kind": _normalize_source_kind(row[5], "observed"),
                "source_ref": _clean_text(row[6], limit=320, allow_unknown=True),
                "first_seen": _clean_text(row[7], limit=64, allow_unknown=True),
                "last_seen": _clean_text(row[8], limit=64, allow_unknown=True),
                "properties": _from_json(row[9], {}),
                "evidence_refs": evidence_map.get(f"node:{node_id}", []),
            })
        edge_result = session.execute(text(
            "SELECT edge_id, edge_key, type, from_node_id, to_node_id, confidence, source_kind, source_ref, first_seen, last_seen, properties_json "
            "FROM graph_edge ORDER BY id ASC"
        ))
        edges = []
        for row in edge_result.fetchall():
            edge_id = _clean_text(row[0], limit=80, allow_unknown=True)
            edges.append({
                "edge_id": edge_id,
                "edge_key": _clean_text(row[1], limit=320, allow_unknown=True),
                "type": _clean_text(row[2], limit=80, lower=True, allow_unknown=True),
                "from_node_id": _clean_text(row[3], limit=80, allow_unknown=True),
                "to_node_id": _clean_text(row[4], limit=80, allow_unknown=True),
                "confidence": _safe_float(row[5]),
                "source_kind": _normalize_source_kind(row[6], "observed"),
                "source_ref": _clean_text(row[7], limit=320, allow_unknown=True),
                "first_seen": _clean_text(row[8], limit=64, allow_unknown=True),
                "last_seen": _clean_text(row[9], limit=64, allow_unknown=True),
                "properties": _from_json(row[10], {}),
                "evidence_refs": evidence_map.get(f"edge:{edge_id}", []),
            })
        layouts = list_graph_layout_states(database)
        annotations = list_graph_annotations(database)
        return {
            "nodes": nodes,
            "edges": edges,
            "layouts": layouts,
            "annotations": annotations,
        }
    finally:
        session.close()


def export_evidence_graph_json(database, *, rebuild: bool = False) -> Dict[str, Any]:
    if rebuild:
        rebuild_evidence_graph(database)
    return get_evidence_graph_snapshot(database)


def export_evidence_graph_graphml(database, *, rebuild: bool = False) -> str:
    if rebuild:
        rebuild_evidence_graph(database)
    snapshot = get_evidence_graph_snapshot(database)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <graph edgedefault="directed" id="legion-evidence-graph">',
    ]
    for node in snapshot.get("nodes", []):
        if not isinstance(node, dict):
            continue
        props = _to_json(node.get("properties", {}), {})
        evidence = _to_json(node.get("evidence_refs", []), [])
        lines.extend([
            f'    <node id="{xml_escape(str(node.get("node_id", "")))}">',
            f'      <data key="type">{xml_escape(str(node.get("type", "")))}</data>',
            f'      <data key="label">{xml_escape(str(node.get("label", "")))}</data>',
            f'      <data key="confidence">{xml_escape(str(node.get("confidence", 0.0)))}</data>',
            f'      <data key="source_kind">{xml_escape(str(node.get("source_kind", "")))}</data>',
            f'      <data key="source_ref">{xml_escape(str(node.get("source_ref", "")))}</data>',
            f'      <data key="properties_json">{xml_escape(props)}</data>',
            f'      <data key="evidence_refs_json">{xml_escape(evidence)}</data>',
            '    </node>',
        ])
    for edge in snapshot.get("edges", []):
        if not isinstance(edge, dict):
            continue
        props = _to_json(edge.get("properties", {}), {})
        evidence = _to_json(edge.get("evidence_refs", []), [])
        lines.extend([
            f'    <edge id="{xml_escape(str(edge.get("edge_id", "")))}" '
            f'source="{xml_escape(str(edge.get("from_node_id", "")))}" '
            f'target="{xml_escape(str(edge.get("to_node_id", "")))}">',
            f'      <data key="type">{xml_escape(str(edge.get("type", "")))}</data>',
            f'      <data key="confidence">{xml_escape(str(edge.get("confidence", 0.0)))}</data>',
            f'      <data key="source_kind">{xml_escape(str(edge.get("source_kind", "")))}</data>',
            f'      <data key="source_ref">{xml_escape(str(edge.get("source_ref", "")))}</data>',
            f'      <data key="properties_json">{xml_escape(props)}</data>',
            f'      <data key="evidence_refs_json">{xml_escape(evidence)}</data>',
            '    </edge>',
        ])
    lines.extend([
        '  </graph>',
        '</graphml>',
    ])
    return "\n".join(lines)
