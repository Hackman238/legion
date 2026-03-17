import datetime
import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import text

from app.scheduler.approvals import ensure_scheduler_approval_table, list_pending_approvals
from app.scheduler.audit import ensure_scheduler_audit_table
from app.scheduler.execution import ensure_scheduler_execution_table, list_execution_records
from app.scheduler.graph import ensure_scheduler_graph_tables, get_evidence_graph_snapshot
from app.scheduler.state import ensure_scheduler_target_state_table, get_target_state


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return int(default)


def _csv_tokens(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item or "").strip() for item in list(value or []) if str(item or "").strip()]
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _normalize_source_kind(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"observed", "inferred", "ai_suggested", "user_entered", "operator", "manual"}:
        return normalized
    if normalized in {"manual_note", "annotation"}:
        return "operator"
    return "observed"


def _provenance_bucket(value: Any) -> str:
    source_kind = _normalize_source_kind(value)
    if source_kind == "observed":
        return "observed_facts"
    if source_kind == "inferred":
        return "inferred_relationships"
    if source_kind == "ai_suggested":
        return "ai_suggestions"
    return "operator_conclusions"


def _dedupe_tokens(values: Iterable[Any], limit: int = 200) -> List[str]:
    seen = set()
    items: List[str] = []
    for item in list(values or []):
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        items.append(token)
        if len(items) >= limit:
            break
    return items


def _stable_json_key(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except Exception:
        return str(value)


def _dedupe_dicts(rows: Iterable[Dict[str, Any]], limit: int = 500) -> List[Dict[str, Any]]:
    seen = set()
    items: List[Dict[str, Any]] = []
    for row in list(rows or []):
        if not isinstance(row, dict):
            continue
        key = _stable_json_key(row)
        if key in seen:
            continue
        seen.add(key)
        items.append(dict(row))
        if len(items) >= limit:
            break
    return items


def _bucket_append(buckets: Dict[str, List[Dict[str, Any]]], item: Dict[str, Any]):
    if not isinstance(item, dict):
        return
    bucket = _provenance_bucket(item.get("source_kind", "observed"))
    buckets.setdefault(bucket, []).append(item)


def _load_cves(database, host_id: int = 0) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        query = (
            "SELECT id, name, severity, product, version, url, source, exploitId, exploit, exploitUrl, hostId "
            "FROM cve"
        )
        params: Dict[str, Any] = {}
        if int(host_id or 0) > 0:
            query += " WHERE hostId = :host_id"
            params["host_id"] = str(host_id)
        query += " ORDER BY id DESC"
        result = session.execute(text(query), params)
        rows = result.fetchall()
        keys = result.keys()
        return [dict(zip(keys, row)) for row in rows]
    except Exception:
        return []
    finally:
        session.close()


def _load_notes(database, host_id: int = 0) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        query = "SELECT id, hostId, text FROM note"
        params: Dict[str, Any] = {}
        if int(host_id or 0) > 0:
            query += " WHERE hostId = :host_id"
            params["host_id"] = int(host_id)
        query += " ORDER BY id DESC"
        result = session.execute(text(query), params)
        rows = result.fetchall()
        keys = result.keys()
        return [dict(zip(keys, row)) for row in rows]
    except Exception:
        return []
    finally:
        session.close()


def _load_audit_rows(database, host_ip: str = "", limit: int = 800) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        ensure_scheduler_audit_table(database)
        query = (
            "SELECT id, timestamp, host_ip, port, protocol, service, scheduler_mode, goal_profile, "
            "engagement_preset, tool_id, label, command_family_id, danger_categories, risk_tags, requires_approval, "
            "policy_decision, policy_reason, risk_summary, safer_alternative, family_policy_state, approved, "
            "executed, reason, rationale, approval_id "
            "FROM scheduler_decision_log"
        )
        params: Dict[str, Any] = {"limit": max(1, min(int(limit or 800), 5000))}
        if str(host_ip or "").strip():
            query += " WHERE host_ip = :host_ip"
            params["host_ip"] = str(host_ip or "").strip()
        query += " ORDER BY id DESC LIMIT :limit"
        result = session.execute(text(query), params)
        rows = result.fetchall()
        keys = result.keys()
        return [dict(zip(keys, row)) for row in rows]
    except Exception:
        return []
    finally:
        session.close()


def _host_matches_node(node: Dict[str, Any], host_id: int, host_ip: str) -> bool:
    properties = node.get("properties", {}) if isinstance(node.get("properties", {}), dict) else {}
    if int(host_id or 0) > 0 and _safe_int(properties.get("host_id", 0)) == int(host_id):
        return True
    resolved_host_ip = str(host_ip or "").strip()
    if not resolved_host_ip:
        return False
    if str(properties.get("ip", "") or "").strip() == resolved_host_ip:
        return True
    if str(node.get("type", "") or "").strip().lower() == "host" and str(node.get("label", "") or "").strip() == resolved_host_ip:
        return True
    return False


def _filter_graph_snapshot(snapshot: Dict[str, Any], host_id: int = 0, host_ip: str = "") -> Dict[str, Any]:
    if int(host_id or 0) <= 0 and not str(host_ip or "").strip():
        return {
            "nodes": list(snapshot.get("nodes", []) or []),
            "edges": list(snapshot.get("edges", []) or []),
            "annotations": list(snapshot.get("annotations", []) or []),
        }

    nodes = [item for item in list(snapshot.get("nodes", []) or []) if isinstance(item, dict)]
    edges = [item for item in list(snapshot.get("edges", []) or []) if isinstance(item, dict)]
    included = {
        str(item.get("node_id", "") or "")
        for item in nodes
        if _host_matches_node(item, int(host_id or 0), str(host_ip or ""))
    }
    changed = True
    while changed:
        changed = False
        for edge in edges:
            from_id = str(edge.get("from_node_id", "") or "")
            to_id = str(edge.get("to_node_id", "") or "")
            if from_id in included or to_id in included:
                if from_id and from_id not in included:
                    included.add(from_id)
                    changed = True
                if to_id and to_id not in included:
                    included.add(to_id)
                    changed = True
    filtered_nodes = [item for item in nodes if str(item.get("node_id", "") or "") in included]
    filtered_edges = [
        item for item in edges
        if str(item.get("from_node_id", "") or "") in included and str(item.get("to_node_id", "") or "") in included
    ]
    filtered_annotations = []
    for item in list(snapshot.get("annotations", []) or []):
        if not isinstance(item, dict):
            continue
        target_ref = str(item.get("target_ref", "") or "")
        source_ref = str(item.get("source_ref", "") or "")
        if target_ref in included or (int(host_id or 0) > 0 and f"host:{int(host_id)}" in source_ref):
            filtered_annotations.append(dict(item))
    return {
        "nodes": filtered_nodes,
        "edges": filtered_edges,
        "annotations": filtered_annotations,
    }


def _build_attack_paths(snapshot: Dict[str, Any], limit: int = 24) -> List[Dict[str, Any]]:
    nodes_by_id = {
        str(item.get("node_id", "") or ""): dict(item)
        for item in list(snapshot.get("nodes", []) or [])
        if isinstance(item, dict) and str(item.get("node_id", "") or "")
    }
    interesting_types = {
        "authenticated_as",
        "pivoted_to",
        "supports_exploit",
        "affected_by",
        "captured",
        "produced",
        "derived_from",
        "validated_by",
    }
    edges = [
        dict(item)
        for item in list(snapshot.get("edges", []) or [])
        if isinstance(item, dict) and str(item.get("type", "") or "").strip().lower() in interesting_types
    ]
    outgoing: Dict[str, List[Dict[str, Any]]] = {}
    incoming_count: Dict[str, int] = {}
    for edge in edges:
        from_id = str(edge.get("from_node_id", "") or "")
        to_id = str(edge.get("to_node_id", "") or "")
        outgoing.setdefault(from_id, []).append(edge)
        incoming_count[to_id] = incoming_count.get(to_id, 0) + 1

    chains: List[Dict[str, Any]] = []
    seen_chains = set()
    for edge in edges:
        from_id = str(edge.get("from_node_id", "") or "")
        if incoming_count.get(from_id, 0) > 0:
            continue
        chain_edges = [edge]
        used_edge_ids = {str(edge.get("edge_id", "") or "")}
        current_node = str(edge.get("to_node_id", "") or "")
        while len(chain_edges) < 4:
            candidates = [
                item for item in list(outgoing.get(current_node, []) or [])
                if str(item.get("edge_id", "") or "") not in used_edge_ids
            ]
            if not candidates:
                break
            next_edge = sorted(candidates, key=lambda item: -_safe_float(item.get("confidence", 0.0)))[0]
            chain_edges.append(next_edge)
            used_edge_ids.add(str(next_edge.get("edge_id", "") or ""))
            current_node = str(next_edge.get("to_node_id", "") or "")

        chain_key = tuple(str(item.get("edge_id", "") or "") for item in chain_edges)
        if chain_key in seen_chains:
            continue
        seen_chains.add(chain_key)

        sequence: List[Dict[str, Any]] = []
        evidence_refs: List[str] = []
        source_kind = "observed"
        if chain_edges:
            first_node = nodes_by_id.get(str(chain_edges[0].get("from_node_id", "") or ""), {})
            if first_node:
                sequence.append({
                    "node_id": first_node.get("node_id", ""),
                    "type": first_node.get("type", ""),
                    "label": first_node.get("label", ""),
                })
                evidence_refs.extend(list(first_node.get("evidence_refs", []) or []))
                source_kind = _normalize_source_kind(first_node.get("source_kind", source_kind))
        for item in chain_edges:
            to_node = nodes_by_id.get(str(item.get("to_node_id", "") or ""), {})
            edge_source_kind = _normalize_source_kind(item.get("source_kind", source_kind))
            if edge_source_kind != "observed":
                source_kind = edge_source_kind
            evidence_refs.extend(list(item.get("evidence_refs", []) or []))
            if to_node:
                evidence_refs.extend(list(to_node.get("evidence_refs", []) or []))
                if _normalize_source_kind(to_node.get("source_kind", source_kind)) != "observed":
                    source_kind = _normalize_source_kind(to_node.get("source_kind", source_kind))
            sequence.append({
                "edge_type": str(item.get("type", "") or ""),
                "to_node_id": str(item.get("to_node_id", "") or ""),
                "to_type": str(to_node.get("type", "") or ""),
                "to_label": str(to_node.get("label", "") or ""),
            })
        labels = []
        if sequence:
            labels.append(str(sequence[0].get("label", "") or ""))
            for item in sequence[1:]:
                labels.append(f"--{str(item.get('edge_type', '') or '')}-->")
                labels.append(str(item.get("to_label", "") or ""))
        chains.append({
            "summary": " ".join([token for token in labels if token]).strip(),
            "source_kind": source_kind,
            "confidence": min(
                [_safe_float(item.get("confidence", 0.0), 0.0) for item in chain_edges] or [0.0]
            ) if chain_edges else 0.0,
            "sequence": sequence,
            "evidence_refs": _dedupe_tokens(evidence_refs, limit=32),
            "edge_ids": [str(item.get("edge_id", "") or "") for item in chain_edges],
        })
        if len(chains) >= limit:
            break

    if chains:
        return chains

    # Fall back to relationship summaries when no longer chain exists.
    fallback = []
    for edge in edges[:limit]:
        from_node = nodes_by_id.get(str(edge.get("from_node_id", "") or ""), {})
        to_node = nodes_by_id.get(str(edge.get("to_node_id", "") or ""), {})
        fallback.append({
            "summary": (
                f"{str(from_node.get('label', '') or edge.get('from_node_id', ''))} "
                f"--{str(edge.get('type', '') or '')}--> "
                f"{str(to_node.get('label', '') or edge.get('to_node_id', ''))}"
            ).strip(),
            "source_kind": _normalize_source_kind(edge.get("source_kind", "observed")),
            "confidence": _safe_float(edge.get("confidence", 0.0), 0.0),
            "sequence": [
                {
                    "node_id": str(from_node.get("node_id", "") or edge.get("from_node_id", "")),
                    "type": str(from_node.get("type", "") or ""),
                    "label": str(from_node.get("label", "") or edge.get("from_node_id", "")),
                },
                {
                    "edge_type": str(edge.get("type", "") or ""),
                    "to_node_id": str(to_node.get("node_id", "") or edge.get("to_node_id", "")),
                    "to_type": str(to_node.get("type", "") or ""),
                    "to_label": str(to_node.get("label", "") or edge.get("to_node_id", "")),
                },
            ],
            "evidence_refs": _dedupe_tokens(
                list(edge.get("evidence_refs", []) or [])
                + list(from_node.get("evidence_refs", []) or [])
                + list(to_node.get("evidence_refs", []) or []),
                limit=32,
            ),
            "edge_ids": [str(edge.get("edge_id", "") or "")],
        })
    return fallback


def _build_findings_section(
        host_row: Dict[str, Any],
        target_state: Dict[str, Any],
        cves: Sequence[Dict[str, Any]],
        filtered_graph: Dict[str, Any],
) -> Dict[str, Any]:
    host_info = {
        "id": _safe_int(host_row.get("id", 0), 0),
        "ip": str(host_row.get("ip", "") or ""),
        "hostname": str(host_row.get("hostname", "") or ""),
    }
    rows: List[Dict[str, Any]] = []
    for item in list(target_state.get("findings", []) or []):
        if not isinstance(item, dict):
            continue
        rows.append({
            "host": dict(host_info),
            "title": str(item.get("title", "") or ""),
            "severity": str(item.get("severity", "") or ""),
            "cvss": _safe_float(item.get("cvss", 0.0), 0.0),
            "cve": str(item.get("cve", "") or ""),
            "evidence": str(item.get("evidence", "") or ""),
            "confidence": _safe_float(item.get("confidence", 0.0), 0.0),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed")),
        })
    for item in list(cves or []):
        if not isinstance(item, dict):
            continue
        rows.append({
            "host": dict(host_info),
            "title": str(item.get("name", "") or ""),
            "severity": str(item.get("severity", "") or ""),
            "cvss": 0.0,
            "cve": str(item.get("name", "") or ""),
            "evidence": str(item.get("source", "") or ""),
            "confidence": 92.0,
            "source_kind": "observed",
        })
    for node in list(filtered_graph.get("nodes", []) or []):
        if not isinstance(node, dict) or str(node.get("type", "") or "").strip().lower() != "finding":
            continue
        props = node.get("properties", {}) if isinstance(node.get("properties", {}), dict) else {}
        rows.append({
            "host": dict(host_info),
            "title": str(node.get("label", "") or ""),
            "severity": str(props.get("severity", "") or ""),
            "cvss": _safe_float(props.get("cvss", 0.0), 0.0),
            "cve": str(props.get("cve", "") or ""),
            "evidence": ", ".join(_dedupe_tokens(list(node.get("evidence_refs", []) or []), limit=8)),
            "confidence": _safe_float(node.get("confidence", 0.0), 0.0),
            "source_kind": _normalize_source_kind(node.get("source_kind", "observed")),
        })
    deduped = _dedupe_dicts(rows, limit=400)
    grouped = {
        "observed": [item for item in deduped if _normalize_source_kind(item.get("source_kind", "")) == "observed"],
        "inferred": [item for item in deduped if _normalize_source_kind(item.get("source_kind", "")) == "inferred"],
        "ai_suggested": [item for item in deduped if _normalize_source_kind(item.get("source_kind", "")) == "ai_suggested"],
        "operator": [item for item in deduped if _normalize_source_kind(item.get("source_kind", "")) in {"operator", "manual", "user_entered"}],
    }
    return {
        "count": len(deduped),
        "items": deduped,
        "observed": grouped["observed"],
        "inferred": grouped["inferred"],
        "ai_suggested": grouped["ai_suggested"],
        "operator": grouped["operator"],
    }


def _build_credentials_section(target_state: Dict[str, Any], filtered_graph: Dict[str, Any]) -> Dict[str, Any]:
    identities = []
    for node in list(filtered_graph.get("nodes", []) or []):
        if not isinstance(node, dict) or str(node.get("type", "") or "").strip().lower() != "identity":
            continue
        identities.append({
            "label": str(node.get("label", "") or ""),
            "confidence": _safe_float(node.get("confidence", 0.0), 0.0),
            "source_kind": _normalize_source_kind(node.get("source_kind", "observed")),
            "properties": dict(node.get("properties", {}) or {}),
        })
    return {
        "credentials": list(target_state.get("credentials", []) or []),
        "identities": _dedupe_dicts(identities, limit=120),
        "sessions": list(target_state.get("sessions", []) or []),
    }


def _build_evidence_references(
        target_state: Dict[str, Any],
        executions: Sequence[Dict[str, Any]],
        filtered_graph: Dict[str, Any],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in list(target_state.get("screenshots", []) or []):
        if not isinstance(item, dict):
            continue
        rows.append({
            "ref": str(item.get("artifact_ref", "") or item.get("filename", "") or ""),
            "kind": "screenshot",
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed")),
        })
    for item in list(target_state.get("artifacts", []) or []):
        if not isinstance(item, dict):
            continue
        rows.append({
            "ref": str(item.get("ref", "") or ""),
            "kind": str(item.get("kind", "") or "artifact"),
            "tool_id": str(item.get("tool_id", "") or ""),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed")),
        })
    for item in list(executions or []):
        if not isinstance(item, dict):
            continue
        for token in list(item.get("artifact_refs", []) or []):
            rows.append({
                "ref": str(token or ""),
                "kind": "artifact",
                "tool_id": str(item.get("tool_id", "") or ""),
                "source_kind": "observed",
            })
        if str(item.get("stdout_ref", "") or "").strip():
            rows.append({
                "ref": str(item.get("stdout_ref", "") or ""),
                "kind": "stdout",
                "tool_id": str(item.get("tool_id", "") or ""),
                "source_kind": "observed",
            })
        if str(item.get("stderr_ref", "") or "").strip():
            rows.append({
                "ref": str(item.get("stderr_ref", "") or ""),
                "kind": "stderr",
                "tool_id": str(item.get("tool_id", "") or ""),
                "source_kind": "observed",
            })
    for node in list(filtered_graph.get("nodes", []) or []):
        if not isinstance(node, dict):
            continue
        for token in list(node.get("evidence_refs", []) or []):
            rows.append({
                "ref": str(token or ""),
                "kind": "graph_evidence",
                "source_kind": _normalize_source_kind(node.get("source_kind", "observed")),
            })
    for edge in list(filtered_graph.get("edges", []) or []):
        if not isinstance(edge, dict):
            continue
        for token in list(edge.get("evidence_refs", []) or []):
            rows.append({
                "ref": str(token or ""),
                "kind": "graph_evidence",
                "source_kind": _normalize_source_kind(edge.get("source_kind", "observed")),
            })
    return _dedupe_dicts([item for item in rows if str(item.get("ref", "") or "").strip()], limit=400)


def _build_next_steps(
        target_state: Dict[str, Any],
        approvals: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    pending_approvals = [
        {
            "approval_id": _safe_int(item.get("id", 0), 0),
            "target": f"{str(item.get('host_ip', '') or '')}:{str(item.get('port', '') or '')}/{str(item.get('protocol', '') or '')}",
            "tool_id": str(item.get("tool_id", "") or ""),
            "label": str(item.get("label", "") or ""),
            "risk_tags": _csv_tokens(item.get("risk_tags", "")),
            "policy_reason": str(item.get("policy_reason", "") or ""),
            "rationale": str(item.get("rationale", "") or ""),
        }
        for item in list(approvals or [])
        if isinstance(item, dict)
    ]
    return {
        "next_phase": str(target_state.get("next_phase", "") or ""),
        "manual_tests": list(target_state.get("manual_tests", []) or []),
        "coverage_gaps": list(target_state.get("coverage_gaps", []) or []),
        "pending_approvals": pending_approvals,
    }


def _build_policy_actions(decisions: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for item in list(decisions or []):
        if not isinstance(item, dict):
            continue
        policy_decision = str(item.get("policy_decision", "") or "").strip().lower()
        if policy_decision not in {"blocked", "approval_required"}:
            continue
        rows.append({
            "timestamp": str(item.get("timestamp", "") or ""),
            "host_ip": str(item.get("host_ip", "") or ""),
            "port": str(item.get("port", "") or ""),
            "protocol": str(item.get("protocol", "") or ""),
            "tool_id": str(item.get("tool_id", "") or ""),
            "label": str(item.get("label", "") or ""),
            "policy_decision": policy_decision,
            "policy_reason": str(item.get("policy_reason", "") or ""),
            "risk_tags": _csv_tokens(item.get("risk_tags", "")),
            "reason": str(item.get("reason", "") or ""),
            "safer_alternative": str(item.get("safer_alternative", "") or ""),
        })
    return _dedupe_dicts(rows, limit=240)


def _build_methodology_coverage(
        target_state: Dict[str, Any],
        executions: Sequence[Dict[str, Any]],
        decisions: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    attempted_actions = list(target_state.get("attempted_actions", []) or [])
    executed_tools = _dedupe_tokens(
        [item.get("tool_id", "") for item in executions if isinstance(item, dict)],
        limit=240,
    )
    packs_seen = _dedupe_tokens(
        [
            token
            for item in attempted_actions
            if isinstance(item, dict)
            for token in list(item.get("pack_ids", []) or [])
        ],
        limit=120,
    )
    runner_usage = {}
    for item in list(executions or []):
        if not isinstance(item, dict):
            continue
        runner_type = str(item.get("runner_type", "") or "local").strip().lower() or "local"
        runner_usage[runner_type] = runner_usage.get(runner_type, 0) + 1
    decision_modes = _dedupe_tokens(
        [item.get("scheduler_mode", "") for item in decisions if isinstance(item, dict)],
        limit=16,
    )
    return {
        "last_mode": str(target_state.get("last_mode", "") or ""),
        "next_phase": str(target_state.get("next_phase", "") or ""),
        "attempted_action_count": len(attempted_actions),
        "executed_tool_ids": executed_tools,
        "strategy_packs_seen": packs_seen,
        "coverage_gaps": list(target_state.get("coverage_gaps", []) or []),
        "runner_usage": runner_usage,
        "decision_modes": decision_modes,
    }


def _build_provenance_buckets(
        host_row: Dict[str, Any],
        target_state: Dict[str, Any],
        filtered_graph: Dict[str, Any],
        notes: Sequence[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    buckets = {
        "observed_facts": [],
        "inferred_relationships": [],
        "ai_suggestions": [],
        "operator_conclusions": [],
    }
    host_label = str(host_row.get("hostname", "") or host_row.get("ip", "") or "")
    for item in list(target_state.get("technologies", []) or []):
        if not isinstance(item, dict):
            continue
        _bucket_append(buckets, {
            "kind": "technology",
            "host": host_label,
            "label": str(item.get("name", "") or ""),
            "summary": str(item.get("evidence", "") or ""),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed")),
            "confidence": _safe_float(item.get("confidence", 0.0), 0.0),
        })
    for item in list(target_state.get("findings", []) or []):
        if not isinstance(item, dict):
            continue
        _bucket_append(buckets, {
            "kind": "finding",
            "host": host_label,
            "label": str(item.get("title", "") or ""),
            "summary": str(item.get("evidence", "") or ""),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed")),
            "confidence": _safe_float(item.get("confidence", 0.0), 0.0),
        })
    for item in list(target_state.get("manual_tests", []) or []):
        if not isinstance(item, dict):
            continue
        _bucket_append(buckets, {
            "kind": "manual_test",
            "host": host_label,
            "label": str(item.get("why", "") or item.get("command", "") or ""),
            "summary": str(item.get("command", "") or ""),
            "source_kind": _normalize_source_kind(item.get("source_kind", "ai_suggested")),
            "confidence": _safe_float(item.get("confidence", 0.0), 0.0),
        })
    for item in list(target_state.get("coverage_gaps", []) or []):
        if not isinstance(item, dict):
            continue
        _bucket_append(buckets, {
            "kind": "coverage_gap",
            "host": host_label,
            "label": str(item.get("gap_id", "") or ""),
            "summary": str(item.get("description", "") or ""),
            "source_kind": _normalize_source_kind(item.get("source_kind", "inferred")),
            "confidence": _safe_float(item.get("confidence", 0.0), 0.0),
        })
    for node in list(filtered_graph.get("nodes", []) or []):
        if not isinstance(node, dict):
            continue
        _bucket_append(buckets, {
            "kind": f"graph_node:{str(node.get('type', '') or '')}",
            "host": host_label,
            "label": str(node.get("label", "") or node.get("node_id", "") or ""),
            "summary": str(node.get("source_ref", "") or ""),
            "source_kind": _normalize_source_kind(node.get("source_kind", "observed")),
            "confidence": _safe_float(node.get("confidence", 0.0), 0.0),
            "evidence_refs": list(node.get("evidence_refs", []) or []),
        })
    for edge in list(filtered_graph.get("edges", []) or []):
        if not isinstance(edge, dict):
            continue
        _bucket_append(buckets, {
            "kind": f"graph_edge:{str(edge.get('type', '') or '')}",
            "host": host_label,
            "label": str(edge.get("type", "") or ""),
            "summary": (
                f"{str(edge.get('from_node_id', '') or '')} -> {str(edge.get('to_node_id', '') or '')}"
            ),
            "source_kind": _normalize_source_kind(edge.get("source_kind", "observed")),
            "confidence": _safe_float(edge.get("confidence", 0.0), 0.0),
            "evidence_refs": list(edge.get("evidence_refs", []) or []),
        })
    for item in list(notes or []):
        if not isinstance(item, dict):
            continue
        _bucket_append(buckets, {
            "kind": "operator_note",
            "host": host_label,
            "label": f"Note #{_safe_int(item.get('id', 0), 0)}",
            "summary": str(item.get("text", "") or ""),
            "source_kind": "operator",
            "confidence": 100.0,
        })
    for item in list(filtered_graph.get("annotations", []) or []):
        if not isinstance(item, dict):
            continue
        _bucket_append(buckets, {
            "kind": "annotation",
            "host": host_label,
            "label": str(item.get("target_ref", "") or ""),
            "summary": str(item.get("body", "") or ""),
            "source_kind": "operator",
            "confidence": 100.0,
        })
    for key in list(buckets.keys()):
        buckets[key] = _dedupe_dicts(buckets[key], limit=200)
    return buckets


def build_host_report(
        database,
        *,
        host_row: Dict[str, Any],
        engagement_policy: Optional[Dict[str, Any]] = None,
        project_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ensure_scheduler_target_state_table(database)
    ensure_scheduler_execution_table(database)
    ensure_scheduler_graph_tables(database)
    ensure_scheduler_audit_table(database)
    ensure_scheduler_approval_table(database)

    resolved_host = dict(host_row or {})
    host_id = _safe_int(resolved_host.get("id", 0), 0)
    host_ip = str(resolved_host.get("ip", "") or "")
    target_state = get_target_state(database, host_id) or {}
    graph_snapshot = _filter_graph_snapshot(get_evidence_graph_snapshot(database), host_id=host_id, host_ip=host_ip)
    all_executions = list_execution_records(database, limit=1000)
    executions = [
        item for item in list(all_executions or [])
        if isinstance(item, dict) and str(item.get("host_ip", "") or "") == host_ip
    ]
    decisions = _load_audit_rows(database, host_ip=host_ip, limit=1200)
    cves = _load_cves(database, host_id=host_id)
    notes = _load_notes(database, host_id=host_id)
    approvals = [
        item for item in list(list_pending_approvals(database, limit=400, status="pending") or [])
        if isinstance(item, dict) and str(item.get("host_ip", "") or "") == host_ip
    ]
    findings = _build_findings_section(resolved_host, target_state, cves, graph_snapshot)
    credentials_and_sessions = _build_credentials_section(target_state, graph_snapshot)
    evidence_references = _build_evidence_references(target_state, executions, graph_snapshot)
    recommended_next_steps = _build_next_steps(target_state, approvals)
    policy_actions = _build_policy_actions(decisions)
    methodology_coverage = _build_methodology_coverage(target_state, executions, decisions)
    provenance = _build_provenance_buckets(resolved_host, target_state, graph_snapshot, notes)

    service_inventory = list(target_state.get("service_inventory", []) or [])
    urls = list(target_state.get("urls", []) or [])
    technologies = list(target_state.get("technologies", []) or [])
    screenshots = list(target_state.get("screenshots", []) or [])
    artifacts = list(target_state.get("artifacts", []) or [])
    attack_paths = _build_attack_paths(graph_snapshot)

    return {
        "generated_at": _utc_now(),
        "report_version": 2,
        "report_kind": "host",
        "project": dict(project_metadata or {}),
        "host": {
            "id": host_id,
            "ip": host_ip,
            "hostname": str(resolved_host.get("hostname", "") or ""),
            "status": str(resolved_host.get("status", "") or ""),
            "os": str(resolved_host.get("os", "") or ""),
        },
        "scope_and_policy": {
            "scope": [host_ip] if host_ip else [],
            "engagement_policy": dict(engagement_policy or {}),
        },
        "summary_of_discovered_assets": {
            "service_count": len(service_inventory),
            "url_count": len(urls),
            "technology_count": len(technologies),
            "finding_count": int(findings.get("count", 0) or 0),
            "credential_count": len(credentials_and_sessions.get("credentials", [])),
            "identity_count": len(credentials_and_sessions.get("identities", [])),
            "session_count": len(credentials_and_sessions.get("sessions", [])),
            "screenshot_count": len(screenshots),
            "artifact_count": len(artifacts),
            "services": service_inventory,
            "urls": urls,
            "technologies": technologies,
            "screenshots": screenshots,
        },
        "validated_findings": findings,
        "attack_paths": attack_paths,
        "credentials_and_sessions": credentials_and_sessions,
        "evidence_references": evidence_references,
        "recommended_next_steps": recommended_next_steps,
        "skipped_or_blocked_actions": policy_actions,
        "methodology_coverage": methodology_coverage,
        "execution_ledger": {
            "count": len(executions),
            "recent_executions": executions[:40],
        },
        "graph_overview": {
            "node_count": len(list(graph_snapshot.get("nodes", []) or [])),
            "edge_count": len(list(graph_snapshot.get("edges", []) or [])),
            "annotation_count": len(list(graph_snapshot.get("annotations", []) or [])),
        },
        "observed_facts": provenance["observed_facts"],
        "inferred_relationships": provenance["inferred_relationships"],
        "ai_suggestions": provenance["ai_suggestions"],
        "operator_conclusions": provenance["operator_conclusions"],
    }


def build_project_report(
        database,
        *,
        project_metadata: Optional[Dict[str, Any]] = None,
        engagement_policy: Optional[Dict[str, Any]] = None,
        summary: Optional[Dict[str, Any]] = None,
        host_inventory: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    ensure_scheduler_target_state_table(database)
    ensure_scheduler_execution_table(database)
    ensure_scheduler_graph_tables(database)
    ensure_scheduler_audit_table(database)
    ensure_scheduler_approval_table(database)

    hosts = [dict(item) for item in list(host_inventory or []) if isinstance(item, dict)]
    host_reports = [
        build_host_report(
            database,
            host_row=item,
            engagement_policy=engagement_policy,
            project_metadata=project_metadata,
        )
        for item in hosts
    ]
    graph_snapshot = get_evidence_graph_snapshot(database)
    executions = list_execution_records(database, limit=1000)
    decisions = _load_audit_rows(database, limit=2000)
    approvals = list_pending_approvals(database, limit=600, status="pending")

    summary_assets = {
        "host_count": len(host_reports),
        "service_count": sum(int(item.get("summary_of_discovered_assets", {}).get("service_count", 0) or 0) for item in host_reports),
        "url_count": sum(int(item.get("summary_of_discovered_assets", {}).get("url_count", 0) or 0) for item in host_reports),
        "technology_count": sum(int(item.get("summary_of_discovered_assets", {}).get("technology_count", 0) or 0) for item in host_reports),
        "finding_count": sum(int(item.get("validated_findings", {}).get("count", 0) or 0) for item in host_reports),
        "credential_count": sum(len(item.get("credentials_and_sessions", {}).get("credentials", [])) for item in host_reports),
        "identity_count": sum(len(item.get("credentials_and_sessions", {}).get("identities", [])) for item in host_reports),
        "session_count": sum(len(item.get("credentials_and_sessions", {}).get("sessions", [])) for item in host_reports),
        "screenshot_count": sum(int(item.get("summary_of_discovered_assets", {}).get("screenshot_count", 0) or 0) for item in host_reports),
        "artifact_count": sum(int(item.get("summary_of_discovered_assets", {}).get("artifact_count", 0) or 0) for item in host_reports),
        "hosts": [
            {
                "host": dict(item.get("host", {}) or {}),
                "finding_count": int(item.get("validated_findings", {}).get("count", 0) or 0),
                "credential_count": len(item.get("credentials_and_sessions", {}).get("credentials", [])),
                "session_count": len(item.get("credentials_and_sessions", {}).get("sessions", [])),
                "next_phase": str(item.get("recommended_next_steps", {}).get("next_phase", "") or ""),
            }
            for item in host_reports
        ],
    }

    findings_rows = _dedupe_dicts(
        [
            finding
            for report in host_reports
            for finding in list(report.get("validated_findings", {}).get("items", []) or [])
        ],
        limit=1200,
    )
    grouped_findings = {
        "observed": [item for item in findings_rows if _normalize_source_kind(item.get("source_kind", "")) == "observed"],
        "inferred": [item for item in findings_rows if _normalize_source_kind(item.get("source_kind", "")) == "inferred"],
        "ai_suggested": [item for item in findings_rows if _normalize_source_kind(item.get("source_kind", "")) == "ai_suggested"],
        "operator": [item for item in findings_rows if _normalize_source_kind(item.get("source_kind", "")) in {"operator", "manual", "user_entered"}],
    }

    credentials = _dedupe_dicts(
        [
            item
            for report in host_reports
            for item in list(report.get("credentials_and_sessions", {}).get("credentials", []) or [])
            if isinstance(item, dict)
        ],
        limit=400,
    )
    identities = _dedupe_dicts(
        [
            item
            for report in host_reports
            for item in list(report.get("credentials_and_sessions", {}).get("identities", []) or [])
            if isinstance(item, dict)
        ],
        limit=400,
    )
    sessions = _dedupe_dicts(
        [
            item
            for report in host_reports
            for item in list(report.get("credentials_and_sessions", {}).get("sessions", []) or [])
            if isinstance(item, dict)
        ],
        limit=400,
    )
    attack_paths = _build_attack_paths(graph_snapshot)
    evidence_references = _dedupe_dicts(
        [
            item
            for report in host_reports
            for item in list(report.get("evidence_references", []) or [])
            if isinstance(item, dict)
        ],
        limit=1200,
    )
    next_steps = {
        "next_phases": _dedupe_tokens(
            [report.get("recommended_next_steps", {}).get("next_phase", "") for report in host_reports],
            limit=80,
        ),
        "manual_tests": _dedupe_dicts(
            [
                item
                for report in host_reports
                for item in list(report.get("recommended_next_steps", {}).get("manual_tests", []) or [])
                if isinstance(item, dict)
            ],
            limit=400,
        ),
        "coverage_gaps": _dedupe_dicts(
            [
                item
                for report in host_reports
                for item in list(report.get("recommended_next_steps", {}).get("coverage_gaps", []) or [])
                if isinstance(item, dict)
            ],
            limit=240,
        ),
        "pending_approvals": [
            {
                "approval_id": _safe_int(item.get("id", 0), 0),
                "host_ip": str(item.get("host_ip", "") or ""),
                "tool_id": str(item.get("tool_id", "") or ""),
                "label": str(item.get("label", "") or ""),
                "policy_reason": str(item.get("policy_reason", "") or ""),
            }
            for item in list(approvals or [])
            if isinstance(item, dict)
        ],
    }
    methodology_coverage = {
        "strategy_packs_seen": _dedupe_tokens(
            [
                token
                for report in host_reports
                for token in list(report.get("methodology_coverage", {}).get("strategy_packs_seen", []) or [])
            ],
            limit=200,
        ),
        "coverage_gaps": next_steps["coverage_gaps"],
        "runner_usage": {},
        "decision_modes": _dedupe_tokens([item.get("scheduler_mode", "") for item in decisions], limit=16),
        "attempted_action_count": sum(
            int(report.get("methodology_coverage", {}).get("attempted_action_count", 0) or 0)
            for report in host_reports
        ),
    }
    for report in host_reports:
        for runner_type, count in dict(report.get("methodology_coverage", {}).get("runner_usage", {}) or {}).items():
            key = str(runner_type or "local").strip().lower() or "local"
            methodology_coverage["runner_usage"][key] = methodology_coverage["runner_usage"].get(key, 0) + int(count or 0)

    provenance = {
        "observed_facts": _dedupe_dicts(
            [item for report in host_reports for item in list(report.get("observed_facts", []) or [])],
            limit=600,
        ),
        "inferred_relationships": _dedupe_dicts(
            [item for report in host_reports for item in list(report.get("inferred_relationships", []) or [])],
            limit=600,
        ),
        "ai_suggestions": _dedupe_dicts(
            [item for report in host_reports for item in list(report.get("ai_suggestions", []) or [])],
            limit=600,
        ),
        "operator_conclusions": _dedupe_dicts(
            [item for report in host_reports for item in list(report.get("operator_conclusions", []) or [])],
            limit=600,
        ),
    }

    return {
        "generated_at": _utc_now(),
        "report_version": 2,
        "report_kind": "project",
        "project": dict(project_metadata or {}),
        "scope_and_policy": {
            "project": dict(project_metadata or {}),
            "engagement_policy": dict(engagement_policy or {}),
        },
        "summary": dict(summary or {}),
        "summary_of_discovered_assets": summary_assets,
        "validated_findings": {
            "count": len(findings_rows),
            "items": findings_rows,
            "observed": grouped_findings["observed"],
            "inferred": grouped_findings["inferred"],
            "ai_suggested": grouped_findings["ai_suggested"],
            "operator": grouped_findings["operator"],
        },
        "attack_paths": attack_paths,
        "credentials_and_sessions": {
            "credentials": credentials,
            "identities": identities,
            "sessions": sessions,
        },
        "evidence_references": evidence_references,
        "recommended_next_steps": next_steps,
        "skipped_or_blocked_actions": _build_policy_actions(decisions),
        "methodology_coverage": methodology_coverage,
        "execution_ledger": {
            "count": len(executions),
            "recent_executions": executions[:80],
        },
        "graph_overview": {
            "node_count": len(list(graph_snapshot.get("nodes", []) or [])),
            "edge_count": len(list(graph_snapshot.get("edges", []) or [])),
            "annotation_count": len(list(graph_snapshot.get("annotations", []) or [])),
        },
        "hosts": summary_assets["hosts"],
        "observed_facts": provenance["observed_facts"],
        "inferred_relationships": provenance["inferred_relationships"],
        "ai_suggestions": provenance["ai_suggestions"],
        "operator_conclusions": provenance["operator_conclusions"],
    }


def _markdown_item_lines(items: Sequence[Dict[str, Any]], *, empty_text: str = "- none") -> List[str]:
    lines: List[str] = []
    for item in list(items or []):
        if not isinstance(item, dict):
            continue
        label = str(item.get("label", "") or item.get("title", "") or item.get("ref", "") or "").strip()
        summary = str(item.get("summary", "") or item.get("evidence", "") or item.get("policy_reason", "") or "").strip()
        if label and summary:
            lines.append(f"- {label}: {summary}")
        elif label:
            lines.append(f"- {label}")
        elif summary:
            lines.append(f"- {summary}")
    return lines or [empty_text]


def render_host_report_markdown(report: Dict[str, Any]) -> str:
    payload = report if isinstance(report, dict) else {}
    host = payload.get("host", {}) if isinstance(payload.get("host", {}), dict) else {}
    policy = payload.get("scope_and_policy", {}).get("engagement_policy", {}) if isinstance(payload.get("scope_and_policy", {}), dict) else {}
    summary_assets = payload.get("summary_of_discovered_assets", {}) if isinstance(payload.get("summary_of_discovered_assets", {}), dict) else {}
    findings = payload.get("validated_findings", {}) if isinstance(payload.get("validated_findings", {}), dict) else {}
    credentials = payload.get("credentials_and_sessions", {}) if isinstance(payload.get("credentials_and_sessions", {}), dict) else {}
    next_steps = payload.get("recommended_next_steps", {}) if isinstance(payload.get("recommended_next_steps", {}), dict) else {}
    methodology = payload.get("methodology_coverage", {}) if isinstance(payload.get("methodology_coverage", {}), dict) else {}

    lines = [
        "# Legion Host Report",
        "",
        f"- Generated: {payload.get('generated_at', '')}",
        f"- Host ID: {host.get('id', '')}",
        f"- Host IP: {host.get('ip', '')}",
        f"- Hostname: {host.get('hostname', '')}",
        f"- Status: {host.get('status', '')}",
        f"- OS: {host.get('os', '')}",
        "",
        "## Scope and Policy",
        "",
        f"- Engagement Preset: {policy.get('preset', '')}",
        f"- Scope: {policy.get('scope', '')}",
        f"- Intent: {policy.get('intent', '')}",
        f"- Approval Mode: {policy.get('approval_mode', '')}",
        f"- Exploitation Allowed: {bool(policy.get('allow_exploitation', False))}",
        f"- Lateral Movement Allowed: {bool(policy.get('allow_lateral_movement', False))}",
        "",
        "## Summary of Discovered Assets",
        "",
        f"- Services: {summary_assets.get('service_count', 0)}",
        f"- URLs: {summary_assets.get('url_count', 0)}",
        f"- Technologies: {summary_assets.get('technology_count', 0)}",
        f"- Findings: {summary_assets.get('finding_count', 0)}",
        f"- Credentials: {summary_assets.get('credential_count', 0)}",
        f"- Sessions: {summary_assets.get('session_count', 0)}",
        "",
        "## Validated Findings",
        "",
    ]
    lines.extend(_markdown_item_lines(findings.get("items", [])))
    lines.extend([
        "",
        "## Attack Paths / Exploitation Chain",
        "",
    ])
    lines.extend(_markdown_item_lines(payload.get("attack_paths", [])))
    lines.extend([
        "",
        "## Credentials / Identities / Sessions",
        "",
        f"- Credentials: {len(credentials.get('credentials', []))}",
        f"- Identities: {len(credentials.get('identities', []))}",
        f"- Sessions: {len(credentials.get('sessions', []))}",
        "",
        "## Evidence References",
        "",
    ])
    lines.extend(_markdown_item_lines(payload.get("evidence_references", [])))
    lines.extend([
        "",
        "## Recommended Next Steps",
        "",
        f"- Next Phase: {next_steps.get('next_phase', '')}",
    ])
    lines.extend(_markdown_item_lines(next_steps.get("coverage_gaps", []), empty_text="- no recorded coverage gaps"))
    lines.extend(_markdown_item_lines(next_steps.get("manual_tests", []), empty_text="- no manual tests queued"))
    lines.extend([
        "",
        "## Skipped or Blocked Actions Due to Policy",
        "",
    ])
    lines.extend(_markdown_item_lines(payload.get("skipped_or_blocked_actions", []), empty_text="- none recorded"))
    lines.extend([
        "",
        "## Methodology Coverage",
        "",
        f"- Last Mode: {methodology.get('last_mode', '')}",
        f"- Next Phase: {methodology.get('next_phase', '')}",
        f"- Attempted Actions: {methodology.get('attempted_action_count', 0)}",
        f"- Strategy Packs Seen: {', '.join(methodology.get('strategy_packs_seen', [])) or 'none'}",
        "",
        "## Provenance Separation",
        "",
        f"- Observed Facts: {len(payload.get('observed_facts', []))}",
        f"- Inferred Relationships: {len(payload.get('inferred_relationships', []))}",
        f"- AI Suggestions: {len(payload.get('ai_suggestions', []))}",
        f"- Operator Conclusions: {len(payload.get('operator_conclusions', []))}",
        "",
    ])
    return "\n".join(lines).strip() + "\n"


def render_project_report_markdown(report: Dict[str, Any]) -> str:
    payload = report if isinstance(report, dict) else {}
    project = payload.get("project", {}) if isinstance(payload.get("project", {}), dict) else {}
    policy = payload.get("scope_and_policy", {}).get("engagement_policy", {}) if isinstance(payload.get("scope_and_policy", {}), dict) else {}
    summary_assets = payload.get("summary_of_discovered_assets", {}) if isinstance(payload.get("summary_of_discovered_assets", {}), dict) else {}
    next_steps = payload.get("recommended_next_steps", {}) if isinstance(payload.get("recommended_next_steps", {}), dict) else {}
    methodology = payload.get("methodology_coverage", {}) if isinstance(payload.get("methodology_coverage", {}), dict) else {}

    lines = [
        "# Legion Project Report",
        "",
        f"- Generated: {payload.get('generated_at', '')}",
        f"- Project: {project.get('name', '')}",
        f"- Temporary: {bool(project.get('is_temporary', False))}",
        f"- Output Folder: {project.get('output_folder', '')}",
        f"- Running Folder: {project.get('running_folder', '')}",
        "",
        "## Scope and Policy",
        "",
        f"- Engagement Preset: {policy.get('preset', '')}",
        f"- Scope: {policy.get('scope', '')}",
        f"- Intent: {policy.get('intent', '')}",
        f"- Approval Mode: {policy.get('approval_mode', '')}",
        f"- Exploitation Allowed: {bool(policy.get('allow_exploitation', False))}",
        f"- Lateral Movement Allowed: {bool(policy.get('allow_lateral_movement', False))}",
        "",
        "## Summary of Discovered Assets",
        "",
        f"- Hosts: {summary_assets.get('host_count', 0)}",
        f"- Services: {summary_assets.get('service_count', 0)}",
        f"- URLs: {summary_assets.get('url_count', 0)}",
        f"- Technologies: {summary_assets.get('technology_count', 0)}",
        f"- Findings: {summary_assets.get('finding_count', 0)}",
        f"- Credentials: {summary_assets.get('credential_count', 0)}",
        f"- Sessions: {summary_assets.get('session_count', 0)}",
        "",
        "## Validated Findings",
        "",
    ]
    lines.extend(_markdown_item_lines(payload.get("validated_findings", {}).get("items", [])))
    lines.extend([
        "",
        "## Attack Paths / Exploitation Chain",
        "",
    ])
    lines.extend(_markdown_item_lines(payload.get("attack_paths", [])))
    lines.extend([
        "",
        "## Credentials / Identities / Sessions",
        "",
        f"- Credentials: {len(payload.get('credentials_and_sessions', {}).get('credentials', []))}",
        f"- Identities: {len(payload.get('credentials_and_sessions', {}).get('identities', []))}",
        f"- Sessions: {len(payload.get('credentials_and_sessions', {}).get('sessions', []))}",
        "",
        "## Evidence References",
        "",
    ])
    lines.extend(_markdown_item_lines(payload.get("evidence_references", [])))
    lines.extend([
        "",
        "## Recommended Next Steps",
        "",
        f"- Next Phases: {', '.join(next_steps.get('next_phases', [])) or 'none'}",
    ])
    lines.extend(_markdown_item_lines(next_steps.get("coverage_gaps", []), empty_text="- no recorded coverage gaps"))
    lines.extend(_markdown_item_lines(next_steps.get("manual_tests", []), empty_text="- no manual tests queued"))
    lines.extend(_markdown_item_lines(next_steps.get("pending_approvals", []), empty_text="- no pending approvals"))
    lines.extend([
        "",
        "## Skipped or Blocked Actions Due to Policy",
        "",
    ])
    lines.extend(_markdown_item_lines(payload.get("skipped_or_blocked_actions", []), empty_text="- none recorded"))
    lines.extend([
        "",
        "## Methodology Coverage",
        "",
        f"- Attempted Actions: {methodology.get('attempted_action_count', 0)}",
        f"- Strategy Packs Seen: {', '.join(methodology.get('strategy_packs_seen', [])) or 'none'}",
        f"- Runner Usage: {json.dumps(methodology.get('runner_usage', {}), sort_keys=True)}",
        "",
        "## Provenance Separation",
        "",
        f"- Observed Facts: {len(payload.get('observed_facts', []))}",
        f"- Inferred Relationships: {len(payload.get('inferred_relationships', []))}",
        f"- AI Suggestions: {len(payload.get('ai_suggestions', []))}",
        f"- Operator Conclusions: {len(payload.get('operator_conclusions', []))}",
        "",
    ])
    return "\n".join(lines).strip() + "\n"
