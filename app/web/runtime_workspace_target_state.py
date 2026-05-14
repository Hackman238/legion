from __future__ import annotations

import json
from typing import Any, Dict, List

from sqlalchemy import text

from app.scheduler.state import ensure_scheduler_target_state_table
from app.scheduler.state import migrate_legacy_ai_state_to_target_state


def _decode_json_value(value: Any, fallback: Any):
    if value is None:
        return fallback
    try:
        return json.loads(str(value or ""))
    except Exception:
        return fallback


def load_target_state_cache(project: Any, host_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    normalized_ids = []
    seen = set()
    for host_id in list(host_ids or []):
        try:
            normalized = int(host_id or 0)
        except (TypeError, ValueError):
            normalized = 0
        if normalized <= 0 or normalized in seen:
            continue
        seen.add(normalized)
        normalized_ids.append(normalized)
    if not normalized_ids:
        return {}

    database = getattr(project, "database", None)
    if database is None:
        return {}

    if not bool(getattr(project, "_legion_web_target_state_bulk_ready", False)):
        try:
            migrate_legacy_ai_state_to_target_state(database)
        except Exception:
            try:
                ensure_scheduler_target_state_table(database)
            except Exception:
                return {}
        try:
            setattr(project, "_legion_web_target_state_bulk_ready", True)
        except Exception:
            pass

    rows: Dict[int, Dict[str, Any]] = {}
    session = database.session()
    try:
        for offset in range(0, len(normalized_ids), 500):
            chunk = normalized_ids[offset:offset + 500]
            params = {f"id_{index}": host_id for index, host_id in enumerate(chunk)}
            placeholders = ", ".join(f":id_{index}" for index in range(len(chunk)))
            result = session.execute(text(
                "SELECT host_id, hostname, os_match, technologies_json, findings_json, service_inventory_json, raw_json "
                f"FROM scheduler_target_state WHERE host_id IN ({placeholders})"
            ), params)
            keys = list(result.keys())
            for row in result.fetchall():
                payload = dict(zip(keys, row))
                raw = _decode_json_value(payload.get("raw_json"), {})
                if not isinstance(raw, dict):
                    raw = {}
                host_id = int(payload.get("host_id", 0) or 0)
                rows[host_id] = {
                    "host_id": host_id,
                    "hostname": str(payload.get("hostname", "") or ""),
                    "os_match": str(payload.get("os_match", "") or ""),
                    "technologies": _decode_json_value(payload.get("technologies_json"), []),
                    "findings": _decode_json_value(payload.get("findings_json"), []),
                    "service_inventory": _decode_json_value(payload.get("service_inventory_json"), []),
                    "raw": raw,
                    "manual_device_categories": raw.get("manual_device_categories", []),
                    "device_categories": raw.get("device_categories", []),
                    "device_category_override": raw.get("device_category_override", False),
                }
    except Exception:
        return {}
    finally:
        session.close()
    return rows
