from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

from sqlalchemy import text

from app.device_categories import category_names
from app.web.runtime_workspace_identity import resolve_host_device_categories


def get_workspace_services(
        runtime,
        limit: int = 300,
        host_id: int = 0,
        category: str = "",
        *,
        load_target_state_cache_func,
) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return []
        try:
            normalized_host_id = int(host_id or 0)
        except (TypeError, ValueError):
            normalized_host_id = 0
        category_filter = str(category or "").strip().lower()

        grouped_by_host: Dict[int, Dict[str, Any]] = {}
        session = project.database.session()
        try:
            query = (
                "SELECT h.id AS host_id, COALESCE(h.hostname, '') AS hostname, COALESCE(h.osMatch, '') AS os_match, "
                "COALESCE(p.portId, '') AS port, COALESCE(p.protocol, 'tcp') AS protocol, COALESCE(p.state, '') AS state, "
                "COALESCE(s.name, '') AS service, COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM hostObj AS h "
                "JOIN portObj AS p ON p.hostId = h.id "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE (p.state = 'open' OR p.state = 'open|filtered') "
            )
            params: Dict[str, Any] = {}
            if normalized_host_id > 0:
                query += "AND h.id = :host_id "
                params["host_id"] = normalized_host_id
            query += "ORDER BY h.id ASC, p.id ASC"
            result = session.execute(text(query), params)
            keys = list(result.keys())
            for row in result.fetchall():
                payload = dict(zip(keys, row))
                current_host_id = int(payload.get("host_id", 0) or 0)
                if current_host_id <= 0:
                    continue
                host_row = grouped_by_host.setdefault(current_host_id, {
                    "host": SimpleNamespace(
                        id=current_host_id,
                        hostname=str(payload.get("hostname", "") or ""),
                        osMatch=str(payload.get("os_match", "") or ""),
                    ),
                    "service_inventory": [],
                })
                host_row["service_inventory"].append({
                    "port": str(payload.get("port", "") or "").strip(),
                    "protocol": str(payload.get("protocol", "tcp") or "tcp").strip().lower(),
                    "state": str(payload.get("state", "") or "").strip(),
                    "service": str(payload.get("service", "") or "").strip(),
                    "service_product": str(payload.get("service_product", "") or "").strip(),
                    "service_version": str(payload.get("service_version", "") or "").strip(),
                    "service_extrainfo": str(payload.get("service_extrainfo", "") or "").strip(),
                })
        except Exception:
            return []
        finally:
            session.close()

        grouped: Dict[str, Dict[str, Any]] = {}
        target_states = load_target_state_cache_func(project, list(grouped_by_host.keys()))
        for current_host_id, host_row in grouped_by_host.items():
            service_inventory = list(host_row.get("service_inventory", []) or [])
            category_state = resolve_host_device_categories(
                runtime,
                project,
                host_row.get("host"),
                target_state=target_states.get(current_host_id, {}),
                service_inventory=service_inventory,
            )
            host_categories = category_names(category_state.get("device_categories", []))
            if category_filter and not any(str(item or "").strip().lower() == category_filter for item in host_categories):
                continue
            for item in service_inventory:
                service_name = str(item.get("service", "") or "unknown").strip() or "unknown"
                key = service_name.lower()
                row = grouped.setdefault(key, {
                    "service": service_name,
                    "port_count": 0,
                    "host_ids": set(),
                    "ports": set(),
                    "protocols": set(),
                    "categories": set(),
                })
                row["port_count"] += 1
                row["host_ids"].add(current_host_id)
                port_value = str(item.get("port", "") or "").strip()
                if port_value:
                    row["ports"].add(port_value)
                row["protocols"].add(str(item.get("protocol", "") or "").strip().lower())
                for category_name in host_categories:
                    row["categories"].add(str(category_name or "").strip())
        rows = []
        for item in grouped.values():
            rows.append({
                "service": str(item.get("service", "") or ""),
                "port_count": int(item.get("port_count", 0) or 0),
                "host_count": len(item.get("host_ids", set()) or set()),
                "ports": sorted(
                    [entry for entry in list(item.get("ports", set()) or set()) if entry],
                    key=lambda value: (0, int(value)) if str(value).isdigit() else (1, str(value)),
                ),
                "protocols": sorted([entry for entry in list(item.get("protocols", set()) or set()) if entry]),
                "categories": sorted([entry for entry in list(item.get("categories", set()) or set()) if entry]),
            })
        rows.sort(key=lambda row: (-int(row.get("host_count", 0) or 0), -int(row.get("port_count", 0) or 0), str(row.get("service", "") or "").lower()))
        return rows[: max(1, min(int(limit), 2000))]
