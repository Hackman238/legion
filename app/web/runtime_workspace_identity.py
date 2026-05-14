from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from app.device_categories import category_names, normalize_manual_device_categories
from app.device_categories import classify_device_categories
from app.device_categories import merge_effective_device_categories
from app.nmap_enrichment import infer_os_from_service_inventory
from app.osclassification import DEFAULT_CATEGORY as UNKNOWN_OS_CATEGORY
from app.osclassification import classify_os
from app.scheduler.state import get_target_state as load_target_state
from app.scheduler.state import load_observed_service_inventory


def workspace_host_services(runtime, port_rows: List[Any], service_repo: Any) -> List[str]:
    return _service_names_from_inventory(workspace_host_service_inventory(port_rows, service_repo))


def workspace_host_service_inventory(port_rows: List[Any], service_repo: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for port in list(port_rows or []):
        service_obj = None
        service_id = getattr(port, "serviceId", None)
        if service_id and service_repo is not None:
            try:
                service_obj = service_repo.getServiceById(service_id)
            except Exception:
                service_obj = None
        service_name = str(getattr(service_obj, "name", "") or getattr(port, "serviceName", "") or "").strip()
        rows.append({
            "port": str(getattr(port, "portId", "") or "").strip(),
            "protocol": str(getattr(port, "protocol", "tcp") or "tcp").strip().lower(),
            "state": str(getattr(port, "state", "") or "").strip(),
            "service": service_name,
            "service_product": str(getattr(service_obj, "product", "") or "").strip() if service_obj else "",
            "service_version": str(getattr(service_obj, "version", "") or "").strip() if service_obj else "",
            "service_extrainfo": str(getattr(service_obj, "extrainfo", "") or "").strip() if service_obj else "",
        })
    return rows


def _service_names_from_inventory(service_inventory: List[Dict[str, Any]]) -> List[str]:
    services = []
    for item in list(service_inventory or []):
        if not isinstance(item, dict):
            continue
        if str(item.get("state", "") or "") not in {"open", "open|filtered"}:
            continue
        service_name = str(item.get("service", "") or "").strip()
        if service_name:
            services.append(service_name)
    return sorted({item for item in services if item})


def _safe_os_accuracy(value: Any) -> Optional[float]:
    token = str(value or "").strip()
    if not token:
        return None
    try:
        parsed = float(token)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return max(0.0, min(parsed, 100.0))


def _service_inventory_os_records(service_inventory: List[Dict[str, Any]]) -> List[tuple]:
    rows = []
    for item in list(service_inventory or []):
        if not isinstance(item, dict):
            continue
        rows.append((
            str(item.get("service", "") or ""),
            str(item.get("service_product", "") or ""),
            str(item.get("service_version", "") or ""),
            str(item.get("service_extrainfo", "") or ""),
        ))
    return rows


def _score_service_os_evidence(os_name: str, service_inventory: List[Dict[str, Any]]) -> int:
    normalized_os = classify_os(os_name)
    if normalized_os == UNKNOWN_OS_CATEGORY:
        return 0

    score = 0
    matched_keys = set()
    for item in list(service_inventory or []):
        if not isinstance(item, dict):
            continue
        service = str(item.get("service", "") or "").strip().lower()
        product = str(item.get("service_product", "") or "").strip().lower()
        version = str(item.get("service_version", "") or "").strip().lower()
        extrainfo = str(item.get("service_extrainfo", "") or "").strip().lower()
        text_value = " ".join([service, product, version, extrainfo])

        if normalized_os == "Windows":
            if service in {"msrpc", "microsoft-ds", "netbios-ssn", "ms-wbt-server", "vmrdp", "winrm"}:
                matched_keys.add(service)
                score += 24
            elif service in {"kerberos-sec", "kpasswd5", "ldap", "ncacn_http"}:
                matched_keys.add(service)
                score += 10
            if any(token in text_value for token in ("microsoft windows", "windows rpc", "microsoft httpapi", "ntlm", "termsrv")):
                score += 28
            elif "microsoft" in text_value:
                score += 18
        elif normalized_os == "Linux":
            if service in {"ssh", "nfs", "rpcbind"}:
                score += 8
            if any(token in text_value for token in ("openssh", "linux", "ubuntu", "debian", "centos", "red hat", "rhel")):
                score += 24
        elif normalized_os == "Darwin":
            if any(token in text_value for token in ("darwin", "mac os", "macos", "apple")):
                score += 28
        elif normalized_os in {"FreeBSD", "OpenBSD", "NetBSD", "Unix"}:
            if any(token in text_value for token in ("freebsd", "openbsd", "netbsd", "unix")):
                score += 24

    if normalized_os == "Windows" and len(matched_keys) >= 2:
        score += 18
    return max(0, min(score, 100))


def resolve_host_os(
        host: Any,
        service_inventory: Optional[List[Dict[str, Any]]] = None,
        target_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    state = dict(target_state or {})
    raw_os = str(getattr(host, "osMatch", "") or state.get("os_match", "") or "").strip()
    raw_category = classify_os(raw_os)
    raw_accuracy = _safe_os_accuracy(getattr(host, "osAccuracy", ""))
    if raw_accuracy is None:
        raw_accuracy = _safe_os_accuracy(state.get("os_confidence"))

    inventory = list(service_inventory or state.get("service_inventory", []) or [])
    inferred_os = infer_os_from_service_inventory(_service_inventory_os_records(inventory))
    inferred_category = classify_os(inferred_os)
    inferred_score = _score_service_os_evidence(inferred_os, inventory)

    raw_unknown = raw_category == UNKNOWN_OS_CATEGORY
    raw_weak = raw_accuracy is None or raw_accuracy < 60.0
    contradictory = bool(
        inferred_category != UNKNOWN_OS_CATEGORY
        and raw_category != UNKNOWN_OS_CATEGORY
        and inferred_category != raw_category
    )

    if inferred_category != UNKNOWN_OS_CATEGORY and (
            raw_unknown
            or (contradictory and raw_weak and inferred_score >= 70)
            or (contradictory and inferred_score >= 90)
    ):
        return {
            "os": inferred_category,
            "raw_os": raw_os,
            "os_source": "service-evidence",
            "os_confidence": float(max(inferred_score, 80)),
        }

    return {
        "os": raw_os,
        "raw_os": raw_os,
        "os_source": "imported" if raw_os else "",
        "os_confidence": float(raw_accuracy or 0.0),
    }


def resolve_host_device_categories(
        runtime,
        project: Any,
        host: Any,
        *,
        target_state: Optional[Dict[str, Any]] = None,
        service_inventory: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    state = dict(target_state or {})
    effective = list(state.get("device_categories", []) or [])
    manual = list(state.get("manual_device_categories", []) or [])
    override_auto = bool(state.get("device_category_override", False))
    if effective and override_auto:
        return {
            "device_categories": list(effective),
            "manual_device_categories": list(manual),
            "device_category_override": override_auto,
        }
    resolved_inventory = list(service_inventory or state.get("service_inventory", []) or [])
    if not resolved_inventory:
        try:
            resolved_inventory = load_observed_service_inventory(project.database, int(getattr(host, "id", 0) or 0))
        except Exception:
            resolved_inventory = []
    manual = normalize_manual_device_categories(
        manual or (
            state.get("raw", {}).get("manual_device_categories", [])
            if isinstance(state.get("raw", {}), dict)
            else []
        )
    )
    override_auto = bool(
        state.get("device_category_override", False)
        or (
            state.get("raw", {}).get("device_category_override", False)
            if isinstance(state.get("raw", {}), dict)
            else False
        )
    )
    auto = classify_device_categories(
        {
            "hostname": str(getattr(host, "hostname", "") or state.get("hostname", "") or ""),
            "os_match": str(getattr(host, "osMatch", "") or state.get("os_match", "") or ""),
            "service_inventory": resolved_inventory,
            "technologies": list(state.get("technologies", []) or []),
            "findings": list(state.get("findings", []) or []),
        },
        custom_rules=runtime.scheduler_config.get_device_categories(),
    )
    return {
        "device_categories": merge_effective_device_categories(auto, manual, override_auto=override_auto),
        "manual_device_categories": manual,
        "device_category_override": override_auto,
    }


def build_workspace_host_row(
        runtime,
        host: Any,
        port_repo: Any,
        service_repo: Any,
        project: Any,
        *,
        get_target_state_func=None,
        preloaded_ports: Optional[List[Any]] = None,
        preloaded_service_inventory: Optional[List[Dict[str, Any]]] = None,
        preloaded_services: Optional[List[str]] = None,
        preloaded_target_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
    ports = list(preloaded_ports) if preloaded_ports is not None else list(port_repo.getPortsByHostId(host.id) or [])
    open_ports = [p for p in ports if str(getattr(p, "state", "")) in {"open", "open|filtered"}]
    service_inventory = (
        list(preloaded_service_inventory)
        if preloaded_service_inventory is not None
        else workspace_host_service_inventory(ports, service_repo)
    )
    services = list(preloaded_services) if preloaded_services is not None else _service_names_from_inventory(service_inventory)
    target_state = (
        dict(preloaded_target_state)
        if preloaded_target_state is not None
        else target_state_getter(project.database, int(getattr(host, "id", 0) or 0)) or {}
    )
    category_state = resolve_host_device_categories(
        runtime,
        project,
        host,
        target_state=target_state,
        service_inventory=service_inventory,
    )
    os_state = resolve_host_os(
        host,
        service_inventory=service_inventory,
        target_state=target_state,
    )
    return {
        "id": int(host.id),
        "ip": str(getattr(host, "ip", "") or ""),
        "hostname": str(getattr(host, "hostname", "") or ""),
        "status": str(getattr(host, "status", "") or ""),
        "os": str(os_state.get("os", "") or ""),
        "raw_os": str(os_state.get("raw_os", "") or ""),
        "os_source": str(os_state.get("os_source", "") or ""),
        "os_confidence": float(os_state.get("os_confidence", 0.0) or 0.0),
        "open_ports": len(open_ports),
        "total_ports": len(ports),
        "services": services,
        "categories": category_names(category_state.get("device_categories", [])),
        "category_override": bool(category_state.get("device_category_override", False)),
    }
