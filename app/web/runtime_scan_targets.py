from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional


def record_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text_value = str(value or "").strip().lower()
    if text_value in {"1", "true", "yes", "on"}:
        return True
    if text_value in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def normalize_targets(targets: Any) -> List[str]:
    if isinstance(targets, str):
        source = targets.replace(",", " ").split()
    elif isinstance(targets, list):
        source = []
        for item in targets:
            text = str(item or "").strip()
            if text:
                source.extend(text.replace(",", " ").split())
    else:
        source = []

    deduped = []
    seen = set()
    for value in source:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(key)

    if not deduped:
        raise ValueError("At least one target is required.")
    return deduped


def normalize_subnet_target(subnet: str) -> str:
    token = str(subnet or "").strip()
    if not token:
        raise ValueError("Subnet is required.")
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {token}") from exc


def count_rfc1918_scan_batches(runtime_cls, targets: List[str]) -> int:
    chunk_prefix = max(1, min(int(runtime_cls.RFC1918_SWEEP_CHUNK_PREFIX), 32))
    batch_size = max(1, int(runtime_cls.RFC1918_SWEEP_BATCH_SIZE))
    chunk_count = 0
    for raw_target in list(targets or []):
        token = str(raw_target or "").strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            chunk_count += 1
            continue
        if not isinstance(network, ipaddress.IPv4Network) or not network.is_private:
            chunk_count += 1
            continue
        if int(network.prefixlen) >= int(chunk_prefix):
            chunk_count += 1
        else:
            chunk_count += 1 << int(chunk_prefix - int(network.prefixlen))
    if chunk_count <= 0:
        return 0
    return max(1, int((chunk_count + batch_size - 1) / batch_size))


def iter_rfc1918_scan_batches(runtime_cls, targets: List[str]):
    chunk_prefix = max(1, min(int(runtime_cls.RFC1918_SWEEP_CHUNK_PREFIX), 32))
    batch_size = max(1, int(runtime_cls.RFC1918_SWEEP_BATCH_SIZE))
    batch: List[str] = []
    for raw_target in list(targets or []):
        token = str(raw_target or "").strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            batch.append(token)
            if len(batch) >= batch_size:
                yield list(batch)
                batch = []
            continue
        if not isinstance(network, ipaddress.IPv4Network) or not network.is_private:
            batch.append(str(network))
            if len(batch) >= batch_size:
                yield list(batch)
                batch = []
            continue
        subnet_iterable = (
            [str(network)]
            if int(network.prefixlen) >= int(chunk_prefix)
            else (str(item) for item in network.subnets(new_prefix=chunk_prefix))
        )
        for subnet in subnet_iterable:
            batch.append(str(subnet))
            if len(batch) >= batch_size:
                yield list(batch)
                batch = []
    if batch:
        yield list(batch)


def normalize_rfc_chunk_concurrency(runtime_cls, raw: Any) -> int:
    try:
        value = int(raw)
    except Exception:
        return 1
    return max(1, min(value, int(runtime_cls.RFC1918_SWEEP_MAX_CONCURRENCY)))


def scan_history_targets(record: Dict[str, Any]) -> List[str]:
    if isinstance(record.get("targets"), list):
        values = [str(item or "").strip() for item in list(record.get("targets", [])) if str(item or "").strip()]
        if values:
            return values
    raw_targets = str(record.get("targets_json", "") or "").strip()
    if raw_targets:
        try:
            parsed = json.loads(raw_targets)
        except Exception:
            parsed = []
        if isinstance(parsed, list):
            values = [str(item or "").strip() for item in parsed if str(item or "").strip()]
            if values:
                return values
    fallback: List[str] = []
    for source in (record.get("scope_summary", ""), record.get("target_summary", "")):
        for token in re.findall(r"[A-Za-z0-9./:-]+", str(source or "")):
            cleaned = str(token or "").strip(",:")
            if cleaned and cleaned not in fallback:
                fallback.append(cleaned)
    return fallback


def scan_target_match_score_for_subnet(target: Any, subnet: str) -> int:
    token = str(target or "").strip().strip(",")
    if not token:
        return -1
    subnet_network = ipaddress.ip_network(str(subnet), strict=False)
    try:
        target_ip = ipaddress.ip_address(token)
        return 50 if target_ip in subnet_network else -1
    except ValueError:
        pass
    try:
        target_network = ipaddress.ip_network(token, strict=False)
        if target_network == subnet_network:
            return 100
        if subnet_network.subnet_of(target_network):
            return 90
        if target_network.subnet_of(subnet_network):
            return 80
        if target_network.overlaps(subnet_network):
            return 70
        return -1
    except ValueError:
        pass
    return -1


def best_scan_submission_for_subnet(runtime_cls, subnet: str, records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    _ = runtime_cls
    best_record: Optional[Dict[str, Any]] = None
    best_score = -1
    for record in list(records or []):
        if str(record.get("submission_kind", "") or "").strip() != "nmap_scan":
            continue
        score = -1
        for target in scan_history_targets(record):
            score = max(score, scan_target_match_score_for_subnet(target, subnet))
        if score > best_score:
            best_record = record
            best_score = score
    return best_record if best_score >= 0 else None


def compact_targets(targets: List[str]) -> str:
    if not targets:
        return ""
    if len(targets) <= 3:
        return ",".join(str(item) for item in targets)
    return ",".join(str(item) for item in targets[:3]) + ",..."


def summarize_scan_scope(targets: List[str]) -> str:
    subnets: List[str] = []
    hosts: List[str] = []
    ranges: List[str] = []
    domains: List[str] = []
    for item in list(targets or []):
        token = str(item or "").strip()
        if not token:
            continue
        if "/" in token:
            try:
                subnet = str(ipaddress.ip_network(token, strict=False))
            except ValueError:
                subnet = ""
            if subnet and subnet not in subnets:
                subnets.append(subnet)
                continue
        if "-" in token and token not in ranges:
            ranges.append(token)
            continue
        try:
            host_value = str(ipaddress.ip_address(token))
        except ValueError:
            host_value = ""
        if host_value:
            if host_value not in hosts:
                hosts.append(host_value)
            continue
        if token not in domains:
            domains.append(token)

    parts: List[str] = []
    if subnets:
        parts.append(f"subnets: {', '.join(subnets[:4])}" + (" ..." if len(subnets) > 4 else ""))
    if ranges:
        parts.append(f"ranges: {', '.join(ranges[:3])}" + (" ..." if len(ranges) > 3 else ""))
    if hosts:
        host_summary = ", ".join(hosts[:4])
        if len(hosts) > 4:
            host_summary = f"{host_summary} ... ({len(hosts)} hosts)"
        parts.append(f"hosts: {host_summary}")
    if domains:
        parts.append(f"domains: {', '.join(domains[:4])}" + (" ..." if len(domains) > 4 else ""))
    return " | ".join(parts[:4])
