from __future__ import annotations

from typing import Any, Dict, List

from app.web.runtime_scheduler_technology import (
    AI_HOST_UPDATE_MIN_CONFIDENCE,
    ANSI_ESCAPE_RE,
    CPE22_TOKEN_RE,
    CPE23_TOKEN_RE,
    CVE_TOKEN_RE,
    GENERIC_TECH_NAME_TOKENS,
    IPV4_LIKE_RE,
    PSEUDO_TECH_NAME_TOKENS,
    REFERENCE_ONLY_FINDING_RE,
    TECH_CPE_HINTS,
    TECH_STRONG_EVIDENCE_MARKERS,
    TECH_VERSION_RE,
    WEAK_TECH_NAME_TOKENS,
    ai_confidence_value,
    cpe_base,
    cve_evidence_lines,
    extract_cpe_tokens,
    extract_version_near_tokens,
    extract_version_token,
    finding_sort_key,
    guess_technology_hint,
    guess_technology_hints,
    is_ipv4_like,
    is_placeholder_scheduler_text,
    is_weak_technology_name,
    name_from_cpe,
    normalize_cpe_token,
    observation_text_for_analysis,
    sanitize_ai_hostname,
    sanitize_technology_version,
    sanitize_technology_version_for_tech,
    severity_from_text,
    technology_canonical_key,
    technology_hint_source_text,
    technology_quality_score,
    version_from_cpe,
)


def normalize_ai_technologies(runtime, items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    best_rows: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()[:120]
        cpe = runtime._normalize_cpe_token(item.get("cpe", ""))
        evidence = runtime._truncate_scheduler_text(item.get("evidence", ""), 520)
        version = runtime._sanitize_technology_version_for_tech(
            name=name,
            version=item.get("version", ""),
            cpe=cpe,
            evidence=evidence,
        )
        if is_placeholder_scheduler_text(name) and not cpe:
            continue
        if is_placeholder_scheduler_text(version):
            version = ""
        if is_placeholder_scheduler_text(evidence):
            evidence = ""
        if not name and not cpe:
            continue
        if not name and cpe:
            name = runtime._name_from_cpe(cpe)
        if str(name or "").strip().lower() in PSEUDO_TECH_NAME_TOKENS and not cpe:
            continue
        if not version and cpe:
            cpe_version = runtime._sanitize_technology_version_for_tech(
                name=name,
                version=runtime._version_from_cpe(cpe),
                cpe=cpe,
                evidence=evidence,
            )
            if cpe_version:
                version = cpe_version
            else:
                cpe = runtime._cpe_base(cpe)
        if not cpe and name:
            hinted_name, hinted_cpe = runtime._guess_technology_hint(name, version)
            if hinted_name and not name:
                name = hinted_name
            if hinted_cpe:
                cpe = runtime._normalize_cpe_token(hinted_cpe)
                if cpe and not version:
                    version = runtime._version_from_cpe(cpe)

        if runtime._is_weak_technology_name(name) and not cpe:
            if not any(marker in evidence.lower() for marker in TECH_STRONG_EVIDENCE_MARKERS):
                continue

        quality = runtime._technology_quality_score(
            name=name,
            version=version,
            cpe=cpe,
            evidence=evidence,
        )
        if quality < 20:
            continue

        canonical = runtime._technology_canonical_key(name, cpe) or "|".join([name.lower(), version.lower(), cpe.lower()])
        candidate = {
            "name": name,
            "version": version,
            "cpe": cpe,
            "evidence": evidence,
            "_quality": quality,
        }
        current = best_rows.get(canonical)
        if current is None:
            best_rows[canonical] = candidate
            continue

        if int(candidate["_quality"]) > int(current.get("_quality", 0)):
            best_rows[canonical] = candidate
            continue
        if int(candidate["_quality"]) == int(current.get("_quality", 0)):
            current_version = str(current.get("version", "") or "")
            if len(version) > len(current_version):
                best_rows[canonical] = candidate
                continue
            if cpe and not str(current.get("cpe", "") or ""):
                best_rows[canonical] = candidate

    rows = sorted(
        list(best_rows.values()),
        key=lambda row: (
            -int(row.get("_quality", 0) or 0),
            str(row.get("name", "") or "").lower(),
            str(row.get("version", "") or "").lower(),
            str(row.get("cpe", "") or "").lower(),
        ),
    )
    trimmed: List[Dict[str, str]] = []
    for row in rows:
        trimmed.append({
            "name": str(row.get("name", "") or "")[:120],
            "version": str(row.get("version", "") or "")[:120],
            "cpe": str(row.get("cpe", "") or "")[:220],
            "evidence": runtime._truncate_scheduler_text(row.get("evidence", ""), 520),
        })
        if len(trimmed) >= 180:
            break
    return trimmed


def merge_technologies(
        runtime,
        *,
        existing: Any,
        incoming: Any,
        limit: int = 220,
) -> List[Dict[str, str]]:
    combined: List[Dict[str, Any]] = []
    if isinstance(incoming, list):
        for item in incoming:
            if isinstance(item, dict):
                combined.append(dict(item))
    if isinstance(existing, list):
        for item in existing:
            if isinstance(item, dict):
                combined.append(dict(item))
    rows = normalize_ai_technologies(runtime, combined)
    return rows[:int(limit)]


def normalize_ai_findings(runtime, items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    allowed = {"critical", "high", "medium", "low", "info"}
    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()[:260]
        severity = str(item.get("severity", "info")).strip().lower()
        if severity not in allowed:
            severity = "info"
        cve_id = str(item.get("cve", "")).strip()[:64]
        cvss_value = runtime._ai_confidence_value(item.get("cvss"))
        if cvss_value > 10.0:
            cvss_value = 10.0
        evidence = runtime._truncate_scheduler_text(item.get("evidence", ""), 640)
        if is_placeholder_scheduler_text(title) and not cve_id:
            continue
        if is_placeholder_scheduler_text(evidence):
            evidence = ""
        if not title and not cve_id:
            continue
        evidence_lower = str(evidence or "").strip().lower()
        if REFERENCE_ONLY_FINDING_RE.match(title) or evidence_lower in {"previous scan result", "previous tls scan result"}:
            continue
        key = "|".join([title.lower(), cve_id.lower(), severity])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "title": title or cve_id,
            "severity": severity,
            "cvss": cvss_value,
            "cve": cve_id,
            "evidence": evidence or title or cve_id,
        })
        if len(rows) >= 220:
            break
    rows.sort(key=lambda row: runtime._finding_sort_key(row), reverse=True)
    return rows


def normalize_ai_manual_tests(runtime, items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        why = runtime._truncate_scheduler_text(item.get("why", ""), 320)
        command = runtime._truncate_scheduler_text(item.get("command", ""), 520)
        scope_note = runtime._truncate_scheduler_text(item.get("scope_note", ""), 280)
        if not command and not why:
            continue
        key = command.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "why": why,
            "command": command,
            "scope_note": scope_note,
        })
        if len(rows) >= 160:
            break
    return rows


def merge_ai_items(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], *, key_fields: List[str], limit: int) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for source in (incoming, existing):
        for item in source:
            if not isinstance(item, dict):
                continue
            key_parts = [str(item.get(field, "")).strip().lower() for field in key_fields]
            key = "|".join(key_parts)
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
            if len(merged) >= int(limit):
                return merged
    return merged
