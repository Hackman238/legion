from __future__ import annotations

from typing import Any, Dict, List

from app.scheduler.observation_parsers import extract_tool_observations
from app.web import runtime_scheduler_inference_helpers as web_runtime_scheduler_inference_helpers


def infer_technologies_from_observations(
        runtime,
        *,
        service_records: List[Dict[str, Any]],
        script_records: List[Dict[str, Any]],
        process_records: List[Dict[str, Any]],
        limit: int = 180,
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    seen = set()

    def _add(name: Any, version: Any, cpe: Any, evidence: Any):
        tech_name = str(name or "").strip()[:120]
        tech_cpe = runtime._normalize_cpe_token(cpe)
        tech_evidence = runtime._truncate_scheduler_text(evidence, 520)
        tech_version = runtime._sanitize_technology_version_for_tech(
            name=tech_name,
            version=version,
            cpe=tech_cpe,
            evidence=tech_evidence,
        )

        if not tech_name and tech_cpe:
            tech_name = runtime._name_from_cpe(tech_cpe)
        if not tech_version and tech_cpe:
            cpe_version = runtime._sanitize_technology_version_for_tech(
                name=tech_name,
                version=runtime._version_from_cpe(tech_cpe),
                cpe=tech_cpe,
                evidence=tech_evidence,
            )
            if cpe_version:
                tech_version = cpe_version
            else:
                tech_cpe = runtime._cpe_base(tech_cpe)

        if not tech_cpe:
            hinted_name, hinted_cpe = runtime._guess_technology_hint(tech_name, tech_version)
            if hinted_name and not tech_name:
                tech_name = hinted_name
            if hinted_cpe:
                tech_cpe = runtime._normalize_cpe_token(hinted_cpe)
                if tech_cpe and not tech_version:
                    tech_version = runtime._version_from_cpe(tech_cpe)

        if not tech_name and not tech_cpe:
            return
        if runtime._is_weak_technology_name(tech_name) and not tech_cpe:
            if not any(marker in tech_evidence.lower() for marker in web_runtime_scheduler_inference_helpers.TECH_STRONG_EVIDENCE_MARKERS):
                return

        quality = runtime._technology_quality_score(
            name=tech_name,
            version=tech_version,
            cpe=tech_cpe,
            evidence=tech_evidence,
        )
        if quality < 20:
            return
        key = "|".join([tech_name.lower(), tech_version.lower(), tech_cpe.lower()])
        if key in seen:
            return
        seen.add(key)
        rows.append({
            "name": tech_name,
            "version": tech_version,
            "cpe": tech_cpe,
            "evidence": tech_evidence,
        })

    for record in service_records[:320]:
        if not isinstance(record, dict):
            continue
        service_name = str(record.get("service_name", "") or "").strip()
        product = str(record.get("service_product", "") or "").strip()
        version = str(record.get("service_version", "") or "").strip()
        extrainfo = str(record.get("service_extrainfo", "") or "").strip()
        banner = str(record.get("banner", "") or "").strip()
        port = str(record.get("port", "") or "").strip()
        protocol = str(record.get("protocol", "") or "").strip().lower()

        evidence_blob = " ".join([
            service_name,
            product,
            version,
            extrainfo,
            banner,
        ])
        cpes = runtime._extract_cpe_tokens(evidence_blob, limit=3)
        hinted_rows = runtime._guess_technology_hints(evidence_blob, version_hint=version)

        primary_name = product
        if not primary_name:
            service_token = service_name.lower()
            has_strong_context = bool(version or cpes or hinted_rows or banner or extrainfo)
            if (
                    service_name
                    and service_token not in web_runtime_scheduler_inference_helpers.GENERIC_TECH_NAME_TOKENS
                    and not runtime._is_weak_technology_name(service_name)
                    and has_strong_context
            ):
                primary_name = service_name
        if primary_name and primary_name.lower() not in {"unknown", "generic"}:
            _add(
                primary_name,
                version,
                cpes[0] if cpes else "",
                f"service {port}/{protocol} {service_name} {product} {version} {extrainfo}".strip(),
            )
        for hinted_name, hinted_cpe in hinted_rows:
            hinted_version = runtime._version_from_cpe(hinted_cpe) or version
            _add(
                hinted_name or primary_name,
                hinted_version,
                hinted_cpe or (cpes[0] if cpes else ""),
                f"service fingerprint {port}/{protocol}",
            )
        for token in cpes:
            _add("", "", token, f"service CPE {port}/{protocol}")
        if len(rows) >= int(limit):
            break

    for record in (script_records[:320] + process_records[:220]):
        if not isinstance(record, dict):
            continue
        source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()
        output = str(
            record.get("analysis_excerpt", "")
            or record.get("excerpt", "")
            or record.get("output_excerpt", "")
        ).strip()
        if not output:
            continue
        analysis_output = runtime._technology_hint_source_text(source_id, output)
        parsed = extract_tool_observations(
            source_id,
            output,
            port=str(record.get("port", "") or ""),
            protocol=str(record.get("protocol", "tcp") or "tcp"),
            service=str(record.get("service", "") or ""),
            artifact_refs=list(record.get("artifact_refs", []) or []),
            host_ip=str(record.get("host_ip", "") or ""),
            hostname=str(record.get("hostname", "") or ""),
        )
        for item in list(parsed.get("technologies", []) or [])[:24]:
            if not isinstance(item, dict):
                continue
            _add(
                item.get("name", ""),
                item.get("version", ""),
                item.get("cpe", ""),
                item.get("evidence", "") or f"{source_id} parsed output",
            )
        cpes = runtime._extract_cpe_tokens(analysis_output or output, limit=4)
        for token in cpes:
            _add("", "", token, f"{source_id} output CPE")
        hinted_rows = runtime._guess_technology_hints(analysis_output or output, version_hint=analysis_output or output)
        for hinted_name, hinted_cpe in hinted_rows:
            version = runtime._version_from_cpe(hinted_cpe)
            if not version:
                version = runtime._extract_version_near_tokens(analysis_output or output, [hinted_name])
            _add(
                hinted_name,
                version,
                hinted_cpe,
                f"{source_id} output fingerprint",
            )
        if len(rows) >= int(limit):
            break

    return web_runtime_scheduler_inference_helpers.normalize_ai_technologies(runtime, rows[:int(limit)])


def infer_findings_from_observations(
        runtime,
        *,
        host_cves_raw: List[Dict[str, Any]],
        script_records: List[Dict[str, Any]],
        process_records: List[Dict[str, Any]],
        limit: int = 220,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    cve_index: Dict[str, Dict[str, Any]] = {}

    for row in host_cves_raw[:240]:
        if not isinstance(row, dict):
            continue
        cve_name = str(row.get("name", "") or "").strip().upper()
        matched = web_runtime_scheduler_inference_helpers.CVE_TOKEN_RE.search(cve_name)
        cve_id = matched.group(0).upper() if matched else ""
        severity = runtime._severity_from_text(row.get("severity", ""))
        product = str(row.get("product", "") or "").strip()
        version = str(row.get("version", "") or "").strip()
        url = str(row.get("url", "") or "").strip()
        title = cve_id or cve_name or f"Potential vulnerability in {product or 'service'}"
        evidence = " | ".join(part for part in [
            f"product={product}" if product else "",
            f"version={version}" if version else "",
            f"url={url}" if url else "",
        ] if part)
        rows.append({
            "title": title,
            "severity": severity,
            "cvss": 0.0,
            "cve": cve_id,
            "evidence": evidence or title,
        })
        if cve_id:
            cve_index[cve_id] = {
                "severity": severity,
                "evidence": evidence or title,
            }

    for record in (script_records[:360] + process_records[:220]):
        if not isinstance(record, dict):
            continue
        source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()[:80]
        excerpt = str(
            record.get("analysis_excerpt", "")
            or record.get("excerpt", "")
            or record.get("output_excerpt", "")
        ).strip()
        if not excerpt:
            continue
        cleaned_excerpt = runtime._observation_text_for_analysis(source_id, excerpt)
        parsed = extract_tool_observations(
            source_id,
            cleaned_excerpt or excerpt,
            port=str(record.get("port", "") or ""),
            protocol=str(record.get("protocol", "tcp") or "tcp"),
            service=str(record.get("service", "") or ""),
            artifact_refs=list(record.get("artifact_refs", []) or []),
            host_ip=str(record.get("host_ip", "") or ""),
            hostname=str(record.get("hostname", "") or ""),
        )
        for item in list(parsed.get("findings", []) or [])[:32]:
            if not isinstance(item, dict):
                continue
            rows.append({
                "title": str(item.get("title", "") or ""),
                "severity": runtime._severity_from_text(item.get("severity", "info")),
                "cvss": 0.0,
                "cve": str(item.get("cve", "") or "").upper(),
                "evidence": runtime._truncate_scheduler_text(item.get("evidence", "") or cleaned_excerpt or excerpt, 420),
            })
        suppressed_cves = {
            str(item.get("cve", "") or "").strip().upper()
            for item in list(parsed.get("finding_quality_events", []) or [])
            if isinstance(item, dict) and str(item.get("action", "") or "").strip().lower() == "suppressed"
        }
        for cve_id, evidence_line in runtime._cve_evidence_lines(source_id, cleaned_excerpt or excerpt):
            if cve_id in suppressed_cves:
                continue
            mapped = cve_index.get(cve_id, {})
            severity = str(mapped.get("severity", "info") or "info")
            evidence = runtime._truncate_scheduler_text(
                f"{source_id}: {evidence_line}",
                420,
            )
            rows.append({
                "title": cve_id,
                "severity": severity,
                "cvss": 0.0,
                "cve": cve_id,
                "evidence": evidence,
            })

    normalized = web_runtime_scheduler_inference_helpers.normalize_ai_findings(runtime, rows)
    return normalized[:int(limit)]


def infer_urls_from_observations(
        runtime,
        *,
        script_records: List[Dict[str, Any]],
        process_records: List[Dict[str, Any]],
        limit: int = 160,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for record in (script_records[:320] + process_records[:220]):
        if not isinstance(record, dict):
            continue
        source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()
        output = str(
            record.get("analysis_excerpt", "")
            or record.get("excerpt", "")
            or record.get("output_excerpt", "")
        ).strip()
        if not output:
            continue
        parsed = extract_tool_observations(
            source_id,
            output,
            port=str(record.get("port", "") or ""),
            protocol=str(record.get("protocol", "tcp") or "tcp"),
            service=str(record.get("service", "") or ""),
            artifact_refs=list(record.get("artifact_refs", []) or []),
            host_ip=str(record.get("host_ip", "") or ""),
            hostname=str(record.get("hostname", "") or ""),
        )
        for item in list(parsed.get("urls", []) or [])[:32]:
            if not isinstance(item, dict):
                continue
            rows.append({
                "url": str(item.get("url", "") or ""),
                "port": str(item.get("port", "") or record.get("port", "") or ""),
                "protocol": str(item.get("protocol", "tcp") or record.get("protocol", "tcp") or "tcp"),
                "service": str(item.get("service", "") or record.get("service", "") or ""),
                "label": str(item.get("label", "") or source_id),
                "confidence": float(item.get("confidence", 90.0) or 90.0),
                "source_kind": str(item.get("source_kind", "observed") or "observed"),
                "observed": bool(item.get("observed", True)),
            })
        if len(rows) >= int(limit):
            break
    return rows[:int(limit)]
