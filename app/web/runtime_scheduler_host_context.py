from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy import text

from app.hostsfile import registrable_root_domain
from app.scheduler.providers import determine_scheduler_phase
from app.web import runtime_scheduler_excerpt as web_runtime_scheduler_excerpt
from app.web import runtime_scheduler_signals as web_runtime_scheduler_signals
from app.web import runtime_scheduler_summary as web_runtime_scheduler_summary


def build_scheduler_target_context(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        goal_profile: str = "internal_asset_discovery",
        engagement_preset: str = "",
        attempted_tool_ids: set,
        attempted_family_ids: Optional[set] = None,
        attempted_command_signatures: Optional[set] = None,
        recent_output_chars: int = 900,
        analysis_mode: str = "standard",
) -> Dict[str, Any]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return {}
        scheduler_preferences = runtime.scheduler_config.load()

        session = project.database.session()
        try:
            host_result = session.execute(text(
                "SELECT COALESCE(h.hostname, '') AS hostname, "
                "COALESCE(h.osMatch, '') AS os_match "
                "FROM hostObj AS h WHERE h.id = :host_id LIMIT 1"
            ), {"host_id": int(host_id or 0)}).fetchone()
            hostname = str(host_result[0] or "") if host_result else ""
            os_match = str(host_result[1] or "") if host_result else ""

            service_result = session.execute(text(
                "SELECT COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "AND COALESCE(p.portId, '') = :port "
                "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "host_id": int(host_id or 0),
                "port": str(port or ""),
                "protocol": str(protocol or "tcp"),
            }).fetchone()
            service_name_db = str(service_result[0] or "") if service_result else ""
            service_product = str(service_result[1] or "") if service_result else ""
            service_version = str(service_result[2] or "") if service_result else ""
            service_extrainfo = str(service_result[3] or "") if service_result else ""
            target_service = str(service_name or service_name_db or "").strip()

            host_port_rows = session.execute(text(
                "SELECT COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol, "
                "COALESCE(p.state, '') AS state, "
                "COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "ORDER BY p.id ASC LIMIT 280"
            ), {
                "host_id": int(host_id or 0),
            }).fetchall()

            script_rows = session.execute(text(
                "SELECT COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS output, "
                "COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol "
                "FROM l1ScriptObj AS s "
                "LEFT JOIN portObj AS p ON p.id = s.portId "
                "WHERE s.hostId = :host_id "
                "ORDER BY s.id DESC LIMIT 260"
            ), {
                "host_id": int(host_id or 0),
            }).fetchall()

            process_rows = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(p.status, '') AS status, "
                "COALESCE(p.command, '') AS command_text, "
                "COALESCE(o.output, '') AS output_text, "
                "COALESCE(p.port, '') AS port, "
                "COALESCE(p.protocol, '') AS protocol "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 180"
            ), {
                "host_ip": str(host_ip or ""),
            }).fetchall()
        finally:
            session.close()

    try:
        host_cves_raw = runtime._load_cves_for_host(project, int(host_id or 0))
    except Exception:
        host_cves_raw = []

    target_port_value = str(port or "")
    target_protocol_value = str(protocol or "tcp").lower()

    port_scripts = {}
    port_banners = {}
    scripts = []
    target_scripts = []
    analysis_output_chars = max(int(recent_output_chars) * 4, 1600)
    for row in script_rows:
        script_id = str(row[0] or "").strip()
        output = web_runtime_scheduler_excerpt.build_scheduler_prompt_excerpt(row[1], int(recent_output_chars))
        analysis_output = web_runtime_scheduler_excerpt.build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars))
        script_port = str(row[2] or "").strip()
        script_protocol = str(row[3] or "tcp").strip().lower() or "tcp"
        if not script_id and not output and not analysis_output:
            continue
        item = {
            "script_id": script_id,
            "port": script_port,
            "protocol": script_protocol,
            "excerpt": output,
            "analysis_excerpt": analysis_output,
        }
        scripts.append(item)
        if not script_port or (script_port == target_port_value and script_protocol == target_protocol_value):
            target_scripts.append(item)

        if script_port:
            key = (script_port, script_protocol)
            if script_id:
                port_scripts.setdefault(key, []).append(script_id)
            if key not in port_banners:
                candidate_banner = web_runtime_scheduler_excerpt.scheduler_banner_from_evidence(script_id, analysis_output or output)
                if candidate_banner:
                    port_banners[key] = candidate_banner

    recent_processes = []
    target_recent_processes = []
    for row in process_rows:
        tool_id = str(row[0] or "").strip()
        status = str(row[1] or "").strip()
        command_text = web_runtime_scheduler_excerpt.truncate_scheduler_text(row[2], 220)
        output_text = web_runtime_scheduler_excerpt.build_scheduler_prompt_excerpt(row[3], int(recent_output_chars))
        analysis_output = web_runtime_scheduler_excerpt.build_scheduler_analysis_excerpt(row[3], int(analysis_output_chars))
        process_port = str(row[4] or "").strip()
        process_protocol = str(row[5] or "tcp").strip().lower() or "tcp"
        if not tool_id and not output_text and not analysis_output:
            continue
        item = {
            "tool_id": tool_id,
            "status": status,
            "port": process_port,
            "protocol": process_protocol,
            "command_excerpt": command_text,
            "output_excerpt": output_text,
            "analysis_excerpt": analysis_output,
        }
        recent_processes.append(item)
        if process_port == target_port_value and process_protocol == target_protocol_value:
            target_recent_processes.append(item)

        if process_port:
            key = (process_port, process_protocol)
            if key not in port_banners:
                candidate_banner = web_runtime_scheduler_excerpt.scheduler_banner_from_evidence(tool_id, analysis_output or output_text)
                if candidate_banner:
                    port_banners[key] = candidate_banner

    host_port_inventory = []
    host_open_services = set()
    host_open_ports = []
    host_banner_hints = []
    for row in host_port_rows:
        port_value = str(row[0] or "").strip()
        port_protocol = str(row[1] or "tcp").strip().lower() or "tcp"
        state_value = str(row[2] or "").strip()
        service_value = str(row[3] or "").strip()
        product_value = str(row[4] or "").strip()
        version_value = str(row[5] or "").strip()
        extra_value = str(row[6] or "").strip()

        key = (port_value, port_protocol)
        banner_value = str(port_banners.get(key, "") or "")
        if not banner_value:
            banner_value = web_runtime_scheduler_excerpt.scheduler_service_banner_fallback(
                service_name=service_value,
                product=product_value,
                version=version_value,
                extrainfo=extra_value,
            )
        if state_value in {"open", "open|filtered"}:
            if service_value:
                host_open_services.add(service_value)
            if port_value:
                host_open_ports.append(f"{port_value}/{port_protocol}:{service_value or 'unknown'}")
            if banner_value:
                host_banner_hints.append(f"{port_value}/{port_protocol}:{banner_value}")

        host_port_inventory.append({
            "port": port_value,
            "protocol": port_protocol,
            "state": state_value,
            "service": service_value,
            "service_product": product_value,
            "service_version": version_value,
            "service_extrainfo": extra_value,
            "banner": banner_value,
            "scripts": port_scripts.get(key, [])[:12],
        })

    inferred_technologies = runtime._infer_technologies_from_observations(
        service_records=[
            {
                "port": str(item.get("port", "") or ""),
                "protocol": str(item.get("protocol", "") or ""),
                "service_name": str(item.get("service", "") or ""),
                "service_product": str(item.get("service_product", "") or ""),
                "service_version": str(item.get("service_version", "") or ""),
                "service_extrainfo": str(item.get("service_extrainfo", "") or ""),
                "banner": str(item.get("banner", "") or ""),
            }
            for item in host_port_inventory
            if isinstance(item, dict)
        ],
        script_records=scripts,
        process_records=recent_processes,
        limit=64,
    )

    target_data = {
        "host_ip": str(host_ip or ""),
        "hostname": str(hostname or ""),
        "root_domain": registrable_root_domain(str(hostname or "").strip()) or registrable_root_domain(str(host_ip or "").strip()),
        "os": str(os_match or ""),
        "port": str(port or ""),
        "protocol": str(protocol or "tcp"),
        "service": str(target_service or service_name or ""),
        "service_product": str(service_product or ""),
        "service_version": str(service_version or ""),
        "service_extrainfo": str(service_extrainfo or ""),
        "engagement_preset": str(engagement_preset or "").strip().lower(),
        "host_open_services": sorted(host_open_services)[:48],
        "host_open_ports": host_open_ports[:120],
        "host_banners": host_banner_hints[:80],
        "grayhatwarfare_enabled": runtime._grayhatwarfare_integration_enabled(scheduler_preferences),
        "shodan_enabled": runtime._shodan_integration_enabled(scheduler_preferences),
    }
    signals = web_runtime_scheduler_signals.extract_scheduler_signals(
        runtime,
        service_name=target_data["service"],
        scripts=scripts,
        recent_processes=recent_processes,
        target=target_data,
    )
    tool_audit = runtime._scheduler_tool_audit_snapshot()

    ai_state = runtime._load_host_ai_analysis(project, int(host_id or 0), str(host_ip or ""))
    ai_context_state = {}
    if isinstance(ai_state, dict) and ai_state:
        host_updates = ai_state.get("host_updates", {}) if isinstance(ai_state.get("host_updates", {}), dict) else {}

        ai_tech = []
        for item in ai_state.get("technologies", [])[:24]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()[:120]
            version = str(item.get("version", "")).strip()[:120]
            cpe = str(item.get("cpe", "")).strip()[:220]
            evidence = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("evidence", ""), 260)
            if not name and not cpe:
                continue
            ai_tech.append({
                "name": name,
                "version": version,
                "cpe": cpe,
                "evidence": evidence,
            })

        ai_findings = []
        for item in ai_state.get("findings", [])[:24]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()[:240]
            severity = str(item.get("severity", "")).strip().lower()[:16]
            cve_id = str(item.get("cve", "")).strip()[:64]
            evidence = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("evidence", ""), 260)
            if not title and not cve_id:
                continue
            ai_findings.append({
                "title": title,
                "severity": severity,
                "cve": cve_id,
                "evidence": evidence,
            })

        ai_manual_tests = []
        for item in ai_state.get("manual_tests", [])[:16]:
            if not isinstance(item, dict):
                continue
            command = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("command", ""), 260)
            why = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("why", ""), 180)
            if not command and not why:
                continue
            ai_manual_tests.append({
                "command": command,
                "why": why,
                "scope_note": web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("scope_note", ""), 160),
            })

        merged_context_tech = runtime._merge_technologies(
            existing=inferred_technologies,
            incoming=ai_tech,
            limit=64,
        )

        ai_context_state = {
            "updated_at": str(ai_state.get("updated_at", "") or ""),
            "provider": str(ai_state.get("provider", "") or ""),
            "goal_profile": str(ai_state.get("goal_profile", "") or ""),
            "next_phase": str(ai_state.get("next_phase", "") or ""),
            "host_updates": {
                "hostname": str(host_updates.get("hostname", "") or ""),
                "hostname_confidence": runtime._ai_confidence_value(host_updates.get("hostname_confidence", 0.0)),
                "os": str(host_updates.get("os", "") or ""),
                "os_confidence": runtime._ai_confidence_value(host_updates.get("os_confidence", 0.0)),
            },
            "technologies": merged_context_tech,
            "findings": ai_findings,
            "manual_tests": ai_manual_tests,
        }
        reflection = ai_state.get("reflection", {}) if isinstance(ai_state.get("reflection", {}), dict) else {}
        if reflection:
            ai_context_state["reflection"] = {
                "state": str(reflection.get("state", "") or "")[:24],
                "priority_shift": str(reflection.get("priority_shift", "") or "")[:64],
                "reason": web_runtime_scheduler_excerpt.truncate_scheduler_text(reflection.get("reason", ""), 220),
                "promote_tool_ids": [
                    str(item or "").strip().lower()[:80]
                    for item in list(reflection.get("promote_tool_ids", []) or [])[:8]
                    if str(item or "").strip()
                ],
                "suppress_tool_ids": [
                    str(item or "").strip().lower()[:80]
                    for item in list(reflection.get("suppress_tool_ids", []) or [])[:8]
                    if str(item or "").strip()
                ],
            }

        ai_observed_tech = [
            str(item.get("name", "")).strip().lower()
            for item in merged_context_tech
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ]
        if ai_observed_tech:
            existing_observed = signals.get("observed_technologies", [])
            if not isinstance(existing_observed, list):
                existing_observed = []
            merged_observed = []
            seen_observed = set()
            for marker in existing_observed + ai_observed_tech:
                token = str(marker or "").strip().lower()
                if not token or token in seen_observed:
                    continue
                seen_observed.add(token)
                merged_observed.append(token)
            if merged_observed:
                signals["observed_technologies"] = merged_observed[:24]
    elif inferred_technologies:
        ai_context_state = {
            "updated_at": "",
            "provider": "",
            "goal_profile": "",
            "next_phase": "",
            "host_updates": {
                "hostname": "",
                "hostname_confidence": 0.0,
                "os": "",
                "os_confidence": 0.0,
            },
            "technologies": inferred_technologies,
            "findings": [],
            "manual_tests": [],
        }
        inferred_names = [
            str(item.get("name", "")).strip().lower()
            for item in inferred_technologies
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ]
        if inferred_names:
            existing_observed = signals.get("observed_technologies", [])
            if not isinstance(existing_observed, list):
                existing_observed = []
            merged_observed = []
            seen_observed = set()
            for marker in existing_observed + inferred_names:
                token = str(marker or "").strip().lower()
                if not token or token in seen_observed:
                    continue
                seen_observed.add(token)
                merged_observed.append(token)
            if merged_observed:
                signals["observed_technologies"] = merged_observed[:24]

    host_cves = []
    for row in host_cves_raw[:120]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "") or "").strip()[:96]
        severity = str(row.get("severity", "") or "").strip().lower()[:24]
        product = str(row.get("product", "") or "").strip()[:120]
        version = str(row.get("version", "") or "").strip()[:80]
        url = str(row.get("url", "") or "").strip()[:220]
        if not any([name, severity, product, version, url]):
            continue
        host_cves.append({
            "name": name,
            "severity": severity,
            "product": product,
            "version": version,
            "url": url,
        })

    observed_tool_ids = set()
    observed_tool_ids.update({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()})
    for item in scripts:
        if not isinstance(item, dict):
            continue
        token = str(item.get("script_id", "")).strip().lower()
        if token:
            observed_tool_ids.add(token)
    for item in recent_processes:
        if not isinstance(item, dict):
            continue
        token = str(item.get("tool_id", "")).strip().lower()
        if token:
            observed_tool_ids.add(token)

    coverage = web_runtime_scheduler_summary.build_scheduler_coverage_summary(
        service_name=str(target_data.get("service", "") or service_name or ""),
        signals=signals,
        observed_tool_ids=observed_tool_ids,
        host_cves=host_cves,
        inferred_technologies=inferred_technologies,
        analysis_mode=analysis_mode,
    )
    current_phase = determine_scheduler_phase(
        goal_profile=str(goal_profile or "internal_asset_discovery"),
        service=str(target_data.get("service", "") or service_name or ""),
        engagement_preset=str(engagement_preset or ""),
        context={
            "analysis_mode": str(analysis_mode or "standard"),
            "signals": signals,
            "coverage": coverage,
            "attempted_tool_ids": sorted(
                {str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}
            ),
        },
    )
    context_summary = web_runtime_scheduler_summary.build_scheduler_context_summary(
        target=target_data,
        analysis_mode=str(analysis_mode or "standard"),
        coverage=coverage,
        signals=signals,
        current_phase=current_phase,
        attempted_tool_ids=attempted_tool_ids,
        attempted_family_ids=attempted_family_ids,
        summary_technologies=(
            ai_context_state.get("technologies", [])
            if isinstance(ai_context_state.get("technologies", []), list) and ai_context_state.get("technologies", [])
            else inferred_technologies
        ),
        host_cves=host_cves,
        host_ai_state=ai_context_state,
        recent_processes=recent_processes,
        target_recent_processes=target_recent_processes,
    )
    runtime._persist_shared_target_state(
        host_id=int(host_id or 0),
        host_ip=str(host_ip or ""),
        port=str(port or ""),
        protocol=str(protocol or "tcp"),
        service_name=str(target_data.get("service", "") or service_name or ""),
        hostname=str(target_data.get("hostname", "") or ""),
        hostname_confidence=95.0 if str(target_data.get("hostname", "") or "").strip() else 0.0,
        os_match=str(target_data.get("os", "") or ""),
        os_confidence=70.0 if str(target_data.get("os", "") or "").strip() else 0.0,
        technologies=inferred_technologies[:64],
        service_inventory=host_port_inventory,
        coverage=coverage,
    )

    return {
        "target": target_data,
        "engagement_preset": str(engagement_preset or "").strip().lower(),
        "signals": signals,
        "tool_audit": tool_audit,
        "attempted_tool_ids": sorted({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}),
        "attempted_family_ids": sorted({str(item).strip().lower() for item in list(attempted_family_ids or set()) if str(item).strip()}),
        "attempted_command_signatures": sorted({str(item).strip().lower() for item in list(attempted_command_signatures or set()) if str(item).strip()}),
        "host_ports": host_port_inventory,
        "scripts": scripts,
        "recent_processes": recent_processes,
        "target_scripts": target_scripts,
        "target_recent_processes": target_recent_processes,
        "inferred_technologies": inferred_technologies[:64],
        "host_cves": host_cves,
        "coverage": coverage,
        "analysis_mode": str(analysis_mode or "standard").strip().lower() or "standard",
        "context_summary": context_summary,
        "host_ai_state": ai_context_state,
    }
