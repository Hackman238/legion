from __future__ import annotations

from typing import Any, Dict, Optional

from app.hostsfile import registrable_root_domain
from app.scheduler.providers import determine_scheduler_phase
from app.web import runtime_scheduler_excerpt as web_runtime_scheduler_excerpt
from app.web import runtime_scheduler_host_ai_context as web_runtime_scheduler_host_ai_context
from app.web import runtime_scheduler_host_evidence as web_runtime_scheduler_host_evidence
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
    evidence = web_runtime_scheduler_host_evidence.load_scheduler_host_evidence(
        runtime,
        host_id=int(host_id or 0),
        host_ip=str(host_ip or ""),
        port=str(port or ""),
        protocol=str(protocol or "tcp"),
    )
    if not evidence:
        return {}
    project = evidence["project"]
    scheduler_preferences = evidence["scheduler_preferences"]
    hostname = evidence["hostname"]
    os_match = evidence["os_match"]
    service_name_db = evidence["service_name_db"]
    service_product = evidence["service_product"]
    service_version = evidence["service_version"]
    service_extrainfo = evidence["service_extrainfo"]
    host_port_rows = evidence["host_port_rows"]
    script_rows = evidence["script_rows"]
    process_rows = evidence["process_rows"]
    host_cves_raw = evidence["host_cves_raw"]
    target_service = str(service_name or service_name_db or "").strip()

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
    ai_context_state, signals = web_runtime_scheduler_host_ai_context.build_host_ai_context_state(
        runtime,
        ai_state=ai_state if isinstance(ai_state, dict) else {},
        inferred_technologies=inferred_technologies,
        signals=signals,
    )

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
