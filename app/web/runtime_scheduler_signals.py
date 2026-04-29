from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.scheduler.planner import SchedulerPlanner
from app.web import runtime_scheduler_excerpt as web_runtime_scheduler_excerpt


def extract_scheduler_signals(
        runtime,
        *,
        service_name: str,
        scripts: List[Dict[str, Any]],
        recent_processes: List[Dict[str, Any]],
        target: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    service_lower = str(service_name or "").strip().lower()
    target_meta = target if isinstance(target, dict) else {}
    target_blob = " ".join([
        str(target_meta.get("hostname", "") or ""),
        str(target_meta.get("os", "") or ""),
        str(target_meta.get("service", "") or ""),
        str(target_meta.get("service_product", "") or ""),
        str(target_meta.get("service_version", "") or ""),
        str(target_meta.get("service_extrainfo", "") or ""),
        " ".join(str(item or "") for item in target_meta.get("host_open_services", []) if str(item or "").strip()),
        " ".join(str(item or "") for item in target_meta.get("host_open_ports", []) if str(item or "").strip()),
        " ".join(str(item or "") for item in target_meta.get("host_banners", []) if str(item or "").strip()),
    ]).lower()
    script_blob = "\n".join(
        " ".join([
            str(item.get("script_id", "")).strip(),
            runtime._observation_text_for_analysis(
                item.get("script_id", ""),
                item.get("analysis_excerpt", "") or item.get("excerpt", ""),
            ),
        ]).strip()
        for item in scripts
    ).lower()
    process_blob = "\n".join(
        " ".join([
            str(item.get("tool_id", "")).strip(),
            str(item.get("status", "")).strip(),
            runtime._observation_text_for_analysis(
                item.get("tool_id", ""),
                item.get("analysis_excerpt", "") or item.get("output_excerpt", ""),
            ),
        ]).strip()
        for item in recent_processes
    ).lower()
    signal_evidence_blob = "\n".join(
        text_value
        for text_value in (
            str(service_name or "").strip().lower(),
            target_blob,
            "\n".join(
                runtime._observation_text_for_analysis(
                    item.get("script_id", ""),
                    item.get("analysis_excerpt", "") or item.get("excerpt", ""),
                )
                for item in scripts
                if isinstance(item, dict)
            ).lower(),
            "\n".join(
                runtime._observation_text_for_analysis(
                    item.get("tool_id", ""),
                    item.get("analysis_excerpt", "") or item.get("output_excerpt", ""),
                )
                for item in recent_processes
                if isinstance(item, dict)
            ).lower(),
        )
        if str(text_value or "").strip()
    )
    combined = f"{target_blob}\n{script_blob}\n{process_blob}"

    missing_tools = set()
    missing_tools.update(web_runtime_scheduler_excerpt.extract_unavailable_tool_tokens(target_blob))
    missing_tools.update(web_runtime_scheduler_excerpt.extract_unavailable_tool_tokens(script_blob))
    for item in recent_processes:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get("tool_id", "") or "").strip().lower()
        tool_tokens = web_runtime_scheduler_excerpt.scheduler_tool_alias_tokens(item.get("tool_id", ""))
        process_failure_blob = "\n".join([
            str(item.get("status", "") or ""),
            str(item.get("output_excerpt", "") or ""),
        ])
        missing_nse_scripts = web_runtime_scheduler_excerpt.extract_missing_nse_script_tokens(process_failure_blob)
        if missing_nse_scripts:
            missing_tools.update(token for token in missing_nse_scripts if token.endswith(".nse"))
            if tool_id.endswith(".nse"):
                missing_tools.add(tool_id)
            continue
        if web_runtime_scheduler_excerpt.looks_like_local_tool_dependency_failure(process_failure_blob):
            if tool_tokens:
                missing_tools.update(tool_tokens)
            elif tool_id:
                missing_tools.add(tool_id)
            continue
        detected = web_runtime_scheduler_excerpt.extract_unavailable_tool_tokens(process_failure_blob)
        if not detected:
            continue
        if tool_tokens and detected & tool_tokens:
            missing_tools.update(tool_tokens)
        else:
            missing_tools.update(detected)

    cve_hits = set(re.findall(r"\bcve-\d{4}-\d+\b", signal_evidence_blob))
    allow_blob = ""
    allow_match = re.search(r"allow:\s*([^\n]+)", signal_evidence_blob)
    if allow_match:
        allow_blob = str(allow_match.group(1) or "").lower()
    webdav_via_allow = any(token in allow_blob for token in ["propfind", "proppatch", "mkcol", "copy", "move"])

    iis_detected = any(token in signal_evidence_blob for token in [
        "microsoft-iis",
        " iis ",
        "iis/7",
        "iis/8",
        "iis/10",
    ])
    webdav_detected = (
        "webdav" in signal_evidence_blob
        or webdav_via_allow
        or ("dav" in signal_evidence_blob and ("propfind" in signal_evidence_blob or "proppatch" in signal_evidence_blob))
    )
    vmware_detected = any(token in signal_evidence_blob for token in ["vmware", "vsphere", "vcenter", "esxi"])
    coldfusion_detected = any(token in signal_evidence_blob for token in ["coldfusion", "cfusion", "adobe coldfusion", "jrun"])
    huawei_detected = any(token in signal_evidence_blob for token in ["huawei", "hg5x", "hgw"])
    ubiquiti_detected = any(token in signal_evidence_blob for token in ["ubiquiti", "unifi", "dream machine", "udm"])
    wordpress_detected = any(
        token in signal_evidence_blob
        for token in ["wordpress", "wp-content", "wp-includes", "wp-json", "/wp-admin", "xmlrpc.php"]
    )
    aws_detected = any(token in signal_evidence_blob for token in [
        "amazon web services",
        "amazonaws.com",
        "aws ",
        " aws",
        "x-amz-",
        "amazon rds",
        "amazon aurora",
        "rds.amazonaws.com",
    ])
    azure_detected = any(token in signal_evidence_blob for token in [
        "microsoft azure",
        "azure",
        "blob.core.windows.net",
        "dfs.core.windows.net",
        "x-ms-",
        "documents.azure.com",
        "cosmos db",
        "cosmosdb",
    ])
    gcp_detected = any(token in signal_evidence_blob for token in [
        "google cloud",
        "storage.googleapis.com",
        "storage.cloud.google.com",
        "googleapis.com",
        "x-goog-",
        " gcp ",
        "cloudsql",
        "google cloud sql",
    ])
    rds_detected = any(token in signal_evidence_blob for token in [
        "amazon rds",
        "aws rds",
        "rds.amazonaws.com",
        "relational database service",
    ])
    aurora_detected = any(token in signal_evidence_blob for token in [
        "amazon aurora",
        "aws aurora",
        "aurora mysql",
        "aurora postgresql",
    ]) or (
        "rds.amazonaws.com" in signal_evidence_blob
        and any(token in signal_evidence_blob for token in [".cluster-", ".cluster-ro-", "aurora"])
    )
    cosmos_detected = any(token in signal_evidence_blob for token in [
        "azure cosmos",
        "cosmos db",
        "cosmosdb",
        "documents.azure.com",
        "mongo.cosmos.azure.com",
        "cassandra.cosmos.azure.com",
        "gremlin.cosmos.azure.com",
        "table.cosmos.azure.com",
    ])
    cloudsql_detected = any(token in signal_evidence_blob for token in [
        "google cloud sql",
        "cloudsql",
        "sqladmin.googleapis.com",
    ])
    mysql_detected = service_lower == "mysql" or any(token in signal_evidence_blob for token in ["mysql", "mariadb"])
    postgresql_detected = service_lower in {"postgres", "postgresql"} or any(
        token in signal_evidence_blob for token in ["postgresql", "postgres ", "pgsql"]
    )
    mssql_detected = service_lower in {"ms-sql", "ms-sql-s", "codasrv-se", "mssql"} or any(
        token in signal_evidence_blob for token in ["microsoft sql server", "ms-sql", "mssql"]
    )
    aws_storage_detected = any(token in signal_evidence_blob for token in [
        "s3.amazonaws.com",
        "amazon s3",
        "aws s3",
        "s3 bucket",
        "bucket.s3",
        "x-amz-bucket",
        "x-amz-request-id",
    ])
    azure_storage_detected = any(token in signal_evidence_blob for token in [
        "blob.core.windows.net",
        "dfs.core.windows.net",
        "azure blob",
        "azure storage",
        "x-ms-blob",
        "x-ms-version",
    ])
    gcp_storage_detected = any(token in signal_evidence_blob for token in [
        "storage.googleapis.com",
        "storage.cloud.google.com",
        "google cloud storage",
        "gcs bucket",
        "x-goog-",
    ])
    cloud_public_negation_detected = any(token in signal_evidence_blob for token in [
        "not publicly accessible",
        "public access disabled",
        "anonymous access disabled",
        "private bucket",
        "private container",
        "authentication required",
    ])
    public_exposure_markers_detected = any(token in signal_evidence_blob for token in [
        "public bucket",
        "bucket listing exposed",
        "container listing exposed",
        "blob listing exposed",
        "publicly accessible",
        "public access enabled",
        "anonymous access",
        "anonymous read",
        "anonymous list",
        "unauthenticated access",
        "world-readable",
        "world readable",
        "allusers",
        "authenticatedusers",
        "public acl",
    ]) and not cloud_public_negation_detected
    managed_db_public_markers_detected = any(token in signal_evidence_blob for token in [
        "publicly accessible",
        "public access enabled",
        "public endpoint",
        "public network access",
        "internet reachable",
        "internet exposed",
    ]) and not cloud_public_negation_detected
    cosmos_risk_markers_detected = any(token in signal_evidence_blob for token in [
        "master key",
        "read-only key",
        "readonly key",
        "publicly accessible",
        "public access enabled",
        "public network access",
        "anonymous access",
    ]) and not cloud_public_negation_detected
    aws_storage_exposure_candidate = bool(aws_storage_detected and public_exposure_markers_detected)
    azure_storage_exposure_candidate = bool(azure_storage_detected and public_exposure_markers_detected)
    gcp_storage_exposure_candidate = bool(gcp_storage_detected and public_exposure_markers_detected)
    rds_public_access_candidate = bool(rds_detected and managed_db_public_markers_detected)
    aurora_public_access_candidate = bool(aurora_detected and managed_db_public_markers_detected)
    cosmos_exposure_candidate = bool(cosmos_detected and cosmos_risk_markers_detected)
    cloudsql_public_access_candidate = bool(cloudsql_detected and managed_db_public_markers_detected)
    cloud_provider_detected = bool(aws_detected or azure_detected or gcp_detected)
    storage_service_detected = bool(aws_storage_detected or azure_storage_detected or gcp_storage_detected)
    storage_exposure_candidate = bool(
        aws_storage_exposure_candidate or azure_storage_exposure_candidate or gcp_storage_exposure_candidate
    )
    managed_db_exposure_candidate = bool(
        rds_public_access_candidate
        or aurora_public_access_candidate
        or cosmos_exposure_candidate
        or cloudsql_public_access_candidate
    )
    cloud_exposure_candidate = bool(storage_exposure_candidate or managed_db_exposure_candidate)

    observed_technologies = []
    for marker, present in (
            ("iis", iis_detected),
            ("webdav", webdav_detected),
            ("vmware", vmware_detected),
            ("coldfusion", coldfusion_detected),
            ("huawei", huawei_detected),
            ("ubiquiti", ubiquiti_detected),
            ("wordpress", wordpress_detected),
            ("aws", aws_detected),
            ("azure", azure_detected),
            ("gcp", gcp_detected),
            ("rds", rds_detected),
            ("aurora", aurora_detected),
            ("cosmos", cosmos_detected),
            ("cloudsql", cloudsql_detected),
            ("cloud_storage", storage_service_detected),
            ("cloud_exposure", cloud_exposure_candidate),
            ("mysql", mysql_detected),
            ("postgresql", postgresql_detected),
            ("mssql", mssql_detected),
            ("nginx", "nginx" in signal_evidence_blob),
            ("apache", "apache" in signal_evidence_blob),
    ):
        if present:
            observed_technologies.append(marker)

    return {
        "web_service": service_lower in SchedulerPlanner.WEB_SERVICE_IDS,
        "rdp_service": service_lower in {"rdp", "ms-wbt-server", "vmrdp"},
        "vnc_service": service_lower in {"vnc", "vnc-http", "rfb"},
        "tls_detected": any(token in signal_evidence_blob for token in ["ssl", "tls", "certificate", "https"]),
        "smb_signing_disabled": any(token in combined for token in [
            "message signing enabled but not required",
            "smb signing disabled",
            "signing: disabled",
            "signing: false",
        ]),
        "directory_listing": "index of /" in signal_evidence_blob or "directory listing" in signal_evidence_blob,
        "waf_detected": "waf" in signal_evidence_blob,
        "shodan_enabled": bool(target_meta.get("shodan_enabled", False)),
        "wordpress_detected": wordpress_detected,
        "iis_detected": iis_detected,
        "webdav_detected": webdav_detected,
        "vmware_detected": vmware_detected,
        "coldfusion_detected": coldfusion_detected,
        "huawei_detected": huawei_detected,
        "ubiquiti_detected": ubiquiti_detected,
        "cloud_provider_detected": cloud_provider_detected,
        "storage_service_detected": storage_service_detected,
        "cloud_exposure_candidate": cloud_exposure_candidate,
        "storage_exposure_candidate": storage_exposure_candidate,
        "managed_db_exposure_candidate": managed_db_exposure_candidate,
        "aws_detected": aws_detected,
        "azure_detected": azure_detected,
        "gcp_detected": gcp_detected,
        "rds_detected": rds_detected,
        "aurora_detected": aurora_detected,
        "cosmos_detected": cosmos_detected,
        "cloudsql_detected": cloudsql_detected,
        "aws_storage_detected": aws_storage_detected,
        "azure_storage_detected": azure_storage_detected,
        "gcp_storage_detected": gcp_storage_detected,
        "aws_storage_exposure_candidate": aws_storage_exposure_candidate,
        "azure_storage_exposure_candidate": azure_storage_exposure_candidate,
        "gcp_storage_exposure_candidate": gcp_storage_exposure_candidate,
        "rds_public_access_candidate": rds_public_access_candidate,
        "aurora_public_access_candidate": aurora_public_access_candidate,
        "cosmos_exposure_candidate": cosmos_exposure_candidate,
        "cloudsql_public_access_candidate": cloudsql_public_access_candidate,
        "mysql_detected": mysql_detected,
        "postgresql_detected": postgresql_detected,
        "mssql_detected": mssql_detected,
        "observed_technologies": observed_technologies[:12],
        "vuln_hits": len(cve_hits),
        "missing_tools": sorted(missing_tools),
    }
