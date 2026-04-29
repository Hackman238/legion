from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.web import runtime_process_parsing as web_runtime_process_parsing


def list_processes(runtime, limit: int = 75) -> List[Dict[str, Any]]:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return []

    runtime._ensure_process_tables()
    process_repo = project.repositoryContainer.processRepository
    rows = process_repo.getProcesses({}, showProcesses='True', sort='desc', ncol='id')
    trimmed = rows[:limit]
    results = []

    for row in trimmed:
        status = str(row.get("status", "") or "")
        status_lower = status.strip().lower()
        terminal = status_lower in {"finished", "crashed", "problem", "cancelled", "killed", "failed"}
        estimated_remaining = row.get("estimatedRemaining")
        if terminal:
            estimated_remaining = None

        percent_value = str(row.get("percent", "") or "")
        if status_lower == "finished":
            numeric = web_runtime_process_parsing.coerce_float(percent_value)
            if numeric is None or numeric <= 0.0:
                percent_value = "100"

        elapsed_value = row.get("elapsed", 0)
        progress_message = row.get("progressMessage", "")
        progress_source = row.get("progressSource", "")
        progress_updated_at = row.get("progressUpdatedAt", "")

        results.append({
            "id": row.get("id", ""),
            "name": row.get("name", ""),
            "hostIp": row.get("hostIp", ""),
            "port": row.get("port", ""),
            "protocol": row.get("protocol", ""),
            "status": status,
            "startTime": row.get("startTime", ""),
            "elapsed": elapsed_value,
            "percent": percent_value,
            "estimatedRemaining": estimated_remaining,
            "progressMessage": progress_message,
            "progressSource": progress_source,
            "progressUpdatedAt": progress_updated_at,
            "progress": web_runtime_process_parsing.build_process_progress_payload(
                status=status,
                percent=percent_value,
                estimated_remaining=estimated_remaining,
                elapsed=elapsed_value,
                progress_message=progress_message,
                progress_source=progress_source,
                progress_updated_at=progress_updated_at,
            ),
        })
    return results


def process_history_records(
        project,
        limit: Optional[int] = None,
        *,
        redact_command=None,
) -> List[Dict[str, Any]]:
    if not project:
        return []

    session = project.database.session()
    try:
        query = (
            "SELECT "
            "process.id AS id, "
            "COALESCE(process.pid, '') AS pid, "
            "COALESCE(process.display, '') AS display, "
            "COALESCE(process.name, '') AS name, "
            "COALESCE(process.tabTitle, '') AS tabTitle, "
            "COALESCE(process.hostIp, '') AS hostIp, "
            "COALESCE(process.port, '') AS port, "
            "COALESCE(process.protocol, '') AS protocol, "
            "COALESCE(process.command, '') AS command, "
            "COALESCE(process.startTime, '') AS startTime, "
            "COALESCE(process.endTime, '') AS endTime, "
            "process.estimatedRemaining AS estimatedRemaining, "
            "COALESCE(process.elapsed, 0) AS elapsed, "
            "COALESCE(process.outputfile, '') AS outputfile, "
            "COALESCE(process.status, '') AS status, "
            "COALESCE(process.closed, '') AS closed, "
            "COALESCE(process.percent, '') AS percent, "
            "COALESCE(process.progressMessage, '') AS progressMessage, "
            "COALESCE(process.progressSource, '') AS progressSource, "
            "COALESCE(process.progressUpdatedAt, '') AS progressUpdatedAt, "
            "CASE "
            "WHEN EXISTS ("
            "    SELECT 1 FROM process_output AS output "
            "    WHERE output.processId = process.id "
            "    AND COALESCE(output.output, '') != ''"
            ") THEN 1 ELSE 0 END AS hasOutput "
            "FROM process AS process "
            "ORDER BY process.id DESC"
        )
        params: Dict[str, Any] = {}
        if limit is not None:
            resolved_limit = max(1, int(limit or 0))
            query = f"{query} LIMIT :limit"
            params["limit"] = resolved_limit
        result = session.execute(text(query), params)
        rows = result.fetchall()
        keys = result.keys()
        records: List[Dict[str, Any]] = []
        redact = redact_command or (lambda value: str(value or ""))
        for row in rows:
            item = dict(zip(keys, row))
            item["command"] = redact(item.get("command", ""))
            start_time_utc, end_time_utc, prefer_utc_naive = normalize_process_time_range_to_utc(
                item.get("startTime", ""),
                item.get("endTime", ""),
            )
            item["startTimeUtc"] = start_time_utc
            item["endTimeUtc"] = end_time_utc
            item["progressUpdatedAtUtc"] = normalize_process_timestamp_to_utc(
                item.get("progressUpdatedAt", ""),
                prefer_utc_naive=prefer_utc_naive,
            )
            records.append(item)
        return records
    finally:
        session.close()


def normalize_process_timestamp_to_utc(value: Any, *, prefer_utc_naive: bool = False) -> str:
    text_value = str(value or "").strip()
    if not text_value:
        return ""

    candidates = process_timestamp_utc_candidates(
        text_value,
        prefer_utc_naive=prefer_utc_naive,
    )
    if not candidates:
        return ""
    parsed = candidates[0][1]
    return parsed.astimezone(datetime.timezone.utc).isoformat()


def process_timestamp_utc_candidates(
        value: Any,
        *,
        prefer_utc_naive: bool = False,
) -> List[tuple]:
    text_value = str(value or "").strip()
    if not text_value:
        return []

    local_tz = datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc
    candidates: List[tuple] = []
    seen = set()

    def _append(candidate_dt: datetime.datetime, assumption: str):
        utc_dt = candidate_dt.astimezone(datetime.timezone.utc)
        normalized = utc_dt.isoformat()
        key = (normalized, assumption)
        if key in seen:
            return
        seen.add(key)
        candidates.append((normalized, utc_dt, assumption))

    try:
        iso_candidate = f"{text_value[:-1]}+00:00" if text_value.endswith("Z") else text_value
        parsed = datetime.datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is None:
            preferred_tz = datetime.timezone.utc if prefer_utc_naive else local_tz
            _append(parsed.replace(tzinfo=preferred_tz), "iso-naive-utc" if prefer_utc_naive else "iso-naive-local")
            alternate_tz = local_tz if prefer_utc_naive else datetime.timezone.utc
            _append(parsed.replace(tzinfo=alternate_tz), "iso-naive-local" if prefer_utc_naive else "iso-naive-utc")
        else:
            _append(parsed, "iso-aware")
    except ValueError:
        pass

    for fmt in ("%d %b %Y %H:%M:%S.%f", "%d %b %Y %H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(text_value, fmt)
        except ValueError:
            continue
        preferred_tz = datetime.timezone.utc if prefer_utc_naive else local_tz
        _append(parsed.replace(tzinfo=preferred_tz), "human-utc" if prefer_utc_naive else "human-local")
        alternate_tz = local_tz if prefer_utc_naive else datetime.timezone.utc
        _append(parsed.replace(tzinfo=alternate_tz), "human-local" if prefer_utc_naive else "human-utc")
        break

    return candidates


def normalize_process_time_range_to_utc(start_value: Any, end_value: Any) -> tuple:
    start_default = process_timestamp_utc_candidates(start_value, prefer_utc_naive=False)
    end_default = process_timestamp_utc_candidates(end_value, prefer_utc_naive=False)
    start_utc = start_default[0][0] if start_default else ""
    end_utc = end_default[0][0] if end_default else ""

    if not start_default or not end_default:
        return start_utc, end_utc, False

    default_start_dt = start_default[0][1]
    default_end_dt = end_default[0][1]
    if default_start_dt <= default_end_dt:
        prefer_utc_naive = any(candidate[2].endswith("-utc") for candidate in (start_default[0], end_default[0]))
        return start_utc, end_utc, prefer_utc_naive

    best_pair = None
    best_delta = None
    for start_candidate in start_default:
        for end_candidate in end_default:
            start_dt = start_candidate[1]
            end_dt = end_candidate[1]
            if start_dt > end_dt:
                continue
            delta_seconds = abs((end_dt - start_dt).total_seconds())
            if best_delta is None or delta_seconds < best_delta:
                best_delta = delta_seconds
                best_pair = (start_candidate, end_candidate)

    if best_pair is None:
        return start_utc, end_utc, False

    prefer_utc_naive = any(candidate[2].endswith("-utc") for candidate in best_pair)
    return best_pair[0][0], best_pair[1][0], prefer_utc_naive
