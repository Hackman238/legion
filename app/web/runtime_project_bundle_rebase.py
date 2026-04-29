from __future__ import annotations

import json
import os
import re
import sqlite3
from typing import Any, Dict, List, Tuple


def normalize_restore_compare_path(path: str) -> str:
    token = str(path or "").strip()
    if not token:
        return ""
    normalized = os.path.normpath(token.replace("\\", "/"))
    if normalized == ".":
        return ""
    return normalized.rstrip("/")


def looks_like_absolute_path(value: str) -> bool:
    token = normalize_restore_compare_path(value)
    if not token:
        return False
    return bool(token.startswith("/") or re.match(r"^[A-Za-z]:/", token))


def path_tail(path: str, depth: int = 2) -> str:
    token = normalize_restore_compare_path(path)
    if not token:
        return ""
    parts = [part for part in token.split("/") if part]
    return "/".join(parts[-max(1, int(depth or 2)):])


def build_restore_root_mappings(
        *,
        manifest: Dict[str, Any],
        project_path: str,
        output_folder: str,
        running_folder: str,
) -> List[Tuple[str, str]]:
    _ = project_path
    candidates: List[Tuple[str, str]] = []
    old_output_folder = str(manifest.get("output_folder", "") or "").strip()
    old_running_folder = str(manifest.get("running_folder", "") or "").strip()
    for old_root, new_root in (
            (old_output_folder, output_folder),
            (old_running_folder, running_folder),
    ):
        old_norm = normalize_restore_compare_path(old_root)
        new_norm = normalize_restore_compare_path(os.path.abspath(str(new_root or "").strip()))
        if not old_norm or not new_norm:
            continue
        candidates.append((old_norm, new_norm))

    deduped: List[Tuple[str, str]] = []
    seen = set()
    for old_root, new_root in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
        key = (old_root, new_root)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((old_root, new_root))
    return deduped


def build_restore_text_replacements(root_mappings: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    replacements: List[Tuple[str, str]] = []
    seen = set()
    for old_root, new_root in list(root_mappings or []):
        paired_variants = [
            (str(old_root or "").strip(), str(new_root or "").strip()),
            (
                str(old_root or "").strip().replace("/", "\\"),
                str(new_root or "").strip().replace("/", "\\"),
            ),
        ]
        for old_variant, new_variant in paired_variants:
            pair = (old_variant, new_variant)
            if not old_variant or pair in seen:
                continue
            seen.add(pair)
            replacements.append(pair)
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    return replacements


def replace_restore_roots_in_text(value: str, text_replacements: List[Tuple[str, str]]) -> str:
    result = str(value or "")
    for old_root, new_root in list(text_replacements or []):
        if old_root and old_root in result:
            result = result.replace(old_root, new_root)
    return result


def build_restore_basename_index(roots: List[str]) -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = {}
    for root in list(roots or []):
        normalized_root = os.path.abspath(str(root or "").strip())
        if not normalized_root or not os.path.isdir(normalized_root):
            continue
        for base, _dirs, files in os.walk(normalized_root):
            for file_name in files:
                full_path = os.path.normpath(os.path.join(base, file_name)).replace("\\", "/")
                key = str(file_name or "").strip().lower()
                if not key:
                    continue
                index.setdefault(key, [])
                if full_path not in index[key]:
                    index[key].append(full_path)
    return index


def match_rebased_candidate(raw_value: str, candidates: List[str]) -> str:
    if not candidates:
        return str(raw_value or "")
    if len(candidates) == 1:
        return str(candidates[0])
    for depth in (3, 2):
        tail = path_tail(raw_value, depth=depth)
        if not tail:
            continue
        matches = [candidate for candidate in list(candidates) if path_tail(candidate, depth=depth) == tail]
        if len(matches) == 1:
            return str(matches[0])
    return str(raw_value or "")


def rebase_restored_file_reference(
        value: str,
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
) -> str:
    _ = root_mappings
    raw_value = str(value or "").strip()
    if not raw_value or raw_value.startswith("process_output:"):
        return raw_value
    if raw_value.startswith(("http://", "https://", "data:")):
        return raw_value

    replaced = replace_restore_roots_in_text(raw_value, text_replacements)
    replaced_norm = normalize_restore_compare_path(replaced)
    if replaced_norm and replaced != raw_value and looks_like_absolute_path(replaced_norm):
        return replaced_norm

    normalized_raw = normalize_restore_compare_path(raw_value)
    if not looks_like_absolute_path(normalized_raw):
        return replaced if replaced != raw_value else raw_value

    basename = os.path.basename(normalized_raw)
    if not basename:
        return replaced if replaced != raw_value else raw_value

    candidates = basename_index.get(str(basename or "").strip().lower(), [])
    matched = match_rebased_candidate(normalized_raw, candidates)
    return matched if matched != normalized_raw else (replaced if replaced != raw_value else raw_value)


def rewrite_restored_json_value(
        value: Any,
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
        key_name: str = "",
) -> Any:
    if isinstance(value, dict):
        return {
            key: rewrite_restored_json_value(
                item,
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
                key_name=str(key or ""),
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            rewrite_restored_json_value(
                item,
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
                key_name=str(key_name or ""),
            )
            for item in value
        ]
    if not isinstance(value, str):
        return value

    key_token = str(key_name or "").strip().lower()
    if key_token in {
        "artifact_ref",
        "ref",
        "stdout_ref",
        "stderr_ref",
        "source_ref",
        "outputfile",
        "path",
        "screenshot_path",
    }:
        return rebase_restored_file_reference(
            value,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
    if key_token in {"command", "command_template", "evidence_refs"}:
        return replace_restore_roots_in_text(value, text_replacements)

    replaced = replace_restore_roots_in_text(value, text_replacements)
    if replaced != value:
        replaced_norm = normalize_restore_compare_path(replaced)
        if replaced_norm and looks_like_absolute_path(replaced_norm):
            return replaced_norm
        return replaced
    if looks_like_absolute_path(value):
        return rebase_restored_file_reference(
            value,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
    return value


def sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> List[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    except Exception:
        return []
    return [str(row[1]) for row in rows if len(row) > 1]


def rewrite_restored_json_text(
        raw_json: Any,
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
) -> Any:
    token = str(raw_json or "").strip()
    if not token:
        return str(raw_json or "")
    try:
        parsed = json.loads(token)
    except Exception:
        return replace_restore_roots_in_text(token, text_replacements)
    rewritten = rewrite_restored_json_value(
        parsed,
        root_mappings=root_mappings,
        text_replacements=text_replacements,
        basename_index=basename_index,
    )
    try:
        return json.dumps(rewritten, ensure_ascii=False)
    except Exception:
        return token


def rewrite_sqlite_table_rows(
        connection: sqlite3.Connection,
        table_name: str,
        column_modes: Dict[str, str],
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
) -> None:
    available_columns = set(sqlite_table_columns(connection, table_name))
    target_columns = [column for column in list(column_modes or {}) if column in available_columns]
    if not target_columns:
        return
    quoted_columns = ", ".join(f'"{column}"' for column in target_columns)
    try:
        rows = connection.execute(f'SELECT rowid, {quoted_columns} FROM "{table_name}"').fetchall()
    except Exception:
        return

    for row in rows:
        rowid = row[0]
        updates: Dict[str, Any] = {}
        for index, column_name in enumerate(target_columns, start=1):
            original = row[index]
            mode = str(column_modes.get(column_name, "text") or "text").strip().lower()
            if mode == "json":
                rewritten = rewrite_restored_json_text(
                    original,
                    root_mappings=root_mappings,
                    text_replacements=text_replacements,
                    basename_index=basename_index,
                )
            elif mode == "path":
                rewritten = rebase_restored_file_reference(
                    str(original or ""),
                    root_mappings=root_mappings,
                    text_replacements=text_replacements,
                    basename_index=basename_index,
                )
            else:
                rewritten = replace_restore_roots_in_text(str(original or ""), text_replacements)
            if rewritten != original:
                updates[column_name] = rewritten
        if not updates:
            continue
        assignments = ", ".join(f'"{column}" = ?' for column in updates)
        params = list(updates.values()) + [rowid]
        connection.execute(f'UPDATE "{table_name}" SET {assignments} WHERE rowid = ?', params)


def rebase_restored_project_paths(
        *,
        project_path: str,
        manifest: Dict[str, Any],
        output_folder: str,
        running_folder: str,
) -> None:
    root_mappings = build_restore_root_mappings(
        manifest=manifest,
        project_path=project_path,
        output_folder=output_folder,
        running_folder=running_folder,
    )
    if not root_mappings:
        return
    text_replacements = build_restore_text_replacements(root_mappings)
    basename_index = build_restore_basename_index([output_folder, running_folder])
    connection = sqlite3.connect(str(project_path))
    try:
        rewrite_sqlite_table_rows(
            connection,
            "process",
            {"outputfile": "path", "command": "text"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_pending_approval",
            {"command_template": "text", "evidence_refs": "text"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_execution_record",
            {
                "stdout_ref": "path",
                "stderr_ref": "path",
                "artifact_refs_json": "json",
                "observations_created_json": "json",
                "graph_mutations_json": "json",
            },
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_target_state",
            {
                "technologies_json": "json",
                "findings_json": "json",
                "manual_tests_json": "json",
                "service_inventory_json": "json",
                "urls_json": "json",
                "coverage_gaps_json": "json",
                "attempted_actions_json": "json",
                "credentials_json": "json",
                "sessions_json": "json",
                "screenshots_json": "json",
                "artifacts_json": "json",
                "raw_json": "json",
            },
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_host_ai_state",
            {
                "technologies_json": "json",
                "findings_json": "json",
                "manual_tests_json": "json",
                "raw_json": "json",
            },
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "graph_node",
            {"source_ref": "path", "properties_json": "json"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "graph_edge",
            {"source_ref": "path", "properties_json": "json"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "graph_evidence_ref",
            {"evidence_ref": "text"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        connection.commit()
    finally:
        connection.close()
