from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import zipfile
from typing import Any, Dict, Tuple


def extract_project_bundle_zip(zip_path: str) -> Dict[str, Any]:
    normalized = normalize_existing_file(zip_path)
    if not zipfile.is_zipfile(normalized):
        raise ValueError(f"Invalid ZIP file: {normalized}")

    with zipfile.ZipFile(normalized, "r") as archive:
        try:
            manifest_name, root_prefix, manifest = read_bundle_manifest(archive)
        except ValueError as exc:
            if str(exc) != "Bundle manifest.json is missing.":
                raise
            return extract_legacy_project_zip(archive)
        _ = manifest_name

        session_member = locate_bundle_session_member(
            archive,
            root_prefix=root_prefix,
            manifest=manifest,
        )
        if not session_member:
            raise ValueError("Bundle does not contain a session .legion file.")

        project_file_name = safe_bundle_filename(
            os.path.basename(str(session_member or "").strip()),
            fallback="restored.legion",
        )
        if not project_file_name.lower().endswith(".legion"):
            project_file_name = f"{project_file_name}.legion"
        project_stem = os.path.splitext(project_file_name)[0]

        restore_root = tempfile.mkdtemp(prefix="legion-restore-")
        project_path = os.path.join(restore_root, project_file_name)
        output_folder = os.path.join(restore_root, f"{project_stem}-tool-output")
        running_folder = os.path.join(restore_root, f"{project_stem}-running")

        try:
            os.makedirs(output_folder, exist_ok=True)
            os.makedirs(running_folder, exist_ok=True)

            extract_zip_member_to_file(archive, session_member, project_path)
            extract_zip_prefix_to_dir(
                archive,
                prefix=bundle_prefix(root_prefix, "tool-output"),
                destination_dir=output_folder,
            )
            extract_zip_prefix_to_dir(
                archive,
                prefix=bundle_prefix(root_prefix, "running"),
                destination_dir=running_folder,
            )
        except Exception:
            shutil.rmtree(restore_root, ignore_errors=True)
            raise

    return {
        "restore_root": restore_root,
        "project_path": project_path,
        "output_folder": output_folder,
        "running_folder": running_folder,
        "manifest": manifest,
    }


def extract_legacy_project_zip(archive: zipfile.ZipFile) -> Dict[str, Any]:
    legacy_members = [
        str(name or "").rstrip("/")
        for name in archive.namelist()
        if str(name or "").lower().endswith(".legion") and not str(name or "").endswith("/")
    ]
    if not legacy_members:
        raise ValueError("Bundle manifest.json is missing and ZIP does not contain a .legion session file.")
    unique_members = sorted(set(legacy_members))
    if len(unique_members) > 1:
        preview = ", ".join(unique_members[:3])
        suffix = f", +{len(unique_members) - 3} more" if len(unique_members) > 3 else ""
        raise ValueError(f"Bundle manifest.json is missing and legacy ZIP contains multiple .legion files: {preview}{suffix}")

    session_member = unique_members[0]
    project_file_name = safe_bundle_filename(
        os.path.basename(str(session_member or "").strip()),
        fallback="restored.legion",
    )
    if not project_file_name.lower().endswith(".legion"):
        project_file_name = f"{project_file_name}.legion"
    project_stem = os.path.splitext(project_file_name)[0]

    restore_root = tempfile.mkdtemp(prefix="legion-restore-")
    project_path = os.path.join(restore_root, project_file_name)
    output_folder = os.path.join(restore_root, f"{project_stem}-tool-output")
    running_folder = os.path.join(restore_root, f"{project_stem}-running")

    try:
        os.makedirs(output_folder, exist_ok=True)
        os.makedirs(running_folder, exist_ok=True)
        extract_zip_member_to_file(archive, session_member, project_path)
    except Exception:
        shutil.rmtree(restore_root, ignore_errors=True)
        raise

    return {
        "restore_root": restore_root,
        "project_path": project_path,
        "output_folder": output_folder,
        "running_folder": running_folder,
        "manifest": {
            "format": "legacy-single-legion-zip",
            "project_file": project_file_name,
        },
    }


def bundle_prefix(root_prefix: str, leaf: str) -> str:
    root = str(root_prefix or "").strip("/")
    suffix = str(leaf or "").strip("/")
    if not suffix:
        return f"{root}/" if root else ""
    return f"{root}/{suffix}/" if root else f"{suffix}/"


def safe_bundle_filename(name: str, fallback: str = "restored.legion") -> str:
    candidate = os.path.basename(str(name or "").strip())
    if not candidate:
        candidate = str(fallback or "restored.legion")
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate)
    candidate = candidate.strip("._")
    if not candidate:
        candidate = str(fallback or "restored.legion")
    return candidate


def safe_bundle_relative_path(path: str) -> str:
    raw = str(path or "").replace("\\", "/").strip()
    if not raw:
        return ""
    raw = raw.lstrip("/")
    parts = []
    for piece in raw.split("/"):
        token = str(piece or "").strip()
        if not token or token == ".":
            continue
        if token == "..":
            return ""
        parts.append(token)
    return "/".join(parts)


def read_bundle_manifest(archive: zipfile.ZipFile) -> Tuple[str, str, Dict[str, Any]]:
    names = [str(item or "") for item in archive.namelist()]
    manifest_name = ""
    for name in names:
        normalized = name.rstrip("/")
        if normalized.endswith("/manifest.json") or normalized == "manifest.json":
            manifest_name = normalized
            break
    if not manifest_name:
        raise ValueError("Bundle manifest.json is missing.")

    try:
        raw_manifest = archive.read(manifest_name)
    except KeyError as exc:
        raise ValueError("Bundle manifest.json is missing.") from exc

    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Bundle manifest.json is invalid.") from exc
    if not isinstance(manifest, dict):
        raise ValueError("Bundle manifest.json must be an object.")

    root_prefix = ""
    if manifest_name.endswith("/manifest.json"):
        root_prefix = manifest_name[:-len("/manifest.json")]

    return manifest_name, str(root_prefix or "").strip("/"), manifest


def locate_bundle_session_member(archive: zipfile.ZipFile, root_prefix: str, manifest: Dict[str, Any]) -> str:
    names = [str(item or "").rstrip("/") for item in archive.namelist()]
    name_set = set(names)

    manifest_project_name = os.path.basename(str(manifest.get("project_file", "") or "").strip())
    candidates = []

    session_prefix = bundle_prefix(root_prefix, "session")
    if manifest_project_name:
        explicit_name = f"{session_prefix}{manifest_project_name}" if session_prefix else manifest_project_name
        if explicit_name in name_set:
            candidates.append(explicit_name)

    if not candidates and session_prefix:
        for name in names:
            if not name.lower().endswith(".legion"):
                continue
            if name.startswith(session_prefix):
                candidates.append(name)

    if not candidates:
        for name in names:
            if name.lower().endswith(".legion"):
                candidates.append(name)

    if not candidates:
        return ""
    candidates.sort(key=lambda item: (len(item), item))
    return candidates[0]


def extract_zip_member_to_file(archive: zipfile.ZipFile, member_name: str, destination_path: str):
    target = os.path.abspath(str(destination_path or "").strip())
    if not target:
        raise ValueError("Destination path is required.")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    try:
        with archive.open(member_name, "r") as source, open(target, "wb") as handle:
            shutil.copyfileobj(source, handle)
    except KeyError as exc:
        raise ValueError(f"Bundle member is missing: {member_name}") from exc


def extract_zip_prefix_to_dir(archive: zipfile.ZipFile, prefix: str, destination_dir: str):
    clean_prefix = str(prefix or "").replace("\\", "/")
    if clean_prefix and not clean_prefix.endswith("/"):
        clean_prefix = f"{clean_prefix}/"

    dest_root = os.path.abspath(str(destination_dir or "").strip())
    if not dest_root:
        return
    os.makedirs(dest_root, exist_ok=True)

    extraction_errors = []
    names = [str(item or "") for item in archive.namelist()]
    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.endswith("/"):
            continue
        if clean_prefix and not normalized.startswith(clean_prefix):
            continue
        relative = normalized[len(clean_prefix):] if clean_prefix else normalized
        safe_relative = safe_bundle_relative_path(relative)
        if not safe_relative:
            extraction_errors.append(f"{normalized}: unsafe path")
            continue

        destination = os.path.abspath(os.path.join(dest_root, safe_relative))
        if not destination.startswith(f"{dest_root}{os.sep}") and destination != dest_root:
            extraction_errors.append(f"{normalized}: destination escapes restore directory")
            continue

        os.makedirs(os.path.dirname(destination), exist_ok=True)
        try:
            with archive.open(name, "r") as source, open(destination, "wb") as handle:
                shutil.copyfileobj(source, handle)
        except Exception as exc:
            extraction_errors.append(f"{normalized}: {exc}")

    if extraction_errors:
        preview = "; ".join(extraction_errors[:3])
        remaining = len(extraction_errors) - min(len(extraction_errors), 3)
        suffix = f"; +{remaining} more" if remaining > 0 else ""
        raise ValueError(f"Failed to extract bundled artifacts from {clean_prefix or '/'}: {preview}{suffix}")


def normalize_existing_file(path: str) -> str:
    candidate = str(path or "").strip()
    if not candidate:
        raise ValueError("File path is required.")
    normalized = os.path.abspath(os.path.expanduser(candidate))
    if not os.path.isfile(normalized):
        raise FileNotFoundError(f"File not found: {normalized}")
    return normalized
