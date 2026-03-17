"""
Helpers for locating optional security tooling in local-first installs.
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional


def _candidate_go_bin_paths(env: Optional[Dict[str, str]] = None) -> List[str]:
    source = env if isinstance(env, dict) else os.environ
    candidates: List[str] = []

    gobin = str(source.get("GOBIN", "") or "").strip()
    if gobin:
        candidates.append(os.path.abspath(os.path.expanduser(gobin)))

    gopath = str(source.get("GOPATH", "") or "").strip()
    if gopath:
        for entry in gopath.split(os.pathsep):
            entry = str(entry or "").strip()
            if entry:
                candidates.append(os.path.abspath(os.path.expanduser(os.path.join(entry, "bin"))))

    home = str(source.get("HOME", "") or "").strip()
    if home:
        candidates.append(os.path.abspath(os.path.expanduser(os.path.join(home, "go", "bin"))))

    default_go_bin = os.path.abspath(os.path.expanduser("~/go/bin"))
    candidates.append(default_go_bin)

    seen = set()
    normalized: List[str] = []
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def augment_path_for_legion_tools(path_value: str = "", *, env: Optional[Dict[str, str]] = None) -> str:
    existing_parts = [part for part in str(path_value or "").split(os.pathsep) if str(part or "").strip()]
    seen = set()
    ordered: List[str] = []

    for part in list(_candidate_go_bin_paths(env)) + existing_parts:
        normalized = os.path.abspath(os.path.expanduser(str(part or "").strip()))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)

    return os.pathsep.join(ordered)


def build_tool_execution_env(base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(base_env or os.environ)
    env["PATH"] = augment_path_for_legion_tools(env.get("PATH", ""), env=env)
    return env

