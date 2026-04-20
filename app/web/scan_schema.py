from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from app.web.http_utils import as_bool


@dataclass(frozen=True)
class TargetsImportRequest:
    path: str

    @classmethod
    def from_payload(cls, payload: Any) -> "TargetsImportRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(path=str(source.get("path", "") or "").strip())


@dataclass(frozen=True)
class NmapImportRequest:
    path: str
    run_actions: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "NmapImportRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            path=str(source.get("path", "") or "").strip(),
            run_actions=as_bool(source.get("run_actions", False), default=False),
        )


@dataclass(frozen=True)
class NmapScanRequest:
    targets: List[str]
    discovery: bool
    staged: bool
    run_actions: bool
    nmap_path: str
    nmap_args: str
    scan_mode: str
    scan_options: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Any) -> "NmapScanRequest":
        source = payload if isinstance(payload, dict) else {}
        raw_targets = source.get("targets", [])
        if raw_targets is None:
            raw_targets = []
        targets = list(raw_targets) if isinstance(raw_targets, list) else [raw_targets]
        scan_options = source.get("scan_options", {})
        if not isinstance(scan_options, dict):
            scan_options = {}
        return cls(
            targets=targets,
            discovery=as_bool(source.get("discovery", True), default=True),
            staged=as_bool(source.get("staged", False), default=False),
            run_actions=as_bool(source.get("run_actions", False), default=False),
            nmap_path=str(source.get("nmap_path", "nmap") or "nmap"),
            nmap_args=str(source.get("nmap_args", "") or ""),
            scan_mode=str(source.get("scan_mode", "legacy") or "legacy"),
            scan_options=scan_options,
        )


@dataclass(frozen=True)
class PassiveCaptureRequest:
    interface_name: str
    duration_minutes: int
    run_actions: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "PassiveCaptureRequest":
        source = payload if isinstance(payload, dict) else {}
        duration = source.get("duration_minutes", 15)
        try:
            normalized_duration = int(duration or 0)
        except (TypeError, ValueError):
            normalized_duration = 15
        return cls(
            interface_name=str(source.get("interface_name", "") or ""),
            duration_minutes=normalized_duration,
            run_actions=as_bool(source.get("run_actions", False), default=False),
        )


@dataclass(frozen=True)
class SubnetRescanRequest:
    subnet: str

    @classmethod
    def from_payload(cls, payload: Any) -> "SubnetRescanRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(subnet=str(source.get("subnet", "") or "").strip())


@dataclass(frozen=True)
class DiscoveryRequest:
    target: str
    run_actions: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "DiscoveryRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            target=str(source.get("target", "localhost") or "localhost"),
            run_actions=as_bool(source.get("run_actions", False), default=False),
        )
