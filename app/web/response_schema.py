from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping


def _mapping_payload(value: Any, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be an object.")
    return dict(value)


def _list_payload(value: Any, field_name: str) -> List[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list.")
    return list(value)


@dataclass(frozen=True)
class AcceptedJobResponse:
    job: Dict[str, Any]

    @classmethod
    def from_job(cls, job: Any) -> "AcceptedJobResponse":
        return cls(job=_mapping_payload(job, "job"))

    def to_dict(self) -> Dict[str, Any]:
        return {"status": "accepted", "job": dict(self.job)}


@dataclass(frozen=True)
class ProjectListResponse:
    projects: List[Any]

    @classmethod
    def from_projects(cls, projects: Any) -> "ProjectListResponse":
        return cls(projects=_list_payload(projects, "projects"))

    def to_dict(self) -> Dict[str, Any]:
        return {"projects": list(self.projects)}


@dataclass(frozen=True)
class ProjectOkResponse:
    project: Dict[str, Any]

    @classmethod
    def from_project(cls, project: Any) -> "ProjectOkResponse":
        return cls(project=_mapping_payload(project, "project"))

    def to_dict(self) -> Dict[str, Any]:
        return {"status": "ok", "project": dict(self.project)}


@dataclass(frozen=True)
class ScanHistoryResponse:
    scans: List[Any]

    @classmethod
    def from_scans(cls, scans: Any) -> "ScanHistoryResponse":
        return cls(scans=_list_payload(scans, "scans"))

    def to_dict(self) -> Dict[str, Any]:
        return {"scans": list(self.scans)}
