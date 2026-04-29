from __future__ import annotations

from typing import Any, Dict

from app.web.scan_schema import (
    DiscoveryRequest,
    NmapImportRequest,
    NmapScanRequest,
    PassiveCaptureRequest,
    SubnetRescanRequest,
    TargetsImportRequest,
)
from app.web.response_schema import AcceptedJobResponse, ScanHistoryResponse


class ScanService:
    def __init__(self, runtime):
        self.runtime = runtime

    def import_targets(self, payload: Any) -> Dict[str, Any]:
        request = TargetsImportRequest.from_payload(payload)
        if not request.path:
            raise ValueError("Targets file path is required.")
        job = self.runtime.start_targets_import_job(request.path)
        return AcceptedJobResponse.from_job(job).to_dict()

    def import_nmap_xml(self, payload: Any) -> Dict[str, Any]:
        request = NmapImportRequest.from_payload(payload)
        if not request.path:
            raise ValueError("Nmap XML path is required.")
        job = self.runtime.start_nmap_xml_import_job(request.path, run_actions=request.run_actions)
        return AcceptedJobResponse.from_job(job).to_dict()

    def nmap_scan(self, payload: Any) -> Dict[str, Any]:
        request = NmapScanRequest.from_payload(payload)
        job = self.runtime.start_nmap_scan_job(
            targets=request.targets,
            discovery=request.discovery,
            staged=request.staged,
            run_actions=request.run_actions,
            nmap_path=request.nmap_path,
            nmap_args=request.nmap_args,
            scan_mode=request.scan_mode,
            scan_options=request.scan_options,
        )
        return AcceptedJobResponse.from_job(job).to_dict()

    def get_network_interfaces(self) -> Dict[str, Any]:
        return self.runtime.get_capture_interface_inventory()

    def passive_capture(self, payload: Any) -> Dict[str, Any]:
        request = PassiveCaptureRequest.from_payload(payload)
        job = self.runtime.start_passive_capture_scan_job(
            interface_name=request.interface_name,
            duration_minutes=request.duration_minutes,
            run_actions=request.run_actions,
        )
        return AcceptedJobResponse.from_job(job).to_dict()

    def host_rescan(self, host_id: int) -> Dict[str, Any]:
        job = self.runtime.start_host_rescan_job(int(host_id))
        return AcceptedJobResponse.from_job(job).to_dict()

    def subnet_rescan(self, payload: Any) -> Dict[str, Any]:
        request = SubnetRescanRequest.from_payload(payload)
        if not request.subnet:
            raise ValueError("Subnet is required.")
        job = self.runtime.start_subnet_rescan_job(request.subnet)
        return AcceptedJobResponse.from_job(job).to_dict()

    def scan_history(self, limit: Any) -> Dict[str, Any]:
        try:
            resolved_limit = int(limit)
        except (TypeError, ValueError):
            resolved_limit = 100
        resolved_limit = max(1, min(resolved_limit, 1000))
        return ScanHistoryResponse.from_scans(self.runtime.get_scan_history(limit=resolved_limit)).to_dict()

    def run_discovery(self, payload: Any) -> Dict[str, Any]:
        request = DiscoveryRequest.from_payload(payload)
        return self.runtime.run_governed_discovery(request.target, run_actions=request.run_actions)
