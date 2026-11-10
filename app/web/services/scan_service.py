from __future__ import annotations

from typing import Any, Dict

from app.web.http_utils import as_bool
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

    def start_governed_nmap_scan(self, payload: Any, *, approvals_delegated: bool = False) -> Dict[str, Any]:
        """An nmap scan asked for by an agent: caller-supplied arguments go through the engagement policy first.

        The free-form `nmap_args` (and the vuln-scripts / aggressive options) are classified like any scheduler
        command. Blocked means refused. Approval-required means refused too, unless the operator has delegated
        approvals to the agent: a scan has no approval record a person could act on later, so the agent is told
        to drop the risky arguments or have the operator start the scan. `nmap_path` is never taken from the
        caller; the configured nmap is used.
        """
        from app.web import runtime_tools

        source = dict(payload) if isinstance(payload, dict) else {}
        source.pop("nmap_path", None)
        request = NmapScanRequest.from_payload(source)
        flags = [request.nmap_args]
        if as_bool(request.scan_options.get("vuln_scripts", False), default=False):
            flags.append("--script vuln")
        if as_bool(request.scan_options.get("aggressive", False), default=False):
            flags.append("-A")
        verdict = runtime_tools.evaluate_command_policy(
            self.runtime, "nmap " + " ".join(flag for flag in flags if flag), tool_id="nmap", label="Nmap scan",
        )
        policy = {
            key: verdict[key] for key in ("state", "risk_tags", "reason", "risk_summary", "safer_alternative")
        }
        if verdict["state"] == "blocked" or (verdict["state"] == "approval_required" and not approvals_delegated):
            return {"status": verdict["state"], "job": None, "policy": policy}
        result = self.nmap_scan(source)
        result["policy"] = policy
        return result

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

    def rerun_scan(self, submission_id: int) -> Dict[str, Any]:
        job = self.runtime.rerun_scan_submission(int(submission_id))
        return AcceptedJobResponse.from_job(job).to_dict()

    def run_discovery(self, payload: Any) -> Dict[str, Any]:
        request = DiscoveryRequest.from_payload(payload)
        return self.runtime.run_governed_discovery(request.target, run_actions=request.run_actions)
