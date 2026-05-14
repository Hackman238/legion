from __future__ import annotations

import json
import re
from typing import Any, Dict

from app.web.credential_schema import (
    CredentialCaptureConfigRequest,
    CredentialCaptureLogQuery,
    CredentialCaptureToolRequest,
    CredentialsDownloadQuery,
    CredentialsQuery,
)


def _safe_filename_token(value: str, fallback: str = "credential-capture") -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-._")
    if not token:
        return str(fallback)
    return token[:96]


class CredentialService:
    def __init__(self, runtime):
        self.runtime = runtime

    def get_credential_capture_state(self) -> Dict[str, Any]:
        return self.runtime.get_credential_capture_state(include_captures=False)

    def save_credential_capture_config(self, payload: Any) -> Dict[str, Any]:
        request = CredentialCaptureConfigRequest.from_payload(payload)
        return self.runtime.save_credential_capture_config(request.updates)

    def start_credential_capture(self, payload: Any) -> Dict[str, Any]:
        request = CredentialCaptureToolRequest.from_payload(payload)
        job = self.runtime.start_credential_capture_session_job(request.tool_id)
        return {"status": "accepted", "job": job}

    def stop_credential_capture(self, payload: Any) -> Dict[str, Any]:
        request = CredentialCaptureToolRequest.from_payload(payload)
        return self.runtime.stop_credential_capture_session(request.tool_id)

    def download_credential_capture_log(self, args) -> Dict[str, Any]:
        query = CredentialCaptureLogQuery.from_args(args)
        payload = self.runtime.get_credential_capture_log_payload(query.tool_id)
        content = str(payload.get("text", "") or "")
        if not content:
            raise FileNotFoundError("No credential capture log output available.")
        return {
            "body": content.encode("utf-8"),
            "mimetype": "text/plain",
            "filename": f"{_safe_filename_token(query.tool_id)}-log.txt",
        }

    def list_credentials(self, args) -> Dict[str, Any]:
        query = CredentialsQuery.from_args(args)
        return self.runtime.get_workspace_credential_captures(limit=query.limit)

    def download_credentials(self, args) -> Dict[str, Any]:
        query = CredentialsDownloadQuery.from_args(args)
        if query.output_format not in {"txt", "json"}:
            raise ValueError("format must be txt or json")
        payload = self.runtime.get_workspace_credential_captures(limit=5000)
        if query.output_format == "json":
            return {
                "body": json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
                "mimetype": "application/json",
                "filename": "credentials.json",
            }
        deduped_hashes = list(payload.get("deduped_hashes", []) or [])
        content = "\n".join(str(item or "") for item in deduped_hashes if str(item or "").strip())
        return {
            "body": content.encode("utf-8"),
            "mimetype": "text/plain",
            "filename": "credential-hashes.txt",
        }
