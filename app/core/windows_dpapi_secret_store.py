from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
from typing import Dict, Optional

from app.paths import get_legion_home


class WindowsDpapiSecretBackend:
    """Persist WSL secrets with Windows DPAPI for the current Windows user."""

    _ENCRYPT_SCRIPT = (
        "$plain = [Console]::In.ReadToEnd(); "
        "$secure = ConvertTo-SecureString $plain -AsPlainText -Force; "
        "[Console]::Out.Write((ConvertFrom-SecureString $secure))"
    )
    _DECRYPT_SCRIPT = (
        "$cipher = [Console]::In.ReadToEnd().Trim(); "
        "$secure = ConvertTo-SecureString $cipher; "
        "$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure); "
        "try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) } "
        "finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }"
    )

    def __init__(self, powershell_path: str, storage_path: str):
        self.powershell_path = str(powershell_path or "").strip()
        self.storage_path = os.path.abspath(os.path.expanduser(str(storage_path or "").strip()))

    @classmethod
    def create_if_available(cls) -> Optional["WindowsDpapiSecretBackend"]:
        release = str(platform.release() or "").lower()
        if not (os.environ.get("WSL_DISTRO_NAME") or "microsoft" in release):
            return None
        powershell_path = shutil.which("powershell.exe")
        if not powershell_path:
            return None
        backend = cls(
            powershell_path,
            os.path.join(get_legion_home(), "secrets.dpapi.json"),
        )
        try:
            probe_value = "legion-dpapi-probe"
            if backend._decrypt(backend._encrypt(probe_value)) != probe_value:
                return None
        except Exception:
            return None
        return backend

    def get_secret(self, secret_ref: str) -> str:
        secret_key = str(secret_ref or "").strip()
        if not secret_key:
            return ""
        encrypted_value = str(self._load_records().get(secret_key, "") or "").strip()
        if not encrypted_value:
            return ""
        return self._decrypt(encrypted_value)

    def set_secret(self, secret_ref: str, value: str):
        secret_key = str(secret_ref or "").strip()
        if not secret_key:
            raise RuntimeError("Missing secret reference.")
        records = self._load_records()
        records[secret_key] = self._encrypt(str(value or ""))
        self._write_records(records)

    def delete_secret(self, secret_ref: str):
        secret_key = str(secret_ref or "").strip()
        if not secret_key or not os.path.exists(self.storage_path):
            return
        records = self._load_records()
        if secret_key not in records:
            return
        records.pop(secret_key, None)
        self._write_records(records)

    def _run_powershell(self, script: str, value: str) -> str:
        try:
            completed = subprocess.run(
                [
                    self.powershell_path,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                input=str(value or ""),
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("Windows DPAPI secret storage is unavailable.") from exc
        return str(completed.stdout or "").strip()

    def _encrypt(self, value: str) -> str:
        encrypted = self._run_powershell(self._ENCRYPT_SCRIPT, value)
        if not encrypted:
            raise RuntimeError("Windows DPAPI returned an empty encrypted value.")
        return encrypted

    def _decrypt(self, value: str) -> str:
        return self._run_powershell(self._DECRYPT_SCRIPT, value)

    def _load_records(self) -> Dict[str, str]:
        if not os.path.exists(self.storage_path):
            return {}
        try:
            with open(self.storage_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError("Windows DPAPI secret store could not be read.") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Windows DPAPI secret store has an invalid format.")
        return {
            str(key): str(value)
            for key, value in payload.items()
            if str(key or "").strip() and str(value or "").strip()
        }

    def _write_records(self, records: Dict[str, str]):
        parent = os.path.dirname(self.storage_path)
        os.makedirs(parent, exist_ok=True)
        fd, temporary_path = tempfile.mkstemp(prefix=".legion-secrets-", dir=parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                json.dump(records, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.storage_path)
            os.chmod(self.storage_path, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
