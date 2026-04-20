from __future__ import annotations

import os
from typing import Dict, Optional


class SecretStoreError(RuntimeError):
    pass


def build_secret_ref(*parts: str) -> str:
    tokens = [str(part or "").strip().lower() for part in parts if str(part or "").strip()]
    return ".".join(tokens)


class SecretStore:
    _SERVICE_NAME = "legion"
    _KNOWN_PROVIDER_ENV_VARS: Dict[str, str] = {
        "lm_studio": "LM_STUDIO_API_KEY",
        "openai": "OPENAI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
    }
    _KNOWN_INTEGRATION_ENV_VARS: Dict[str, str] = {
        "grayhatwarfare": "GRAYHATWARFARE_API_KEY",
        "chaos": "CHAOS_API_KEY",
        "shodan": "SHODAN_API_KEY",
    }

    def __init__(self, service_name: str = _SERVICE_NAME):
        self.service_name = str(service_name or self._SERVICE_NAME)
        self._keyring = None
        self._backend_name = "unavailable"
        self._write_available = False
        try:
            import keyring  # type: ignore

            self._keyring = keyring
            backend = keyring.get_keyring()
            self._backend_name = f"{backend.__class__.__module__}.{backend.__class__.__name__}"
            module_name = str(getattr(backend.__class__, "__module__", "") or "").lower()
            priority = float(getattr(backend, "priority", 0) or 0)
            self._write_available = priority > 0 and "keyring.backends.fail" not in module_name
        except Exception:
            self._keyring = None
            self._backend_name = "unavailable"
            self._write_available = False

    @classmethod
    def provider_env_var(cls, provider_name: str) -> str:
        return str(cls._KNOWN_PROVIDER_ENV_VARS.get(str(provider_name or "").strip().lower(), "") or "")

    @classmethod
    def integration_env_var(cls, integration_name: str) -> str:
        return str(cls._KNOWN_INTEGRATION_ENV_VARS.get(str(integration_name or "").strip().lower(), "") or "")

    def write_available(self) -> bool:
        return bool(self._write_available and self._keyring is not None)

    def backend_name(self) -> str:
        return str(self._backend_name or "unavailable")

    def describe(self) -> Dict[str, object]:
        return {
            "backend": self.backend_name(),
            "write_available": self.write_available(),
        }

    def get_secret(self, secret_ref: str, *, env_var: str = "") -> str:
        resolved_env_var = str(env_var or "").strip()
        if resolved_env_var:
            env_value = str(os.environ.get(resolved_env_var, "") or "").strip()
            if env_value:
                return env_value
        secret_key = str(secret_ref or "").strip()
        if not secret_key or self._keyring is None:
            return ""
        try:
            return str(self._keyring.get_password(self.service_name, secret_key) or "")
        except Exception:
            return ""

    def set_secret(self, secret_ref: str, value: str) -> str:
        secret_key = str(secret_ref or "").strip()
        secret_value = str(value or "")
        if not secret_key:
            raise SecretStoreError("Missing secret reference.")
        if not secret_value:
            self.delete_secret(secret_key)
            return secret_key
        if not self.write_available():
            raise SecretStoreError(
                "Secure secret storage is unavailable. Configure a supported keyring backend or use environment variables."
            )
        try:
            self._keyring.set_password(self.service_name, secret_key, secret_value)
        except Exception as exc:
            raise SecretStoreError(str(exc)) from exc
        return secret_key

    def delete_secret(self, secret_ref: str):
        secret_key = str(secret_ref or "").strip()
        if not secret_key or not self.write_available():
            return
        try:
            self._keyring.delete_password(self.service_name, secret_key)
        except Exception:
            return
