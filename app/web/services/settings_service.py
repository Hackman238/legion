from __future__ import annotations

import os
from typing import Any, Dict

from app.settings import AppSettings, Settings
from app.tooling import (
    audit_legion_tools,
    build_tool_install_plan,
    detect_supported_tool_install_platform,
    tool_audit_summary,
)
from app.web.http_utils import as_bool
from app.web.settings_schema import (
    DisplaySettingsRequest,
    LegionConfRequest,
    ToolAuditInstallRequest,
    ToolAuditPlanQuery,
)


def load_display_settings(runtime=None) -> Dict[str, Any]:
    settings = getattr(runtime, "settings", None)
    if settings is None:
        try:
            settings = Settings(AppSettings())
        except Exception:
            settings = None
    colorful_ascii_background = as_bool(
        getattr(settings, "general_colorful_ascii_background", False) if settings is not None else False,
        False,
    )
    return {
        "colorful_ascii_background": bool(colorful_ascii_background),
    }


def _refresh_runtime_settings(runtime) -> None:
    if runtime is None:
        return
    try:
        runtime.settings_file = AppSettings()
        runtime.settings = Settings(runtime.settings_file)
    except Exception:
        pass


class SettingsService:
    def __init__(self, runtime):
        self.runtime = runtime

    def get_legion_conf(self) -> Dict[str, Any]:
        settings = AppSettings()
        conf_path = str(settings.actions.fileName() or "")
        if not conf_path:
            raise RuntimeError("Unable to resolve legion.conf path.")
        if not os.path.isfile(conf_path):
            raise FileNotFoundError(f"Config file not found: {conf_path}")
        with open(conf_path, "r", encoding="utf-8") as handle:
            text_value = handle.read()
        return {"path": conf_path, "text": text_value}

    def save_legion_conf(self, payload: Any) -> Dict[str, Any]:
        request = LegionConfRequest.from_payload(payload)
        settings = AppSettings()
        conf_path = str(settings.actions.fileName() or "")
        if not conf_path:
            raise RuntimeError("Unable to resolve legion.conf path.")
        with open(conf_path, "w", encoding="utf-8") as handle:
            handle.write(request.text_value)
        _refresh_runtime_settings(self.runtime)
        return {"status": "ok", "path": conf_path}

    def get_display_settings(self) -> Dict[str, Any]:
        return load_display_settings(self.runtime)

    def save_display_settings(self, payload: Any) -> Dict[str, Any]:
        request = DisplaySettingsRequest.from_payload(payload)
        settings_file = AppSettings()
        settings_file.actions.beginGroup("GeneralSettings")
        settings_file.actions.setValue(
            "colorful-ascii-background",
            "True" if request.colorful_ascii_background else "False",
        )
        settings_file.actions.endGroup()
        settings_file.actions.sync()
        _refresh_runtime_settings(self.runtime)
        return {
            "status": "ok",
            "colorful_ascii_background": bool(request.colorful_ascii_background),
        }

    def get_tool_audit(self) -> Dict[str, Any]:
        runtime_getter = getattr(self.runtime, "get_tool_audit", None) if self.runtime is not None else None
        if callable(runtime_getter):
            return runtime_getter()
        settings = getattr(self.runtime, "settings", None) if self.runtime is not None else None
        if settings is None:
            settings = Settings(AppSettings())
        entries = audit_legion_tools(settings)
        return {
            "summary": tool_audit_summary(entries),
            "tools": [entry.to_dict() for entry in entries],
            "supported_platforms": ["kali", "ubuntu"],
            "recommended_platform": detect_supported_tool_install_platform(),
        }

    def get_tool_install_plan(self, args: Any) -> Dict[str, Any]:
        query = ToolAuditPlanQuery.from_args(args)
        runtime_getter = getattr(self.runtime, "get_tool_install_plan", None) if self.runtime is not None else None
        if callable(runtime_getter):
            return runtime_getter(platform=query.platform, scope=query.scope, tool_keys=query.tool_keys)
        settings = getattr(self.runtime, "settings", None) if self.runtime is not None else None
        if settings is None:
            settings = Settings(AppSettings())
        entries = audit_legion_tools(settings)
        return build_tool_install_plan(
            entries,
            platform=query.platform,
            scope=query.scope,
            tool_keys=query.tool_keys,
        )

    def start_tool_install(self, payload: Any) -> Dict[str, Any]:
        runtime_start = getattr(self.runtime, "start_tool_install_job", None) if self.runtime is not None else None
        if not callable(runtime_start):
            raise NotImplementedError("Tool installation is unavailable in this runtime.")
        request = ToolAuditInstallRequest.from_payload(payload)
        job = runtime_start(
            platform=request.platform,
            scope=request.scope,
            tool_keys=request.tool_keys,
        )
        return {"status": "accepted", "job": job}
