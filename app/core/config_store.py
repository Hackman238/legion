"""
Qt-free INI settings store with a minimal QSettings-like API surface.
"""

from __future__ import annotations

import configparser
import csv
import io
import os
from typing import Iterable, Optional


class IniSettingsStore:
    _LIST_VALUE_GROUPS = {
        "HostActions",
        "PortActions",
        "PortTerminalActions",
        "SchedulerSettings",
    }

    def __init__(self, file_path: str, list_value_groups: Optional[Iterable[str]] = None):
        self._file_path = str(file_path)
        self._groups = []
        self._list_value_groups = set(list_value_groups or self._LIST_VALUE_GROUPS)
        self._parser = configparser.ConfigParser(interpolation=None)
        self._parser.optionxform = str
        if os.path.exists(self._file_path):
            self._parser.read(self._file_path, encoding="utf-8")

    def fileName(self) -> str:
        return self._file_path

    def beginGroup(self, name: str):
        group = str(name or "").strip()
        if group:
            self._groups.append(group)

    def endGroup(self):
        if self._groups:
            self._groups.pop()

    def childKeys(self):
        section = self._current_section()
        if not section or not self._parser.has_section(section):
            return []
        return list(self._parser[section].keys())

    def value(self, key: str):
        section = self._current_section()
        option = str(key or "")
        if not section or not option:
            return None
        if not self._parser.has_section(section):
            return None
        if not self._parser.has_option(section, option):
            return None
        raw = self._parser.get(section, option, raw=True, fallback=None)
        if raw is None:
            return None
        if section in self._list_value_groups:
            return self._decode_csv(raw)
        return self._decode_scalar(raw)

    def setValue(self, key: str, value):
        section = self._current_section()
        option = str(key or "")
        if not section or not option:
            return
        if not self._parser.has_section(section):
            self._parser.add_section(section)
        if section in self._list_value_groups and isinstance(value, (list, tuple)):
            encoded = self._encode_csv(value)
        else:
            encoded = self._encode_scalar(value)
        self._parser.set(section, option, encoded)

    def remove(self, key: str):
        section = self._current_section()
        option = str(key or "")
        if not section or not option:
            return
        if self._parser.has_section(section):
            self._parser.remove_option(section, option)

    def sync(self):
        parent = os.path.dirname(self._file_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self._file_path, "w", encoding="utf-8") as handle:
            self._parser.write(handle, space_around_delimiters=False)

    def _current_section(self) -> str:
        if not self._groups:
            return ""
        return "/".join(self._groups)

    @staticmethod
    def _decode_scalar(raw: str):
        value = str(raw)
        stripped = value.strip()
        if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ('"', "'"):
            return stripped[1:-1]
        return value

    @staticmethod
    def _decode_csv(raw: str):
        text = str(raw).strip()
        if text == "":
            return [""]
        try:
            return next(csv.reader([text], skipinitialspace=True))
        except Exception:
            return [text]

    @staticmethod
    def _encode_csv(values) -> str:
        row = [str(item) for item in list(values)]
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="")
        writer.writerow(row)
        return buffer.getvalue()

    @staticmethod
    def _encode_scalar(value) -> str:
        text = str(value)
        if "," not in text:
            return text
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="")
        writer.writerow([text])
        return buffer.getvalue()
