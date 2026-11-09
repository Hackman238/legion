import getpass
import logging
import os
import re
import tempfile
from typing import Optional


import sys

def _default_legion_home() -> str:
    # Computed at call time (not import) so platform is never stale.
    if sys.platform == "darwin":
        return "~/Library/Application Support/legion"
    return "~/.local/share/legion"

_warned_fallback_home = False
log = logging.getLogger(__name__)


def _current_user_token() -> str:
    try:
        raw = str(getpass.getuser() or "").strip()
    except Exception:
        raw = ""
    if not raw and hasattr(os, "getuid"):
        raw = f"uid-{os.getuid()}"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw or "user").strip(".-")
    return cleaned or "user"


def _fallback_legion_home() -> str:
    return os.path.abspath(os.path.join(tempfile.gettempdir(), "legion-home", _current_user_token()))


def _is_writable_directory(path: str) -> bool:
    candidate = os.path.abspath(os.path.expanduser(str(path or "").strip()))
    if not candidate:
        return False
    try:
        os.makedirs(candidate, exist_ok=True)
    except OSError:
        return False
    try:
        fd, probe_path = tempfile.mkstemp(prefix=".legion-write-", dir=candidate)
    except OSError:
        return False
    try:
        os.close(fd)
    finally:
        try:
            os.unlink(probe_path)
        except OSError:
            pass
    return True


def get_legion_home() -> str:
    override = str(os.environ.get("LEGION_HOME", "") or "").strip()
    if not override and sys.platform == "darwin":
        # Preserve pre-macOS-port installs/data that used the Linux-style
        # home. Fresh macOS installs use ~/Library/Application Support.
        legacy_home = os.path.abspath(os.path.expanduser("~/.local/share/legion"))
        if os.path.isfile(os.path.join(legacy_home, "legion.conf")):
            return legacy_home
    base = override if override else _default_legion_home()
    resolved = os.path.abspath(os.path.expanduser(base))
    if override or _is_writable_directory(resolved):
        return resolved

    fallback = _fallback_legion_home()
    global _warned_fallback_home
    if not _warned_fallback_home:
        log.warning(
            "Default Legion home '%s' is not writable; using fallback '%s'.",
            resolved,
            fallback,
        )
        _warned_fallback_home = True
    return fallback


def ensure_legion_home() -> str:
    base = get_legion_home()
    os.makedirs(base, exist_ok=True)
    return base


def get_legion_conf_path() -> str:
    return os.path.join(get_legion_home(), "legion.conf")


def get_legion_backup_dir() -> str:
    return os.path.join(get_legion_home(), "backup")


def get_legion_autosave_dir() -> str:
    return os.path.join(get_legion_home(), "autosave")


def get_scheduler_config_path(filename: Optional[str] = None) -> str:
    name = str(filename or "scheduler-ai.json").strip() or "scheduler-ai.json"
    return os.path.join(get_legion_home(), name)
