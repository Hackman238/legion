import os
from typing import Optional


_DEFAULT_LEGION_HOME = "~/.local/share/legion"


def get_legion_home() -> str:
    override = str(os.environ.get("LEGION_HOME", "") or "").strip()
    base = override if override else _DEFAULT_LEGION_HOME
    return os.path.abspath(os.path.expanduser(base))


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
