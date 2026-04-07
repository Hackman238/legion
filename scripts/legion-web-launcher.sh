#!/usr/bin/env bash
set -euo pipefail

log_error() {
  printf '[legion launcher] ERROR: %s\n' "$*" >&2
}

resolve_target_home() {
  local uid passwd_entry home_dir

  if [[ -n "${PKEXEC_UID:-}" ]]; then
    uid="$PKEXEC_UID"
  elif [[ -n "${SUDO_UID:-}" ]]; then
    uid="$SUDO_UID"
  else
    uid="$(id -u)"
  fi

  passwd_entry="$(getent passwd "$uid" || true)"
  if [[ -n "$passwd_entry" ]]; then
    home_dir="$(printf '%s' "$passwd_entry" | cut -d: -f6)"
    if [[ -n "$home_dir" ]]; then
      printf '%s\n' "$home_dir"
      return 0
    fi
  fi

  if [[ "$uid" == "$(id -u)" ]]; then
    printf '%s\n' "${HOME:-/root}"
    return 0
  fi

  return 1
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$0" "$@"
  fi

  log_error "root access is required; re-run with pkexec or sudo."
  exit 1
fi

target_home="$(resolve_target_home)" || {
  log_error "Unable to resolve the invoking user's home directory."
  exit 1
}

INSTALL_DIR="${LEGION_DEV_INSTALL_DIR:-$target_home/.local/opt/legion-web-dev}"
DATA_DIR="${LEGION_DEV_DATA_DIR:-$target_home/.local/share/legion-web-dev}"
VENV_PY="$INSTALL_DIR/.venv/bin/python3"
LEGION_PY="$INSTALL_DIR/legion.py"

export LEGION_HOME="$DATA_DIR"
cd "$INSTALL_DIR"

if [[ ! -x "$VENV_PY" ]]; then
  log_error "Legion side-by-side install is not fully installed at $INSTALL_DIR."
  log_error "Re-run the installer or update the environment."
  exit 1
fi

exec "$VENV_PY" "$LEGION_PY" --web "$@"
