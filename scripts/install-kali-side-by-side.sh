#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${LEGION_REPO_URL:-https://github.com/Hackman238/legion.git}"
BRANCH="${LEGION_BRANCH:-master}"
INSTALL_DIR="${LEGION_DEV_INSTALL_DIR:-$HOME/.local/opt/legion-web-dev}"
DATA_DIR="${LEGION_DEV_DATA_DIR:-$HOME/.local/share/legion-web-dev}"
BIN_DIR="${LEGION_DEV_BIN_DIR:-$HOME/.local/bin}"
VENV_DIR="$INSTALL_DIR/.venv"
SYSTEM_LAUNCHER_PATH="${LEGION_SYSTEM_LAUNCHER_PATH:-/usr/bin/legion-web}"
SYSTEM_COMPAT_LAUNCHER_PATH="${LEGION_SYSTEM_COMPAT_LAUNCHER_PATH:-/usr/bin/legion-web-dev}"
USER_LAUNCHER_PATH="$BIN_DIR/legion"
LEGACY_USER_LAUNCHER_PATH="$BIN_DIR/legion-web-dev"
SYSTEM_LAUNCHER_SOURCE="$INSTALL_DIR/scripts/legion-web-launcher.sh"
PYTHON_BIN="${PYTHON_BIN:-}"

log() {
  printf '[legion installer] %s\n' "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

need_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Missing required command: $cmd"
}

supports_python_312_plus() {
  local cmd="$1"
  "$cmd" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1
}

resolve_python_bin() {
  if [[ -n "${PYTHON_BIN:-}" ]]; then
    need_cmd "$PYTHON_BIN"
    supports_python_312_plus "$PYTHON_BIN" || die "PYTHON_BIN=$PYTHON_BIN is not Python 3.12+."
    return
  fi

  local candidate
  for candidate in python3.13 python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && supports_python_312_plus "$candidate"; then
      PYTHON_BIN="$candidate"
      return
    fi
  done

  die "Python 3.12+ is required. Install python3.12 and recreate the virtual environment."
}

install_latest_repo() {
  local install_parent backup_dir stage_dir
  install_parent="$(dirname "$INSTALL_DIR")"
  backup_dir="${INSTALL_DIR}.previous"

  mkdir -p "$install_parent"
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating existing git checkout at $INSTALL_DIR"
    git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    git -C "$INSTALL_DIR" fetch --depth=1 origin "$BRANCH"
    git -C "$INSTALL_DIR" reset --hard FETCH_HEAD
    git -C "$INSTALL_DIR" clean -fdx
    return
  fi

  stage_dir="$(mktemp -d "${install_parent}/.legion-web-dev-stage-XXXXXX")"

  log "Cloning $REPO_URL ($BRANCH) into temporary staging dir"
  git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$stage_dir"

  if [[ -e "$INSTALL_DIR" ]]; then
    log "Removing previous side-by-side install at $INSTALL_DIR"
    rm -rf "$backup_dir"
    mv "$INSTALL_DIR" "$backup_dir"
  fi

  mv "$stage_dir" "$INSTALL_DIR"
  rm -rf "$backup_dir"
}

setup_python_env() {
  log "Creating a fresh virtual environment at $VENV_DIR"
  rm -rf "$VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  supports_python_312_plus "$VENV_DIR/bin/python3" || die "Virtual environment at $VENV_DIR is not using Python 3.12+."
  "$VENV_DIR/bin/python3" -m pip install --upgrade pip wheel setuptools
  "$VENV_DIR/bin/python3" -m pip install -r "$INSTALL_DIR/requirements.txt"
}

prepare_data_dir() {
  mkdir -p "$DATA_DIR/backup"
  if [[ ! -f "$DATA_DIR/legion.conf" ]]; then
    cp "$INSTALL_DIR/legion.conf" "$DATA_DIR/legion.conf"
  fi
}

install_launchers() {
  if [[ ! -f "$SYSTEM_LAUNCHER_SOURCE" ]]; then
    die "Missing launcher source: $SYSTEM_LAUNCHER_SOURCE"
  fi

  if [[ $EUID -eq 0 ]]; then
    install -m 0755 "$SYSTEM_LAUNCHER_SOURCE" "$SYSTEM_LAUNCHER_PATH"
    ln -sfn "$SYSTEM_LAUNCHER_PATH" "$SYSTEM_COMPAT_LAUNCHER_PATH"
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 0755 "$SYSTEM_LAUNCHER_SOURCE" "$SYSTEM_LAUNCHER_PATH"
    sudo ln -sfn "$SYSTEM_LAUNCHER_PATH" "$SYSTEM_COMPAT_LAUNCHER_PATH"
  elif [[ -x "$SYSTEM_LAUNCHER_PATH" ]]; then
    log "System launcher already exists at $SYSTEM_LAUNCHER_PATH"
  else
    return 1
  fi

  mkdir -p "$BIN_DIR"
  ln -sfn "$SYSTEM_LAUNCHER_PATH" "$USER_LAUNCHER_PATH"
  rm -f "$LEGACY_USER_LAUNCHER_PATH"
}

main() {
  need_cmd git
  resolve_python_bin

  install_latest_repo
  setup_python_env
  prepare_data_dir
  install_launchers || log "WARNING: Could not create $SYSTEM_LAUNCHER_PATH. Use $USER_LAUNCHER_PATH or rerun the installer with sudo."

  log "Done."
  log "Source checkout and runtime data stay side-by-side."
  log "User launcher: $USER_LAUNCHER_PATH"
  log "System launcher: $SYSTEM_LAUNCHER_PATH"
  log "System compatibility launcher: $SYSTEM_COMPAT_LAUNCHER_PATH"
  log "Install dir: $INSTALL_DIR"
  log "Data dir (LEGION_HOME): $DATA_DIR"
  log ""
  log "Recommended run flow:"
  log "  legion"
  log ""
  log "Optional:"
  log "  legion-web"
  log "  legion-web-dev"
  log "  cd \"$INSTALL_DIR\" && source \"$VENV_DIR/bin/activate\" && python legion.py --headless --input-file targets.txt --discovery"
  log ""
  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    log ""
    log "NOTE: $BIN_DIR is not currently in PATH."
    log "Add this to your shell profile:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
  fi
}

main "$@"
