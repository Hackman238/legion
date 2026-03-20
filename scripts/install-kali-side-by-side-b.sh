#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${LEGION_REPO_URL:-https://github.com/Hackman238/legion.git}"
BRANCH="${LEGION_BRANCH:-master}"
INSTALL_DIR="${LEGION_DEV_INSTALL_DIR:-$HOME/.local/opt/legion-web-dev}"
DATA_DIR="${LEGION_DEV_DATA_DIR:-$HOME/.local/share/legion-web-dev}"
BIN_DIR="${LEGION_DEV_BIN_DIR:-$HOME/.local/bin}"
LAUNCHER_PATH="$BIN_DIR/legion-web-dev"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON_BIN="${PYTHON_BIN:-}"

log() {
  printf '[legion-web-dev installer] %s\n' "$*"
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

write_launcher() {
  mkdir -p "$BIN_DIR"
  cat > "$LAUNCHER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$INSTALL_DIR"
VENV_PY="$VENV_DIR/bin/python3"
export LEGION_HOME="$DATA_DIR"

if [[ ! -x "\$VENV_PY" ]]; then
  echo "legion-web-dev is not fully installed. Re-run installer." >&2
  exit 1
fi

if ! "\$VENV_PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; then
  echo "legion-web-dev requires a Python 3.12+ virtual environment. Re-run installer with python3.12." >&2
  exit 1
fi

if [[ \$# -eq 0 ]]; then
  exec "\$VENV_PY" "\$INSTALL_DIR/legion.py" --web
fi

exec "\$VENV_PY" "\$INSTALL_DIR/legion.py" "\$@"
EOF
  chmod +x "$LAUNCHER_PATH"
}

install_latest_repo() {
  local install_parent backup_dir stage_dir
  install_parent="$(dirname "$INSTALL_DIR")"
  backup_dir="${INSTALL_DIR}.previous"

  mkdir -p "$install_parent"
  stage_dir="$(mktemp -d "${install_parent}/.legion-web-dev-stage-XXXXXX")"

  log "Cloning $REPO_URL ($BRANCH) into temporary staging dir"
  git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$stage_dir"

  rm -rf "$backup_dir"
  if [[ -e "$INSTALL_DIR" ]]; then
    log "Removing previous side-by-side install at $INSTALL_DIR"
    mv "$INSTALL_DIR" "$backup_dir"
  fi

  mv "$stage_dir" "$INSTALL_DIR"
  rm -rf "$backup_dir"
}

setup_python_env() {
  log "Creating/updating virtual environment at $VENV_DIR"
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

main() {
  need_cmd git
  resolve_python_bin

  install_latest_repo
  setup_python_env
  prepare_data_dir
  write_launcher

  log "Done."
  log "Packaged Kali Legion remains untouched."
  log "Launcher: $LAUNCHER_PATH"
  log "Install dir: $INSTALL_DIR"
  log "Data dir (LEGION_HOME): $DATA_DIR"
  log ""
  log "Recommended run flow:"
  log "  cd \"$INSTALL_DIR\""
  log "  source \"$VENV_DIR/bin/activate\""
  log "  python legion.py --web"
  log ""
  log "Optional:"
  log "  python legion.py --web --web-port 5000 --web-bind-all"
  log "  python legion.py --web --web-port 5001"
  log "  python legion.py --headless --input-file targets.txt --discovery"
  log ""
  log "Convenience launcher still available:"
  log "  legion-web-dev"

  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    log ""
    log "NOTE: $BIN_DIR is not currently in PATH."
    log "Add this to your shell profile:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
  fi
}

main "$@"
