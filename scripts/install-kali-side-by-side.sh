#!/usr/bin/env bash
set -euo pipefail

# Side-by-side installer for Kali (does not overwrite packaged `legion`).
# Installs a separate clone + venv and creates launcher: ~/.local/bin/legion-web-dev

REPO_URL="${LEGION_REPO_URL:-https://github.com/Hackman238/legion.git}"
BRANCH="${LEGION_BRANCH:-main}"
INSTALL_DIR="${LEGION_DEV_INSTALL_DIR:-$HOME/.local/opt/legion-web-dev}"
DATA_DIR="${LEGION_DEV_DATA_DIR:-$HOME/.local/share/legion-web-dev}"
BIN_DIR="${LEGION_DEV_BIN_DIR:-$HOME/.local/bin}"
LAUNCHER_PATH="$BIN_DIR/legion-web-dev"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

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

if [[ \$# -eq 0 ]]; then
  exec "\$VENV_PY" "\$INSTALL_DIR/legion.py" --web
fi

exec "\$VENV_PY" "\$INSTALL_DIR/legion.py" "\$@"
EOF
  chmod +x "$LAUNCHER_PATH"
}

install_or_update_repo() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating existing install at $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --depth=1 origin "$BRANCH"
    git -C "$INSTALL_DIR" checkout -f "$BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
  else
    log "Cloning $REPO_URL into $INSTALL_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
}

setup_python_env() {
  log "Creating/updating virtual environment at $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
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
  need_cmd "$PYTHON_BIN"

  install_or_update_repo
  setup_python_env
  prepare_data_dir
  write_launcher

  log "Done."
  log "Packaged Kali Legion remains untouched."
  log "Launcher: $LAUNCHER_PATH"
  log "Install dir: $INSTALL_DIR"
  log "Data dir (LEGION_HOME): $DATA_DIR"
  log ""
  log "Run:"
  log "  legion-web-dev                   # starts local web UI on 127.0.0.1:5000"
  log "  legion-web-dev --web --web-port 5001"
  log "  legion-web-dev --headless --input-file targets.txt --discovery"

  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    log ""
    log "NOTE: $BIN_DIR is not currently in PATH."
    log "Add this to your shell profile:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
  fi
}

main "$@"
