#!/usr/bin/env bash
set -euo pipefail

# ====================================================================
# EyeWitness browser prerequisites installer (Firefox/ESR + Geckodriver)
# Works on Kali/Debian/Ubuntu. Run as root (or via sudo).
# Optional env: GECKODRIVER_VERSION=v0.34.0 (default: latest)
# ====================================================================

NEED_SUDO=""
if [[ ${EUID:-0} -ne 0 ]]; then
  if command -v sudo &>/dev/null; then
    NEED_SUDO="sudo"
  else
    echo "[-] Please run as root or install sudo."
    exit 1
  fi
fi

# -------- helpers --------
log() { echo -e "[*] $*"; }
ok()  { echo -e "[+] $*"; }
err() { echo -e "[-] $*" >&2; }

require() {
  if ! command -v "$1" &>/dev/null; then
    log "Installing $1..."
    $NEED_SUDO apt-get update -y
    $NEED_SUDO apt-get install -y "$1"
  fi
}

# Initialize to avoid set -u issues
DISTRO="unknown"
DISTRO_LIKE=""

detect_distro() {
  # Sets globals: DISTRO, DISTRO_LIKE
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
  fi
}

# -------- install firefox or firefox-esr --------
ensure_firefox() {
  detect_distro
  log "Detected distro: ${DISTRO} (like: ${DISTRO_LIKE:-unknown})"

  # If either firefox-esr or firefox already present, keep it.
  if command -v firefox-esr &>/dev/null; then
    ok "Found firefox-esr: $(firefox-esr --version 2>/dev/null || true)"
    FIREFOX_BIN="$(command -v firefox-esr)"
    return 0
  fi

  if command -v firefox &>/dev/null; then
    ok "Found firefox: $(firefox --version 2>/dev/null || true)"
    FIREFOX_BIN="$(command -v firefox)"
    return 0
  fi

  $NEED_SUDO apt-get update -y

  case "${DISTRO}" in
    kali|debian)
      log "Installing firefox-esr via apt..."
      $NEED_SUDO apt-get install -y firefox-esr || {
        err "Failed to install firefox-esr via apt."
        exit 1
      }
      FIREFOX_BIN="$(command -v firefox-esr)"
      ;;
    ubuntu)
      log "Installing firefox on Ubuntu..."
      if $NEED_SUDO apt-get install -y firefox; then
        FIREFOX_BIN="$(command -v firefox)"
      else
        if command -v snap &>/dev/null; then
          log "Apt firefox failed; trying snap..."
          $NEED_SUDO snap install firefox || {
            err "Failed to install firefox via snap."
            exit 1
          }
          FIREFOX_BIN="$(command -v firefox)"
        else
          err "Could not install firefox. Install Snap (apt install snapd) or add the Mozilla Team PPA for firefox-esr."
          exit 1
        fi
      fi
      ;;
    *)
      log "Unknown distro—trying firefox-esr, then firefox..."
      if $NEED_SUDO apt-get install -y firefox-esr; then
        FIREFOX_BIN="$(command -v firefox-esr)"
      else
        $NEED_SUDO apt-get install -y firefox || {
          err "Failed to install firefox/esr."
          exit 1
        }
        FIREFOX_BIN="$(command -v firefox)"
      fi
      ;;
  esac

  ok "Installed: $($FIREFOX_BIN --version 2>/dev/null || true)"
}

# -------- install geckodriver --------
install_geckodriver() {
  require curl
  local target="/usr/local/bin/geckodriver"
  local ver="${GECKODRIVER_VERSION:-}"

  if command -v geckodriver &>/dev/null; then
    ok "geckodriver already present: $(geckodriver --version | head -n1)"
    return 0
  fi

  log "geckodriver not found; installing..."
  local url
  if [[ -n "$ver" ]]; then
    url="https://github.com/mozilla/geckodriver/releases/download/${ver}/geckodriver-${ver}-linux64.tar.gz"
  else
    url="$(curl -fsSL https://api.github.com/repos/mozilla/geckodriver/releases/latest \
           | grep -oE 'https://[^"]+linux64\.tar\.gz' | head -n1)"
  fi

  if [[ -z "${url:-}" ]]; then
    err "Could not resolve geckodriver download URL."
    exit 1
  fi

  log "Downloading: $url"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  curl -fsSL "$url" -o "$tmpdir/geckodriver.tar.gz"
  tar -xzf "$tmpdir/geckodriver.tar.gz" -C "$tmpdir"

  log "Installing to $target"
  $NEED_SUDO mv "$tmpdir/geckodriver" "$target"
  $NEED_SUDO chmod +x "$target"

  ok "geckodriver installed: $(geckodriver --version | head -n1)"
}

# -------- smoketest (optional but helpful) --------
smoketest() {
  # Some libs improve stability even in headless mode.
  $NEED_SUDO apt-get update -y
  $NEED_SUDO apt-get install -y xvfb libdbus-glib-1-2 libgtk-3-0 libnss3 libx11-xcb1 libxrandr2 libxtst6 fonts-liberation >/dev/null 2>&1 || true

  log "Running headless smoketest (geckodriver + firefox)..."
  export MOZ_HEADLESS=1

  GECKODRIVER_LOG=error geckodriver --binary "${FIREFOX_BIN}" --port 4444 >/tmp/geckodriver.log 2>&1 &
  local pid=$!
  sleep 2

  if ! curl -fsS http://127.0.0.1:4444/status >/dev/null; then
    err "Smoketest failed. Check /tmp/geckodriver.log for details."
    kill $pid 2>/dev/null || true
    return 1
  fi

  ok "Smoketest OK."
  kill $pid 2>/dev/null || true
}

main() {
  require lsb-release || true
  ensure_firefox
  install_geckodriver
  smoketest || {
    err "Environment ready, but smoketest failed—could be sandbox/missing GUI lib. EyeWitness may still work; see /tmp/geckodriver.log."
    exit 1
  }
  ok "All set."
}

main "$@"
