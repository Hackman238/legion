#!/usr/bin/env bash
set -uo pipefail

target=""
port="4786"
output=""

usage() {
  printf 'Usage: %s --target HOST --port PORT --output FILE\n' "$0"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2
      ;;
    --port)
      port="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$target" ] || [ -z "$port" ] || [ -z "$output" ]; then
  usage >&2
  exit 2
fi

if ! printf '%s' "$target" | grep -Eq '^[A-Za-z0-9._:-]+$'; then
  printf 'Refusing unsafe target value: %s\n' "$target" >&2
  exit 2
fi

if ! printf '%s' "$port" | grep -Eq '^[0-9]{1,5}$' || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  printf 'Refusing invalid port value: %s\n' "$port" >&2
  exit 2
fi

mkdir -p "$(dirname "$output")"
: > "$output"

log() {
  printf '%s\n' "$*" | tee -a "$output"
}

run_and_log() {
  log ""
  log "+ $*"
  "$@" 2>&1 | tee -a "$output"
  return "${PIPESTATUS[0]}"
}

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
base_output="${output%.txt}"

log "Legion pipette: Cisco Smart Install exposure check"
log "Timestamp: $timestamp"
log "Target: $target"
log "Port: $port/tcp"
log "Mode: read-only check"

if command -v timeout >/dev/null 2>&1; then
  if timeout 5 bash -c ":</dev/tcp/$target/$port" >/dev/null 2>&1; then
    log "TCP reachability: open or reachable"
  else
    log "TCP reachability: closed, filtered, or unreachable"
  fi
else
  log "TCP reachability: skipped because timeout is not available"
fi

if command -v nmap >/dev/null 2>&1; then
  run_and_log nmap -Pn -n -sV -p "$port" --stats-every 15s "$target" -oA "${base_output}-nmap"
  nmap_status=$?
  if [ "$nmap_status" -ne 0 ]; then
    log "Nmap service detection exited with status $nmap_status."
  fi

  if nmap --script-help cisco-smi >/dev/null 2>&1; then
    run_and_log nmap -Pn -n -sV -p "$port" --script cisco-smi --stats-every 15s "$target" -oA "${base_output}-cisco-smi"
    script_status=$?
    if [ "$script_status" -ne 0 ]; then
      log "Nmap cisco-smi script exited with status $script_status."
    fi
  else
    log "Nmap cisco-smi NSE script not found locally; skipping NSE Smart Install script validation."
  fi
else
  log "nmap not found; install nmap to run service and NSE validation."
fi

if command -v cisco-smart-install >/dev/null 2>&1; then
  log "Optional tool present: cisco-smart-install."
  log "Not invoked automatically because no verified read-only command syntax is configured yet."
else
  log "Optional tool missing: cisco-smart-install."
fi

if command -v siet >/dev/null 2>&1; then
  log "Optional tool present: SIET/siet."
  log "Not invoked automatically because SIET can perform active Smart Install actions and needs explicit approval-mode wiring."
else
  log "Optional tool missing: SIET/siet."
fi

if grep -Eiq '4786/tcp[[:space:]]+open|smart[- ]install|cisco.*smart install|vstack' "$output"; then
  log ""
  log "LEGION_FINDING possible_cisco_smart_install_exposure severity=high target=$target port=$port"
  log "Finding note: TCP/4786 or Smart Install evidence was observed. Confirm authorization before any active proof step."
else
  log ""
  log "LEGION_FINDING cisco_smart_install_not_confirmed severity=info target=$target port=$port"
fi

exit 0
