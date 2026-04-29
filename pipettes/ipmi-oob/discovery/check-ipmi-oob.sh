#!/usr/bin/env bash
set -uo pipefail

target=""
port=""
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

nmap_has_script() {
  nmap --script-help "$1" >/dev/null 2>&1
}

append_script_if_available() {
  variable_name="$1"
  script_name="$2"
  if nmap_has_script "$script_name"; then
    eval "current_value=\"\${$variable_name}\""
    if [ -z "$current_value" ]; then
      eval "$variable_name=\"$script_name\""
    else
      eval "$variable_name=\"${current_value},${script_name}\""
    fi
    log "Nmap NSE available: $script_name"
  else
    log "Nmap NSE missing locally: $script_name"
  fi
}

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
base_output="${output%.txt}"
tcp_ports="623,3668,3669,5900,17988,17990,3002,49152"
ipmi_udp_scripts=""
vnc_scripts=""

log "Legion pipette: IPMI, iDRAC, and iLO discovery"
log "Timestamp: $timestamp"
log "Target: $target"
log "Launch context port: $port"
log "Mode: active discovery check"
log "Note: IPMI NSE checks and VNC metadata probes can generate observable management-plane traffic."
log "Safety note: supermicro-ipmi-conf is detected but not invoked automatically because it can retrieve BMC configuration data containing credentials."

case "$port" in
  623|5900|3668|3669|17988|17990|3002|49152)
    ;;
  *)
    log "Port $port is outside the bundled OOB-management trigger set: 623, 5900, 3668, 3669, 17988, 17990, 3002, 49152."
    ;;
esac

if command -v nmap >/dev/null 2>&1; then
  append_script_if_available ipmi_udp_scripts ipmi-version
  append_script_if_available ipmi_udp_scripts ipmi-cipher-zero

  if [ -n "$ipmi_udp_scripts" ]; then
    run_and_log nmap -Pn -n -sU -p 623 --script "$ipmi_udp_scripts" --script-timeout 60s --stats-every 15s "$target" -oA "${base_output}-ipmi-udp"
    ipmi_status=$?
  else
    log "No requested IPMI UDP NSE scripts were found locally; running UDP/623 discovery only."
    run_and_log nmap -Pn -n -sU -p 623 --stats-every 15s "$target" -oA "${base_output}-ipmi-udp-service"
    ipmi_status=$?
  fi
  if [ "$ipmi_status" -ne 0 ]; then
    log "Nmap IPMI UDP discovery exited with status $ipmi_status."
  fi

  append_script_if_available vnc_scripts vnc-info
  if [ -n "$vnc_scripts" ]; then
    run_and_log nmap -Pn -n -sT -sV -p "$tcp_ports" --script "$vnc_scripts" --script-timeout 60s --stats-every 15s "$target" -oA "${base_output}-oob-tcp"
    tcp_status=$?
  else
    log "Nmap vnc-info NSE script was not found locally; running TCP service and CPE discovery only."
    run_and_log nmap -Pn -n -sT -sV -p "$tcp_ports" --stats-every 15s "$target" -oA "${base_output}-oob-tcp-service"
    tcp_status=$?
  fi
  if [ "$tcp_status" -ne 0 ]; then
    log "Nmap OOB TCP discovery exited with status $tcp_status."
  fi

  if nmap_has_script supermicro-ipmi-conf; then
    log "Nmap NSE available: supermicro-ipmi-conf"
    log "supermicro-ipmi-conf was not executed. It can download BMC configuration content and should be a separate proof-mode action."
  else
    log "Nmap NSE missing locally: supermicro-ipmi-conf"
  fi
else
  log "nmap not found; install nmap to run IPMI/iDRAC/iLO NSE and service validation."
fi

if grep -Eiq 'ipmi-version|IPMI-|asf-rmcp|623/(udp|tcp)[[:space:]]+open' "$output"; then
  log "LEGION_FINDING oob_ipmi_evidence_observed severity=medium target=$target port=623"
fi

if grep -Eiq 'IPMI-2\.0|IPMI 2\.0|Level:[[:space:]]*.*2\.0' "$output"; then
  log "LEGION_FINDING ipmi_2_0_rakp_hash_exposure_review severity=high target=$target port=623 cve_hint=CVE-2013-4786"
fi

if grep -Eiq 'ipmi-cipher-zero:|Cipher Zero|State:[[:space:]]*VULNERABLE|cipher suite .?0' "$output"; then
  if grep -Eiq 'State:[[:space:]]*VULNERABLE|VULNERABLE:|Authentication Bypass' "$output"; then
    log "LEGION_FINDING ipmi_cipher_zero_possible severity=high target=$target port=623 cve_hint=CVE-2013-4782"
  else
    log "LEGION_FINDING ipmi_cipher_zero_check_completed severity=info target=$target port=623"
  fi
fi

if grep -Eiq 'cpe:/' "$output"; then
  log "LEGION_FINDING oob_cpe_or_version_evidence_observed severity=info target=$target"
fi

if grep -Eiq 'idrac|integrated dell remote access|dell.*remote access|dell.*rac' "$output"; then
  log "LEGION_FINDING dell_idrac_evidence_observed severity=medium target=$target"
fi

if grep -Eiq '(^|[^A-Za-z])ilo([^A-Za-z]|$)|integrated lights-out|hp.*lights-out|hpe.*lights-out' "$output"; then
  log "LEGION_FINDING hp_hpe_ilo_evidence_observed severity=medium target=$target"
fi

if grep -Eiq '5900/tcp[[:space:]]+open|vnc-info:|Protocol version:|Security types:' "$output"; then
  log "LEGION_FINDING oob_vnc_console_evidence_observed severity=medium target=$target port=5900"
fi

if grep -Eiq 'No authentication|Security types:.*None|None authentication|TLSNone' "$output"; then
  log "LEGION_FINDING vnc_console_no_auth_indicator severity=high target=$target port=5900"
fi

if grep -Eiq '3668/tcp[[:space:]]+open|3669/tcp[[:space:]]+open|17988/tcp[[:space:]]+open|17990/tcp[[:space:]]+open|3002/tcp[[:space:]]+open' "$output"; then
  log "LEGION_FINDING oob_virtual_media_or_remote_console_ports_observed severity=medium target=$target"
fi

if grep -Eiq '49152/tcp[[:space:]]+open' "$output"; then
  log "LEGION_FINDING supermicro_bmc_config_disclosure_proof_candidate severity=medium target=$target port=49152"
fi

if grep -Eiq 'LEGION_FINDING oob_|LEGION_FINDING ipmi_|LEGION_FINDING dell_|LEGION_FINDING hp_hpe_|LEGION_FINDING vnc_|LEGION_FINDING supermicro_' "$output"; then
  log "LEGION_FINDING oob_management_discovery_completed severity=info target=$target"
else
  log "LEGION_FINDING oob_management_not_confirmed severity=info target=$target"
fi

exit 0
