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

probe_cert_services_web() {
  if ! command -v curl >/dev/null 2>&1; then
    log "AD CS web-enrollment probe skipped: curl is not available."
    return 0
  fi

  log ""
  log "AD CS web-enrollment probe"
  for scheme in http https; do
    url="${scheme}://${target}/certsrv/"
    certsrv_output="${base_output}-certsrv-${scheme}.txt"
    log ""
    log "+ curl -k -L --max-time 10 $url"
    http_status="$(curl -k -L --max-time 10 -sS -o "$certsrv_output" -w '%{http_code}' "$url" 2>&1)"
    curl_status=$?
    {
      printf 'URL: %s\n' "$url"
      printf 'curl_status: %s\n' "$curl_status"
      printf 'http_status: %s\n' "$http_status"
      printf '%s\n' "--- response preview ---"
      sed -n '1,80p' "$certsrv_output" 2>/dev/null || true
    } | tee -a "$output"
  done
}

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
base_output="${output%.txt}"
smb_scripts=""
rdp_scripts=""

log "Legion pipette: Windows systems discovery"
log "Timestamp: $timestamp"
log "Target: $target"
log "Launch context port: $port/tcp"
log "Mode: active discovery check"
log "Note: anonymous SMB checks and RDP NSE scripts can generate observable authentication and protocol probes."

case "$port" in
  135|139|445|3389)
    ;;
  *)
    log "Port $port is outside the bundled Windows discovery trigger set: 135, 139, 445, 3389."
    ;;
esac

if command -v nmap >/dev/null 2>&1; then
  append_script_if_available smb_scripts smb-os-discovery
  append_script_if_available smb_scripts smb-protocols
  append_script_if_available smb_scripts smb2-capabilities
  append_script_if_available smb_scripts smb-security-mode
  append_script_if_available smb_scripts smb2-security-mode
  append_script_if_available smb_scripts smb-enum-shares

  if [ -n "$smb_scripts" ]; then
    run_and_log nmap -Pn -n -sV -p 135,139,445 --script "$smb_scripts" --script-timeout 60s --stats-every 15s "$target" -oA "${base_output}-smb"
    smb_status=$?
  else
    log "No requested SMB NSE scripts were found locally; running SMB/RPC service detection only."
    run_and_log nmap -Pn -n -sV -p 135,139,445 --stats-every 15s "$target" -oA "${base_output}-smb-service"
    smb_status=$?
  fi
  if [ "$smb_status" -ne 0 ]; then
    log "Nmap SMB discovery exited with status $smb_status."
  fi

  append_script_if_available rdp_scripts rdp-enum-encryption
  append_script_if_available rdp_scripts rdp-vuln-ms12-020
  append_script_if_available rdp_scripts rdp-ntlm-info

  if [ -n "$rdp_scripts" ]; then
    run_and_log nmap -Pn -n -sV -p 3389 -T4 --script "$rdp_scripts" --script-timeout 60s --stats-every 15s "$target" -oA "${base_output}-rdp"
    rdp_status=$?
  else
    log "No requested RDP NSE scripts were found locally; running RDP service detection only."
    run_and_log nmap -Pn -n -sV -p 3389 -T4 --stats-every 15s "$target" -oA "${base_output}-rdp-service"
    rdp_status=$?
  fi
  if [ "$rdp_status" -ne 0 ]; then
    log "Nmap RDP discovery exited with status $rdp_status."
  fi
else
  log "nmap not found; install nmap to run SMB/RDP NSE validation."
fi

if command -v smbclient >/dev/null 2>&1; then
  run_and_log smbclient -L "//$target" -N -g
  smbclient_status=$?
  if [ "$smbclient_status" -eq 0 ]; then
    log "LEGION_FINDING smb_anonymous_share_listing_possible severity=medium target=$target port=445"
  else
    log "Anonymous smbclient share listing exited with status $smbclient_status."
  fi
else
  log "Anonymous SMB share listing skipped: smbclient is not available."
fi

if command -v rpcclient >/dev/null 2>&1; then
  run_and_log rpcclient -U "" -N "$target" -c "srvinfo;netshareenumall"
  rpcclient_status=$?
  if [ "$rpcclient_status" -eq 0 ]; then
    log "LEGION_FINDING smb_ipc_null_session_rpc_access_possible severity=medium target=$target port=445"
  else
    log "Anonymous rpcclient IPC$ probe exited with status $rpcclient_status."
  fi
else
  log "Anonymous IPC$ RPC probe skipped: rpcclient is not available."
fi

probe_cert_services_web

if grep -Eiq 'message_signing:[[:space:]]*disabled|message signing disabled|signing_enabled:[[:space:]]*false' "$output"; then
  log "LEGION_FINDING smb_signing_disabled severity=high target=$target port=445"
elif grep -Eiq 'message_signing:[[:space:]]*enabled but not required|message signing.*not required|signing_required:[[:space:]]*false' "$output"; then
  log "LEGION_FINDING smb_signing_not_required severity=high target=$target port=445"
elif grep -Eiq 'message signing enabled and required|signing_required:[[:space:]]*true' "$output"; then
  log "LEGION_FINDING smb_signing_required severity=info target=$target port=445"
fi

if grep -Eiq 'Anonymous access|READ/WRITE|READ ONLY|Disk\\||IPC\\||Share\\|' "$output"; then
  log "LEGION_FINDING smb_share_information_observed severity=info target=$target port=445"
fi

if grep -Eiq 'Windows|Microsoft|NetBIOS computer name|DNS computer name|Product_Version|Target_Name' "$output"; then
  log "LEGION_FINDING windows_identity_information_observed severity=info target=$target"
fi

if grep -Eiq 'MS12-020|VULNERABLE|Remote Desktop Protocol server.*vulnerable' "$output"; then
  log "LEGION_FINDING rdp_ms12_020_indicator severity=high target=$target port=3389"
fi

if grep -Eiq 'CredSSP|HYBRID|SSL|RDP Protocol Security|rdp-enum-encryption' "$output"; then
  log "LEGION_FINDING rdp_encryption_information_observed severity=info target=$target port=3389"
fi

if grep -Eiq 'certsrv|Certificate Services|Active Directory Certificate Services|Microsoft.*Certification Authority' "$output"; then
  log "LEGION_FINDING possible_adcs_web_enrollment severity=medium target=$target"
else
  log "LEGION_FINDING windows_discovery_completed severity=info target=$target"
fi

exit 0
