#!/usr/bin/env bash
set -uo pipefail

target=""
port=""
output=""
domain="${LEGION_SMTP_DOMAIN:-}"

usage() {
  printf 'Usage: %s --target HOST --port PORT --output FILE [--domain DOMAIN]\n' "$0"
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
    --domain)
      domain="${2:-}"
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

if [ -n "$domain" ] && ! printf '%s' "$domain" | grep -Eq '^[A-Za-z0-9._-]+$'; then
  printf 'Refusing unsafe domain value: %s\n' "$domain" >&2
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
  script_name="$1"
  if nmap_has_script "$script_name"; then
    if [ -z "$nse_scripts" ]; then
      nse_scripts="$script_name"
    else
      nse_scripts="${nse_scripts},${script_name}"
    fi
    log "Nmap NSE available: $script_name"
  else
    log "Nmap NSE missing locally: $script_name"
  fi
}

lookup_spf_records() {
  spf_domain="$1"
  log ""
  log "SPF policy review"
  log "Domain: $spf_domain"
  spf_output="${base_output}-spf.txt"
  : > "$spf_output"

  if command -v dig >/dev/null 2>&1; then
    run_and_log dig +short TXT "$spf_domain"
    dig +short TXT "$spf_domain" > "$spf_output" 2>/dev/null || true
  elif command -v nslookup >/dev/null 2>&1; then
    run_and_log nslookup -type=TXT "$spf_domain"
    nslookup -type=TXT "$spf_domain" > "$spf_output" 2>/dev/null || true
  else
    log "SPF lookup skipped: neither dig nor nslookup is available."
    log "LEGION_FINDING smtp_spf_lookup_not_run severity=info target=$target port=$port domain=$spf_domain"
    return 0
  fi

  if ! grep -Eiq 'v=spf1' "$spf_output"; then
    log "LEGION_FINDING smtp_spf_record_missing severity=medium target=$target port=$port domain=$spf_domain"
    return 0
  fi

  if grep -Eiq 'v=spf1.*[+]all' "$spf_output"; then
    log "LEGION_FINDING smtp_spf_permissive_all severity=high target=$target port=$port domain=$spf_domain"
  elif grep -Eiq 'v=spf1.*[?]all' "$spf_output"; then
    log "LEGION_FINDING smtp_spf_neutral_all severity=medium target=$target port=$port domain=$spf_domain"
  elif grep -Eiq 'v=spf1.*~all' "$spf_output"; then
    log "LEGION_FINDING smtp_spf_softfail_all severity=info target=$target port=$port domain=$spf_domain"
  elif grep -Eiq 'v=spf1.*-all' "$spf_output"; then
    log "LEGION_FINDING smtp_spf_hardfail_all severity=info target=$target port=$port domain=$spf_domain"
  else
    log "LEGION_FINDING smtp_spf_record_present_without_all_mechanism severity=info target=$target port=$port domain=$spf_domain"
  fi
}

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
base_output="${output%.txt}"
nse_scripts=""

log "Legion pipette: Internal SMTP discovery and relay check"
log "Timestamp: $timestamp"
log "Target: $target"
log "Port: $port/tcp"
log "Mode: active check using Nmap SMTP NSE scripts"
log "Note: smtp-enum-users and smtp-open-relay can generate observable SMTP transaction attempts."

case "$port" in
  25|465|587|2525)
    ;;
  *)
    log "Port $port is outside the bundled SMTP target set: 25, 465, 587, 2525."
    ;;
esac

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
  append_script_if_available smtp-commands
  append_script_if_available smtp-enum-users
  append_script_if_available smtp-open-relay
  append_script_if_available smtp-vuln-cve2010-4344
  append_script_if_available smtp-vuln-cve2011-1764

  if [ -n "$nse_scripts" ]; then
    run_and_log nmap -Pn -n -sV -p "$port" --script "$nse_scripts" --script-timeout 60s --stats-every 15s "$target" -oA "${base_output}-smtp-nse"
    nmap_status=$?
  else
    log "No requested SMTP NSE scripts were found locally; running service detection only."
    run_and_log nmap -Pn -n -sV -p "$port" --stats-every 15s "$target" -oA "${base_output}-smtp-service"
    nmap_status=$?
  fi

  if [ "$nmap_status" -ne 0 ]; then
    log "Nmap SMTP check exited with status $nmap_status."
  fi
else
  log "nmap not found; install nmap to run SMTP NSE validation."
fi

if [ -n "$domain" ]; then
  lookup_spf_records "$domain"
else
  log ""
  log "SPF policy review skipped: no domain was provided."
  log "Provide --domain example.org or LEGION_SMTP_DOMAIN=example.org for a basic SPF TXT-policy review."
  log "LEGION_FINDING smtp_spf_domain_not_provided severity=info target=$target port=$port"
fi

if grep -Eiq 'open relay|server is an open relay|relay.*accepted|mail relayed' "$output"; then
  log "LEGION_FINDING smtp_possible_open_relay severity=high target=$target port=$port"
fi

if grep -Eiq 'valid user|valid username|user found|user exists|mailbox exists|account exists' "$output"; then
  log "LEGION_FINDING smtp_user_enumeration_behavior_observed severity=medium target=$target port=$port"
fi

if grep -Eiq 'CVE-2010-4344|CVE-2011-1764|VULNERABLE' "$output"; then
  log "LEGION_FINDING smtp_known_vulnerability_indicator severity=high target=$target port=$port"
fi

if grep -Eiq 'smtp-commands|STARTTLS|AUTH|PIPELINING|VRFY|EXPN' "$output"; then
  log "LEGION_FINDING smtp_capabilities_observed severity=info target=$target port=$port"
else
  log "LEGION_FINDING smtp_discovery_not_confirmed severity=info target=$target port=$port"
fi

exit 0
