#!/bin/bash
# smbenum: bounded, read-only SMB enumeration of one host with whatever Samba, nmap and polenum tools are installed.
#
# Every step is anonymous (null session), non-interactive (nothing ever waits for a password) and, where a
# timeout command exists, time-limited, so the wrapper finishes even against a host that accepts the TCP
# connection and then stalls. Steps whose
# tool is missing are reported and skipped. There is no brute forcing and no exploitation here; those are
# separate, approval-gated actions.

if [ $# -eq 0 ]; then
    echo "Usage: $0 <IP>"
    exit 1
fi
IP="$1"
STEP_TIMEOUT="${SMBENUM_STEP_TIMEOUT:-120}"

# coreutils `timeout` is not on stock macOS (Homebrew installs it as gtimeout). Without either, steps run with
# no time limit: stdin is closed and every login is anonymous, so they still cannot wait on a prompt.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
else
    TIMEOUT_BIN=""
fi

run_step() {
    # run_step <title> <tool> <command...>: prints a header, runs the command with stdin closed and a timeout.
    local title="$1" tool="$2"
    shift 2
    echo
    echo "########## ${title} ##########"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "(${tool} not installed; skipped)"
        return 0
    fi
    if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" "$STEP_TIMEOUT" "$@" </dev/null 2>&1
        if [ $? -eq 124 ]; then
            echo "(${tool} timed out after ${STEP_TIMEOUT}s)"
        fi
    else
        "$@" </dev/null 2>&1
    fi
    return 0
}

rpc() {
    # rpcclient with an anonymous login; -c runs the command and exits, so nothing prompts.
    run_step "$1" rpcclient rpcclient -U '' -N "$IP" -c "$2"
}

run_step "Getting NetBIOS name" nbtscan nbtscan -v -h "$IP"
run_step "NetBIOS name lookup" nmblookup nmblookup -A "$IP"
rpc "Checking for NULL sessions" "srvinfo"
rpc "Enumerating domains" "enumdomains"
rpc "Domain information" "querydominfo"
run_step "Enumerating password and lockout policies" polenum polenum "$IP"
rpc "Enumerating users" "enumdomusers"
rpc "Enumerating groups" "enumdomgroups"
run_step "Enumerating Administrators" net net rpc group members "Administrators" -I "$IP" -U '%'
run_step "Enumerating Domain Admins" net net rpc group members "Domain Admins" -I "$IP" -U '%'
run_step "Listing shares" smbclient smbclient -N -L "//$IP"
run_step "nmap SMB enumeration scripts" nmap nmap -Pn -T4 -p139,445 \
    --script=smb-enum-users,smb-enum-groups,smb-enum-shares,smb-enum-domains,smb-security-mode,smb2-security-mode "$IP"

echo
echo "########## smbenum finished ##########"
