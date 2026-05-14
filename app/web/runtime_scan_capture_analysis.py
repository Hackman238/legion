from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

import psutil

from app.tooling import build_tool_execution_env


def preferred_capture_interface_sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
    name = str(item.get("name", "") or "").strip().lower()
    preferred_prefixes = ("eth", "en", "eno", "ens", "enp", "wl", "wlan")
    depreferred_prefixes = ("docker", "br-", "veth", "virbr", "vmnet", "zt", "tailscale", "tun", "tap")
    if name.startswith(depreferred_prefixes):
        return 2, name
    if name.startswith(preferred_prefixes):
        return 0, name
    return 1, name


def list_capture_interfaces(runtime) -> List[Dict[str, Any]]:
    stats = psutil.net_if_stats() if hasattr(psutil, "net_if_stats") else {}
    addrs = psutil.net_if_addrs() if hasattr(psutil, "net_if_addrs") else {}
    rows: List[Dict[str, Any]] = []
    for name, entries in dict(addrs or {}).items():
        token = str(name or "").strip()
        if not token or token == "lo":
            continue
        stat = (stats or {}).get(token)
        if stat is not None and not bool(getattr(stat, "isup", True)):
            continue
        ipv4_addresses: List[str] = []
        ipv4_networks: List[str] = []
        seen_networks: Set[str] = set()
        for entry in list(entries or []):
            if int(getattr(entry, "family", 0) or 0) != int(socket.AF_INET):
                continue
            address = str(getattr(entry, "address", "") or "").strip()
            netmask = str(getattr(entry, "netmask", "") or "").strip()
            if not address:
                continue
            try:
                iface = ipaddress.ip_interface(f"{address}/{netmask or '32'}")
            except ValueError:
                continue
            if iface.ip.is_loopback:
                continue
            ipv4_addresses.append(str(iface.ip))
            network_text = str(iface.network)
            if network_text and network_text not in seen_networks:
                seen_networks.add(network_text)
                ipv4_networks.append(network_text)
        if not ipv4_addresses:
            continue
        rows.append({
            "name": token,
            "label": f"{token} ({', '.join(ipv4_addresses[:2])})",
            "ipv4_addresses": ipv4_addresses,
            "ipv4_networks": ipv4_networks,
        })
    rows.sort(key=preferred_capture_interface_sort_key)
    return rows


def get_capture_interface_inventory(runtime) -> Dict[str, Any]:
    rows = list_capture_interfaces(runtime)
    default_name = str(rows[0].get("name", "") or "") if rows else ""
    return {
        "interfaces": rows,
        "default_interface": default_name,
    }


def connected_ipv4_networks_for_interface(runtime, interface_name: str) -> List[ipaddress.IPv4Network]:
    token = str(interface_name or "").strip()
    if not token:
        return []
    rows = runtime.list_capture_interfaces()
    for item in rows:
        if str(item.get("name", "") or "").strip() != token:
            continue
        networks: List[ipaddress.IPv4Network] = []
        for raw in list(item.get("ipv4_networks", []) or []):
            try:
                networks.append(ipaddress.ip_network(str(raw), strict=False))
            except ValueError:
                continue
        return networks
    return []


def passive_capture_filter() -> str:
    return (
        "arp or broadcast or multicast or "
        "udp port 67 or udp port 68 or udp port 137 or udp port 138 or "
        "udp port 5353 or udp port 5355 or udp port 1900"
    )


def parse_tshark_field_blob(value: str) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return [item.strip() for item in re.split(r"[,;]", text) if item.strip()]


def classify_passive_protocols(protocol_blob: str, udp_ports: List[str], query_name: str) -> Set[str]:
    labels: Set[str] = set()
    text = str(protocol_blob or "").strip().lower()
    query = str(query_name or "").strip().lower()
    port_tokens = {str(item or "").strip() for item in list(udp_ports or []) if str(item or "").strip()}
    if "arp" in text:
        labels.add("arp")
    if "mdns" in text or "udp:5353" in text or "5353" in port_tokens or query.endswith(".local"):
        labels.update({"mdns", "bonjour"})
    if "llmnr" in text or "5355" in port_tokens:
        labels.add("llmnr")
    if "nbns" in text or "netbios" in text or "137" in port_tokens or "138" in port_tokens:
        labels.add("netbios")
    if "ssdp" in text or "1900" in port_tokens:
        labels.add("ssdp")
    if "dhcp" in text or "bootp" in text or "67" in port_tokens or "68" in port_tokens:
        labels.add("dhcp")
    if "igmp" in text:
        labels.add("multicast")
    return labels


def analyze_passive_capture(
        runtime,
        *,
        interface_name: str,
        capture_path: str,
        analysis_path: str,
) -> Dict[str, Any]:
    if not os.path.isfile(str(capture_path or "")):
        return {
            "candidate_networks": [],
            "observed_private_hosts": [],
            "signals": [],
            "analysis_path": "",
            "record_count": 0,
        }

    connected_networks = runtime._connected_ipv4_networks_for_interface(interface_name)
    local_ips: Set[ipaddress.IPv4Address] = set()
    for network in connected_networks:
        try:
            interface_addr = network.network_address + 1
        except Exception:
            continue
        local_ips.add(interface_addr)
    for item in runtime.list_capture_interfaces():
        if str(item.get("name", "") or "").strip() != str(interface_name or "").strip():
            continue
        for raw_ip in list(item.get("ipv4_addresses", []) or []):
            try:
                local_ips.add(ipaddress.ip_address(str(raw_ip)))
            except ValueError:
                continue

    fields = [
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "udp.srcport",
        "udp.dstport",
        "dns.qry.name",
    ]
    cmd = ["tshark", "-r", str(capture_path), "-T", "fields"]
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "header=n", "-E", "separator=\t", "-E", "occurrence=f"])
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=build_tool_execution_env(),
        check=False,
    )
    if int(result.returncode or 0) != 0:
        return {
            "candidate_networks": [],
            "observed_private_hosts": [],
            "signals": [],
            "analysis_path": "",
            "record_count": 0,
            "error": str(result.stderr or result.stdout or "").strip(),
        }

    observed_private_hosts: Set[str] = set()
    candidate_networks: Set[str] = set()
    protocol_counts: Dict[str, int] = defaultdict(int)
    record_count = 0

    for line in str(result.stdout or "").splitlines():
        columns = line.split("\t")
        while len(columns) < len(fields):
            columns.append("")
        protocol_blob, ip_src, ip_dst, arp_src, arp_dst, udp_src, udp_dst, query_name = columns[:len(fields)]
        ip_values = []
        for value in (ip_src, ip_dst, arp_src, arp_dst):
            ip_values.extend(parse_tshark_field_blob(value))
        parsed_ips: List[ipaddress.IPv4Address] = []
        for raw_ip in ip_values:
            try:
                ip_value = ipaddress.ip_address(str(raw_ip))
            except ValueError:
                continue
            if not isinstance(ip_value, ipaddress.IPv4Address):
                continue
            if not ip_value.is_private or ip_value.is_loopback or ip_value.is_link_local or ip_value.is_multicast:
                continue
            if ip_value in local_ips:
                continue
            parsed_ips.append(ip_value)
            observed_private_hosts.add(str(ip_value))
        if not parsed_ips and not str(protocol_blob or "").strip():
            continue
        record_count += 1

        protocols = classify_passive_protocols(
            protocol_blob,
            parse_tshark_field_blob(udp_src) + parse_tshark_field_blob(udp_dst),
            query_name,
        )
        for label in protocols:
            protocol_counts[label] += 1

        for ip_value in parsed_ips:
            matching_network = next((item for item in connected_networks if ip_value in item), None)
            if matching_network is None:
                inferred = ipaddress.ip_network(f"{ip_value}/24", strict=False)
            elif int(matching_network.prefixlen) >= 24:
                inferred = matching_network
            else:
                inferred = ipaddress.ip_network(f"{ip_value}/24", strict=False)
            if inferred.prefixlen <= 32:
                candidate_networks.add(str(inferred))

    summary = {
        "candidate_networks": sorted(candidate_networks),
        "observed_private_hosts": sorted(observed_private_hosts),
        "signals": [
            {"name": key, "count": int(protocol_counts[key])}
            for key in sorted(protocol_counts.keys())
        ],
        "analysis_path": str(analysis_path or ""),
        "record_count": int(record_count),
    }
    if analysis_path:
        try:
            with open(analysis_path, "w", encoding="utf-8") as handle:
                json.dump(summary, handle, indent=2, sort_keys=True)
        except Exception:
            pass
    return summary
