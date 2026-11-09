"""Convert other scanners' reports into nmap XML so the one nmap importer can load them.

Supported inputs: nmap XML (returned unchanged), nmap grepable output (.gnmap), masscan XML (-oX), masscan JSON (-oJ)
and masscan list output (-oL). Detection looks at the content, not the extension, so uploads with odd names work.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import quoteattr

try:  # uploads are untrusted: refuse external entities and entity expansion when defusedxml is installed
    from defusedxml import minidom
except ImportError:  # pragma: no cover - defusedxml ships with the requirements, this keeps bare installs working
    from xml.dom import minidom

FORMAT_NMAP_XML = "nmap_xml"
FORMAT_MASSCAN_XML = "masscan_xml"
FORMAT_MASSCAN_JSON = "masscan_json"
FORMAT_MASSCAN_LIST = "masscan_list"
FORMAT_GNMAP = "gnmap"
FORMAT_UNKNOWN = "unknown"

_GNMAP_HOST_RE = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s*(.*)$")
_MASSCAN_LIST_RE = re.compile(r"^(open|closed)\s+(tcp|udp|icmp|sctp)\s+(\d+)\s+(\S+)\s+(\d+)\s*$")
_MASSCAN_BANNER_RE = re.compile(r"^banner\s+(tcp|udp)\s+(\d+)\s+(\S+)\s+\d+\s+(\S+)\s+(.*)$")


def _head(path: str, size: int = 65536) -> str:
    with open(path, "rb") as handle:
        return handle.read(size).decode("utf-8", errors="ignore")


def _detect_scan_format(path: str) -> Tuple[str, Any]:
    """(format, parsed JSON payload or None); FORMAT_UNKNOWN when the file is none of the supported formats."""
    try:
        head = _head(path)
    except OSError:
        return FORMAT_UNKNOWN, None
    stripped = head.lstrip("\ufeff \t\r\n")
    if stripped.startswith("<"):
        # Any other XML is handed to the nmap importer unchanged, so its own malformed-document error is raised.
        return (FORMAT_MASSCAN_XML if 'scanner="masscan"' in stripped[:4096].lower() else FORMAT_NMAP_XML), None
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            payload = json.loads(_read_all(path))
        except (OSError, ValueError):
            return FORMAT_UNKNOWN, None
        rows = payload if isinstance(payload, list) else [payload]
        if rows and all(isinstance(row, dict) and ("ip" in row and "ports" in row) for row in rows):
            return FORMAT_MASSCAN_JSON, payload
        return FORMAT_UNKNOWN, None
    for line in stripped.splitlines()[:50]:
        text = line.strip()
        if not text:
            continue
        if text.startswith("#"):
            if "masscan" in text.lower():
                return FORMAT_MASSCAN_LIST, None
            if "nmap" in text.lower() and ("-oG" in text or "scan initiated" in text.lower()):
                return FORMAT_GNMAP, None
            continue
        if _GNMAP_HOST_RE.match(text):
            return FORMAT_GNMAP, None
        if _MASSCAN_LIST_RE.match(text) or _MASSCAN_BANNER_RE.match(text):
            return FORMAT_MASSCAN_LIST, None
    return FORMAT_UNKNOWN, None


def detect_scan_format(path: str) -> str:
    """Name the report format of `path`; FORMAT_UNKNOWN when it is none of the supported ones."""
    return _detect_scan_format(path)[0]


def _read_all(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


# ---- intermediate host model -------------------------------------------------------------------------------------

def _new_host(ip: str) -> Dict[str, Any]:
    return {"ip": ip, "hostname": "", "status": "up", "mac": "", "ports": {}}


def _add_port(host: Dict[str, Any], protocol: str, port: str, state: str = "open", service: str = "",
              product: str = "", version: str = "", extrainfo: str = "") -> None:
    key = (str(protocol or "tcp").lower(), str(port))
    entry = host["ports"].setdefault(key, {"protocol": key[0], "port": key[1], "state": state or "open",
                                           "service": "", "product": "", "version": "", "extrainfo": ""})
    if state:
        entry["state"] = state
    for name, value in (("service", service), ("product", product), ("version", version), ("extrainfo", extrainfo)):
        if value and not entry[name]:
            entry[name] = value


def _parse_gnmap(text: str) -> Tuple[Dict[str, Dict[str, Any]], str]:
    hosts: Dict[str, Dict[str, Any]] = {}
    args = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            if "as:" in line and not args:
                args = line.split("as:", 1)[1].strip()
            continue
        match = _GNMAP_HOST_RE.match(line)
        if not match:
            continue
        ip, hostname, rest = match.group(1), match.group(2).strip(), match.group(3)
        host = hosts.setdefault(ip, _new_host(ip))
        if hostname and not host["hostname"]:
            host["hostname"] = hostname
        for field in rest.split("\t"):
            field = field.strip()
            if field.startswith("Status:"):
                host["status"] = field.split(":", 1)[1].strip().lower() or "up"
            elif field.startswith("Ports:"):
                for item in field.split(":", 1)[1].split(","):
                    parts = item.strip().split("/")
                    if len(parts) < 5:
                        continue
                    port, state, protocol, _owner, service = parts[0], parts[1], parts[2], parts[3], parts[4]
                    version = parts[6] if len(parts) > 6 else ""
                    _add_port(host, protocol, port, state=state or "open", service=service, product=version)
            elif field.startswith("OS:"):
                host["os"] = field.split(":", 1)[1].strip()
    return hosts, args


def _parse_masscan_list(text: str) -> Dict[str, Dict[str, Any]]:
    hosts: Dict[str, Dict[str, Any]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _MASSCAN_LIST_RE.match(line)
        if match:
            state, protocol, port, ip = match.group(1), match.group(2), match.group(3), match.group(4)
            if protocol == "icmp":
                hosts.setdefault(ip, _new_host(ip))
                continue
            _add_port(hosts.setdefault(ip, _new_host(ip)), protocol, port, state=state)
            continue
        banner = _MASSCAN_BANNER_RE.match(line)
        if banner:
            protocol, port, ip, kind, value = banner.groups()
            host = hosts.setdefault(ip, _new_host(ip))
            service = "" if kind in {"title", "X509", "ssl", "vuln"} else kind
            _add_port(host, protocol, port, service=service, extrainfo=f"{kind}: {value.strip()}"[:400])
    return hosts


def _parse_masscan_json(text: str) -> Dict[str, Dict[str, Any]]:
    return _parse_masscan_payload(json.loads(text))


def _parse_masscan_payload(payload: Any) -> Dict[str, Dict[str, Any]]:
    hosts: Dict[str, Dict[str, Any]] = {}
    rows = payload if isinstance(payload, list) else [payload]
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip", "") or "").strip()
        if not ip:
            continue
        host = hosts.setdefault(ip, _new_host(ip))
        for port in list(row.get("ports") or []):
            if not isinstance(port, dict):
                continue
            protocol = str(port.get("proto", "tcp") or "tcp").lower()
            if protocol == "icmp":
                continue
            service_info = port.get("service") if isinstance(port.get("service"), dict) else {}
            kind = str(service_info.get("name", "") or "")
            banner = str(service_info.get("banner", "") or "")
            _add_port(
                host, protocol, str(port.get("port", "")), state=str(port.get("status", "open") or "open"),
                service="" if kind in {"title", "X509", "ssl", "vuln", ""} else kind,
                extrainfo=f"{kind}: {banner}"[:400] if banner else "",
            )
    return hosts


def _parse_masscan_xml(text: str) -> Dict[str, Dict[str, Any]]:
    hosts: Dict[str, Dict[str, Any]] = {}
    dom = minidom.parseString(text)
    for host_node in dom.getElementsByTagName("host"):
        ip = ""
        for address in host_node.getElementsByTagName("address"):
            if address.getAttribute("addrtype") in ("ipv4", "ipv6"):
                ip = address.getAttribute("addr")
                break
        if not ip:
            continue
        host = hosts.setdefault(ip, _new_host(ip))
        for port_node in host_node.getElementsByTagName("port"):
            protocol = port_node.getAttribute("protocol") or "tcp"
            if protocol == "icmp":
                continue
            state_nodes = port_node.getElementsByTagName("state")
            state = state_nodes[0].getAttribute("state") if state_nodes else "open"
            service_nodes = port_node.getElementsByTagName("service")
            kind = service_nodes[0].getAttribute("name") if service_nodes else ""
            banner = service_nodes[0].getAttribute("banner") if service_nodes else ""
            _add_port(
                host, protocol, port_node.getAttribute("portid"), state=state or "open",
                service="" if kind in {"title", "X509", "ssl", "vuln"} else kind,
                extrainfo=f"{kind}: {banner}"[:400] if banner else "",
            )
    return hosts


# ---- nmap XML writer --------------------------------------------------------------------------------------------

def _xml_for_hosts(hosts: Dict[str, Dict[str, Any]], *, scanner: str, args: str) -> str:
    now = int(time.time())
    up = sum(1 for host in hosts.values() if host.get("status", "up") == "up")
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<nmaprun scanner={quoteattr(scanner)} args={quoteattr(args)} start="{now}" '
        f'startstr={quoteattr(time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(now)))} version="" '
        'xmloutputversion="1.05">',
    ]
    for ip in sorted(hosts, key=_ip_sort_key):
        host = hosts[ip]
        lines.append("<host>")
        lines.append(f'<status state={quoteattr(host.get("status", "up") or "up")} reason="converted"/>')
        addrtype = "ipv6" if ":" in ip else "ipv4"
        lines.append(f'<address addr={quoteattr(ip)} addrtype="{addrtype}"/>')
        if host.get("mac"):
            lines.append(f'<address addr={quoteattr(host["mac"])} addrtype="mac"/>')
        if host.get("hostname"):
            lines.append(f'<hostnames><hostname name={quoteattr(host["hostname"])} type="user"/></hostnames>')
        else:
            lines.append("<hostnames/>")
        ports = list(host.get("ports", {}).values())
        if ports:
            lines.append("<ports>")
            for entry in sorted(ports, key=lambda item: (item["protocol"], int(item["port"]) if str(item["port"]).isdigit() else 0)):
                lines.append(f'<port protocol={quoteattr(entry["protocol"])} portid={quoteattr(str(entry["port"]))}>')
                lines.append(f'<state state={quoteattr(entry.get("state") or "open")} reason="converted" reason_ttl="0"/>')
                if entry.get("service") or entry.get("product") or entry.get("extrainfo"):
                    attrs = [f'name={quoteattr(entry.get("service") or "")}']
                    if entry.get("product"):
                        attrs.append(f'product={quoteattr(entry["product"])}')
                    if entry.get("version"):
                        attrs.append(f'version={quoteattr(entry["version"])}')
                    if entry.get("extrainfo"):
                        attrs.append(f'extrainfo={quoteattr(entry["extrainfo"])}')
                    attrs.append('method="table" conf="3"')
                    lines.append(f'<service {" ".join(attrs)}/>')
                lines.append("</port>")
            lines.append("</ports>")
        if host.get("os"):
            lines.append(f'<os><osmatch name={quoteattr(host["os"])} accuracy="90" line="0"/></os>')
        lines.append("</host>")
    lines.append(f'<runstats><finished time="{now}" timestr={quoteattr(time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(now)))} '
                 f'elapsed="0" summary="converted" exit="success"/><hosts up="{up}" down="{len(hosts) - up}" total="{len(hosts)}"/></runstats>')
    lines.append("</nmaprun>")
    return "\n".join(lines) + "\n"


def _ip_sort_key(ip: str):
    parts = ip.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return (0, tuple(int(part) for part in parts))
    return (1, ip)


def convert_report_to_nmap_xml(path: str, output_dir: Optional[str] = None) -> Tuple[str, str]:
    """Return (xml_path, detected_format). Nmap XML is returned as-is; other formats are converted next to it
    (or into `output_dir`). Raises ValueError for formats Legion cannot read."""
    if not os.path.isfile(path):
        return path, FORMAT_NMAP_XML  # the importer reports missing files (and searches its fallback folders) itself
    detected, parsed_payload = _detect_scan_format(path)
    if detected == FORMAT_NMAP_XML:
        return path, detected
    if detected == FORMAT_UNKNOWN:
        raise ValueError(
            f"{os.path.basename(path)} is not a report Legion can import "
            "(expected nmap XML or .gnmap, or masscan XML, JSON or list output)."
        )
    args = ""
    if detected == FORMAT_MASSCAN_JSON:
        hosts, scanner = _parse_masscan_payload(parsed_payload), "masscan"  # detection already parsed it
    else:
        text = _read_all(path)
        if detected == FORMAT_GNMAP:
            hosts, args = _parse_gnmap(text)
            scanner = "nmap"
        elif detected == FORMAT_MASSCAN_LIST:
            hosts, scanner = _parse_masscan_list(text), "masscan"
        else:
            hosts, scanner = _parse_masscan_xml(text), "masscan"
    target_dir = output_dir if output_dir and os.path.isdir(output_dir) else os.path.dirname(os.path.abspath(path))
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(os.path.basename(path))[0])[:80]
    # Unique per conversion: two same-named reports (or two concurrent import jobs) must not share a file.
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix=f"{base}.converted-{detected}-", suffix=".xml", dir=target_dir, delete=False,
    )
    with handle:
        handle.write(_xml_for_hosts(hosts, scanner=scanner, args=args or f"converted from {detected}"))
    return handle.name, detected


def summarize_hosts(xml_text: str) -> List[str]:
    """IPs in a converted document (used by tests and log lines)."""
    dom = minidom.parseString(xml_text)
    ips = []
    for address in dom.getElementsByTagName("address"):
        if address.getAttribute("addrtype") in ("ipv4", "ipv6"):
            ips.append(address.getAttribute("addr"))
    return ips
