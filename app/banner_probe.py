"""
Bounded TCP/UDP banner probe used by the scheduler's banner action.
"""

from __future__ import annotations

import os
import socket
import sys


def _probe_tcp(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=4.0) as sock:
        sock.settimeout(2.0)
        try:
            data = sock.recv(4096)
        except (TimeoutError, OSError):
            data = b""
        if data:
            return data
        try:
            sock.sendall(b"\r\n")
        except OSError:
            return b""
        try:
            return sock.recv(4096)
        except (TimeoutError, OSError):
            return b""


def _probe_udp(host: str, port: int) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.sendto(b"\r\n", (host, port))
        try:
            data, _ = sock.recvfrom(4096)
            return data
        except (TimeoutError, OSError):
            return b""


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    host = str(os.environ.get("LEGION_BANNER_TARGET") or (args[0] if args else "")).strip()
    port_text = str(os.environ.get("LEGION_BANNER_PORT") or (args[1] if len(args) > 1 else "")).strip()
    protocol = str(os.environ.get("LEGION_BANNER_PROTOCOL") or (args[2] if len(args) > 2 else "tcp")).strip().lower() or "tcp"

    if not host or not port_text:
        sys.stderr.write("banner probe requires target host and port\n")
        return 2

    try:
        port = int(port_text)
    except (TypeError, ValueError):
        sys.stderr.write(f"banner probe invalid port: {port_text}\n")
        return 2

    try:
        data = _probe_udp(host, port) if protocol == "udp" else _probe_tcp(host, port)
    except (TimeoutError, socket.timeout):
        sys.stderr.write(f"banner probe timeout: {host}:{port}/{protocol}\n")
        return 1
    except OSError as exc:
        sys.stderr.write(f"banner probe error: {exc}\n")
        return 1

    if data:
        sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
