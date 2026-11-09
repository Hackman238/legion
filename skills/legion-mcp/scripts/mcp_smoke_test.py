#!/usr/bin/env python3
"""Start Legion's MCP server over stdio, do the MCP handshake, list its tools and call list_projects.

Usage: mcp_smoke_test.py [--python PYTHON] [--legion /path/to/legion.py] [--legion-home DIR] [--timeout SECONDS]

Exit status 0 when the server answers all three requests; the output is a short human-readable summary.
The server's stderr (its log) goes to a temporary file, so a chatty server can never block on a full pipe, and
the whole exchange has a deadline: on failure or timeout the tail of that log is printed.
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time


class SmokeTestFailure(Exception):
    pass


def _pump(stream, lines):
    for line in stream:
        lines.put(line)
    lines.put(None)


def _request(proc, lines, deadline, request_id, method, params=None):
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeTestFailure(f"timed out waiting for the answer to {method}")
        try:
            line = lines.get(timeout=remaining)
        except queue.Empty:
            raise SmokeTestFailure(f"timed out waiting for the answer to {method}")
        if line is None:
            raise SmokeTestFailure(f"server closed stdout before answering {method}")
        line = line.strip()
        if not line:
            continue
        try:
            response = json.loads(line)
        except ValueError:
            raise SmokeTestFailure(f"non-JSON line on the server's stdout (something printed to stdout): {line[:200]}")
        if response.get("id") == request_id:
            if "error" in response:
                raise SmokeTestFailure(f"{method} failed: {response['error']}")
            return response["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable, help="interpreter with Legion's requirements")
    parser.add_argument("--legion", default=os.path.join(os.getcwd(), "legion.py"), help="path to legion.py")
    parser.add_argument("--legion-home", default=os.environ.get("LEGION_HOME", ""), help="LEGION_HOME for the server")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds allowed for the whole exchange")
    args = parser.parse_args()

    env = dict(os.environ)
    if args.legion_home:
        env["LEGION_HOME"] = args.legion_home
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as server_log:
        proc = subprocess.Popen(
            [args.python, args.legion, "--mcp-server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=server_log, text=True, env=env,
        )
        lines = queue.Queue()
        threading.Thread(target=_pump, args=(proc.stdout, lines), daemon=True).start()
        deadline = time.monotonic() + max(1.0, args.timeout)
        failure = None
        try:
            init = _request(proc, lines, deadline, 1, "initialize", {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "legion-mcp-smoke-test", "version": "1"},
            })
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()
            tools = _request(proc, lines, deadline, 2, "tools/list")["tools"]
            projects = _request(proc, lines, deadline, 3, "tools/call",
                                {"name": "list_projects", "arguments": {"limit": 5}})
        except (SmokeTestFailure, OSError) as exc:
            failure = str(exc)
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if failure is not None:
            server_log.seek(0)
            tail = server_log.read()[-2000:]
            print(f"FAILED: {failure}", file=sys.stderr)
            if tail.strip():
                print("--- server log (tail) ---", file=sys.stderr)
                print(tail, file=sys.stderr)
            return 1

    server = init.get("serverInfo", {})
    print(f"server: {server.get('name')} {server.get('version')} (protocol {init.get('protocolVersion')})")
    print(f"tools: {len(tools)}: {', '.join(sorted(tool['name'] for tool in tools))}")
    text = next((block.get("text", "") for block in projects.get("content", []) if block.get("type") == "text"), "")
    print(f"list_projects: {'error' if projects.get('isError') else 'ok'} {text[:300]}")
    return 1 if projects.get("isError") else 0


if __name__ == "__main__":
    sys.exit(main())
