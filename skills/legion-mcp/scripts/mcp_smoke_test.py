#!/usr/bin/env python3
"""Start Legion's MCP server over stdio, do the MCP handshake, list its tools and call list_projects.

Usage: mcp_smoke_test.py [--python PYTHON] [--legion /path/to/legion.py] [--legion-home DIR]

Exit status 0 when the server answers all three requests; the output is a short human-readable summary.
"""
import argparse
import json
import os
import subprocess
import sys


def _request(proc, request_id, method, params=None):
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read()
            raise SystemExit(f"server closed stdout before answering {method}\n{stderr}")
        line = line.strip()
        if not line:
            continue
        try:
            response = json.loads(line)
        except ValueError:
            raise SystemExit(f"non-JSON line on the server's stdout (something printed to stdout): {line[:200]}")
        if response.get("id") == request_id:
            if "error" in response:
                raise SystemExit(f"{method} failed: {response['error']}")
            return response["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable, help="interpreter with Legion's requirements")
    parser.add_argument("--legion", default=os.path.join(os.getcwd(), "legion.py"), help="path to legion.py")
    parser.add_argument("--legion-home", default=os.environ.get("LEGION_HOME", ""), help="LEGION_HOME for the server")
    args = parser.parse_args()

    env = dict(os.environ)
    if args.legion_home:
        env["LEGION_HOME"] = args.legion_home
    proc = subprocess.Popen(
        [args.python, args.legion, "--mcp-server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=os.path.dirname(os.path.abspath(args.legion)), env=env,
    )
    try:
        init = _request(proc, 1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "legion-mcp-smoke-test", "version": "1"},
        })
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()
        tools = _request(proc, 2, "tools/list")["tools"]
        projects = _request(proc, 3, "tools/call", {"name": "list_projects", "arguments": {"limit": 5}})
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    server = init.get("serverInfo", {})
    print(f"server: {server.get('name')} {server.get('version')} (protocol {init.get('protocolVersion')})")
    print(f"tools: {len(tools)}: {', '.join(sorted(tool['name'] for tool in tools))}")
    text = next((block.get("text", "") for block in projects.get("content", []) if block.get("type") == "text"), "")
    print(f"list_projects: {'error' if projects.get('isError') else 'ok'} {text[:300]}")
    return 1 if projects.get("isError") else 0


if __name__ == "__main__":
    sys.exit(main())
