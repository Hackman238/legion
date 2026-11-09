#!/usr/bin/env python3
"""Write references/tools.md from the MCP server's own tool table, so the reference cannot drift from the code.

Run from the Legion checkout: python3 skills/legion-mcp/scripts/generate_tools_reference.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, os.pardir))
OUTPUT = os.path.join(HERE, os.pardir, "references", "tools.md")

GROUPS = [
    ("Projects", ["list_projects", "open_project", "save_project"]),
    ("Scans and imports", ["run_discovery", "start_nmap_scan", "import_nmap_xml", "list_scan_history"]),
    ("Inventory", ["list_hosts", "get_host", "list_services"]),
    ("Tools and processes",
     ["list_tool_catalog", "run_tool", "list_processes", "get_process_output", "kill_process"]),
    ("Jobs", ["list_jobs", "get_job"]),
    ("Engagement policy and the scheduler",
     ["get_engagement_policy", "set_engagement_policy", "get_plan_preview", "run_scheduler"]),
    ("Approvals", ["list_approvals", "approve_approval", "execute_approved_plan_step", "reject_approval"]),
    ("Results", ["query_findings", "query_state", "query_graph", "list_execution_traces", "get_execution_trace",
                 "create_annotation", "export_report"]),
]


def render(tools):
    lines = [
        "# Legion MCP tools",
        "",
        "Generated from `app/mcpServer.py` by `scripts/generate_tools_reference.py`; edit the server, not this file.",
        "Every tool takes a JSON object of arguments. Required arguments are marked; the rest are optional.",
        "Mutating tools answer `{\"status\": \"accepted\", \"job\": {...}}` and run in the background: poll `get_job`.",
        "",
    ]
    seen = set()
    for title, names in GROUPS:
        lines += [f"## {title}", ""]
        for name in names:
            tool = tools[name]
            seen.add(name)
            lines += [f"### `{name}`", "", tool["description"], ""]
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {}) or {}
            required = set(schema.get("required", []) or [])
            if not properties:
                lines += ["No arguments.", ""]
                continue
            lines += ["| Argument | Type | Notes |", "| --- | --- | --- |"]
            for arg, spec in properties.items():
                kind = spec.get("type", "")
                if kind == "array":
                    kind = f"array of {spec.get('items', {}).get('type', 'string')}"
                notes = []
                if arg in required:
                    notes.append("required")
                if spec.get("description"):
                    notes.append(spec["description"])
                lines.append(f"| `{arg}` | {kind} | {'; '.join(notes)} |")
            lines.append("")
    missing = sorted(set(tools) - seen)
    if missing:
        lines += ["## Other tools", ""]
        for name in missing:
            lines += [f"### `{name}`", "", tools[name]["description"], ""]
    return "\n".join(lines).rstrip() + "\n"


def main():
    sys.path.insert(0, REPO)
    from app.mcpServer import MCPServer

    text = render(MCPServer().tools)
    if "--check" in sys.argv:
        with open(OUTPUT, encoding="utf-8") as handle:
            current = handle.read()
        if current != text:
            print("references/tools.md is out of date; run this script without --check", file=sys.stderr)
            return 1
        print("references/tools.md is up to date")
        return 0
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"wrote {os.path.relpath(OUTPUT, REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
