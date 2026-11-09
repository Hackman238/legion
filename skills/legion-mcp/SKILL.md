---
name: legion-mcp
description: >-
  Set up Legion (the local-first network reconnaissance and penetration-testing platform) and drive it
  through its MCP server: install Legion, start `legion.py --mcp-server`, register it in Claude Code,
  Codex or another MCP client, then run discovery and nmap scans, import nmap XML, run catalog tools,
  work the approval queue, query hosts, services, findings and the evidence graph, and export reports.
  Use this whenever the user mentions Legion, legion.py, a .legion project file, the Legion MCP server,
  or wants an AI agent to run or review authorized reconnaissance (nmap, service enumeration, web probes)
  against hosts, CIDRs or an internal network, even if they do not name Legion. Also use it when an MCP
  client lists tools such as list_hosts, start_nmap_scan, run_tool or run_scheduler.
---

# Legion through MCP

Legion keeps a reconnaissance project (hosts, ports, services, scripts, CVEs, notes, screenshots, an evidence
graph, findings and an execution ledger) in a single `.legion` SQLite file and runs tools through a governed
scheduler with an approval queue. The MCP server exposes that same core, so an agent can do everything the web
UI can, under the same engagement policy. Read `references/tools.md` for every tool with its arguments; this
file is about getting it running and using it well.

## Authorization comes first

Legion launches real scanners against real hosts. Before any scan or tool run, confirm that the user is
authorized to test the targets (their own network, a signed engagement, a lab). Ask when the scope is unclear.
Set the engagement policy to match the authorization (`set_engagement_policy`, see below) rather than loosening
it to make a step go through, and never approve a pending approval on the user's behalf unless they said so for
that action: the approval queue exists so a human decides about credential attacks, exploitation and other risky
steps.

## Setup

Skip to "Register the server" when `legion.py` already exists on the machine. Otherwise read
`references/setup.md`: it covers the from-source install (Kali, Ubuntu, Python 3.12+), the Kali side-by-side
installer, Docker, and what privileges scans need. The short version:

```bash
git clone https://github.com/Hackman238/legion.git && cd legion
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python3 legion.py --tool-audit     # which external tools (nmap, nikto, ...) are installed
```

Nmap needs raw sockets for OS detection and SYN scans. Run the MCP client as root, or give nmap the
capability and set `NMAP_PRIVILEGED=1` in the server's environment; without either, Legion drops OS detection
from its plans and logs that it did.

## Register the server

The server speaks MCP over stdio. It must be started with the Python that has Legion's requirements and with
`LEGION_HOME` pointing at the data directory the user wants (default `~/.local/share/legion`). Use absolute paths.

Claude Code, for every project of the current user (without `--scope user` the default scope is `local`: only
the project the command is run in):

```bash
claude mcp add legion --scope user -e LEGION_HOME=$HOME/.local/share/legion -- /path/to/legion/.venv/bin/python /path/to/legion/legion.py --mcp-server
```

Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.legion]
command = "/path/to/legion/.venv/bin/python"
args = ["/path/to/legion/legion.py", "--mcp-server"]
env = { LEGION_HOME = "/home/you/.local/share/legion" }
```

Claude Desktop, Cursor and other JSON-configured clients use the same command, args and env under
`mcpServers.legion` (exact snippet in `references/setup.md`). Inside the Legion repository itself, the committed
`.mcp.json` already registers the server for Claude Code.

Verify before relying on it. `scripts/mcp_smoke_test.py` starts the server, performs the MCP handshake,
lists the tools and calls `list_projects`, and prints what it got:

```bash
python3 /path/to/legion/skills/legion-mcp/scripts/mcp_smoke_test.py --python /path/to/legion/.venv/bin/python --legion /path/to/legion/legion.py
```

If the client reports a parse error on connect, something on the Legion side wrote to stdout. Legion itself logs
to stderr; the usual culprit is a shell profile that echoes text, so start the server with a plain command, not
through a login shell.

## Working with a project

Nothing persists until a project is saved. When the server starts without a project, the first tool call
creates a temporary one; call `save_project` with a path ending in `.legion` as soon as the work matters, and
again at the end. `list_projects` shows what is already on disk under `LEGION_HOME`, `open_project` opens one.

Paths in tool arguments (`import_nmap_xml`, `save_project`) are paths on the machine running the server, not on
the client, which matters when the server runs in Docker or on another host.

## The working loop

Most mutating tools return `{"status": "accepted", "job": {...}}` immediately. Poll `get_job` with the job's
`id` until its status is `completed`, `failed` or `cancelled`, then read the results through the query tools.
Do not re-submit a scan because the first call returned quickly; it is running.

1. **Policy.** `get_engagement_policy`, then `set_engagement_policy` if it does not match the authorization.
   Presets: `external_recon`, `external_pentest`, `internal_quick_recon`, `internal_recon`, `internal_pentest`,
   `custom`. `approval_mode` is `never`, `risky` or `always`; `credential_attack_mode` and the other risk modes
   are `blocked`, `approval` or `allowed`.
2. **Get data in.** `start_nmap_scan` with `targets` (IPs, CIDRs, hostnames) and a `scan_mode` of `easy`
   (top 1000 ports, service detection, default scripts), `hard` (no host discovery, T4), `legacy` (the classic
   `-T4 -sV -O` scan) or `rfc1918_discovery` (chunked sweep of private ranges); `staged: true` runs the
   configured port and script stages instead. `run_discovery` is the one-call version for a single target.
   `import_nmap_xml` imports an existing report. Each returns a job.
3. **Look at what came back.** `list_hosts` (filter `show_all` to include hosts that are down), `get_host` for
   the full picture of one host, `list_services` for the service view across hosts, `list_scan_history` for
   what was submitted.
4. **Follow up on a service.** `list_tool_catalog` with `service` and `port` lists the tools and pipettes that
   apply, each with its risk category. `run_tool` queues one as a tracked process; `list_processes` and
   `get_process_output` (paged with `offset` and `limit`) read its output; `kill_process` stops a runaway.
   The engagement policy decides before `run_tool` executes anything, and the result's `status` says which:
   `accepted` (queued as a job), `approval_required` (a pending approval was created, see `approval_ids`; nothing
   ran) or `blocked` (the policy refuses it; `policy.reason` says why). The catalog's `danger_categories` show in
   advance which tools are likely to need approval. Treat `approval_required` as a question for the user, not
   as something to approve yourself.
5. **Let the scheduler plan.** `get_plan_preview` shows the next governed steps for a host or service
   without running anything. `run_scheduler` starts a governed run over the whole project; it creates approvals
   for anything the policy marks risky. `list_approvals` (status `pending`), then `approve_approval`,
   `execute_approved_plan_step` or `reject_approval` with a `reason`, each only when the user has decided.
6. **Read results.** `query_findings` for findings, `query_state` for the consolidated target state of a host,
   `query_graph` for the evidence graph (`search`, `node_types`, `min_confidence`), `list_execution_traces` and
   `get_execution_trace` for exactly what ran and what it printed. `create_annotation` records an analyst note
   on a graph node.
7. **Report.** `export_report` with `scope` `project` or `host` (then `host_id`) and `format` `json` or `md`.
   Then `save_project`.

Keep result sizes in mind: `list_hosts` and `get_process_output` take `limit`, and `get_host` on a host with
many scripts is large. Ask for what the next step needs rather than everything.

## When something does not work

- A tool result with `isError: true` carries the exception text; `ValueError` messages name the missing or
  invalid argument. Fix the call rather than retrying it unchanged.
- A scan job that fails at once usually means nmap is not installed or not on `PATH` for the server's user;
  `legion.py --tool-audit` on the server machine shows what is missing.
- `list_hosts` empty after a scan: the job may still be running (`get_job`), the targets may all be down (filter
  `show_all`), or discovery was blocked by a firewall (`scan_mode: hard` skips host discovery).
- Approvals that never appear: the policy's `approval_mode` is `never` or the action's risk mode is `allowed`,
  so the step ran without asking. Check `list_execution_traces`.
