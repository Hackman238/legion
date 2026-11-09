# Legion REST API

The web UI is a thin client over this JSON API, so everything the UI does can be scripted. The MCP server
(`python legion.py --mcp-server`) exposes a governed subset of the same operations to AI agents.

## Conventions

- Base URL: `http://127.0.0.1:5000` by default (`--web-port` changes the port).
- Requests and responses are JSON unless an endpoint is marked **file**. Send `Content-Type: application/json`.
- Errors are always JSON: `{"error": "message"}` with `400` (bad input), `404` (unknown id or path), `409` (busy or
  conflicting state) or `500`.
- Long-running work returns `202 Accepted` with `{"status": "accepted", "job": {...}}`. Poll `GET /api/jobs/<id>`
  (or watch `/ws/snapshot`) until the job's `status` is `completed`, `failed` or `cancelled`.
- Lists accept `limit` (clamped server-side) and return the newest rows first.
- **Authentication:** when the server was started with `--web-token` / `LEGION_WEB_TOKEN` (always the case with
  `--web-bind-all`), every request except `/health`, `/login` and `/logout` needs the token. Browsers sign in at
  `/login` (sets the `legion_token` cookie); scripts send `Authorization: Bearer <token>` or `X-Legion-Token: <token>`.
- **Origin check:** state-changing requests must carry no `Origin` header or one matching the server's own host and
  port, so a page on another local port cannot drive the API through the browser.

```shell
TOKEN=...                                   # omit the header when no token is configured
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/api/workspace/hosts | jq '.hosts[] | .ip'
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"targets": ["10.0.0.0/24"], "discovery": true, "run_actions": true}' http://127.0.0.1:5000/api/nmap/scan
```

## Health and session

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | `{"status": "ok"}`; never needs a token. |
| GET, POST | `/login` | Login form; `POST` with form field `token` sets the `legion_token` cookie. |
| POST | `/logout` | Clears the cookie. |
| GET | `/api/snapshot` | The capped UI snapshot: project, summary, hosts, services, processes, jobs, approvals, decisions and scan history in one call. |
| WS | `/ws/snapshot` | WebSocket; pushes `{"channels": [...]}` invalidation messages when parts of the snapshot change. |

## Projects

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET | `/api/project` | | Open project: name, folders, temporary flag, autosave state. |
| GET | `/api/projects` | `limit` | `.legion` files in the temp and autosave folders, newest first, with `is_current`. |
| POST | `/api/project/new-temp` | | Close the open project and start a temporary one. `409` while jobs run. |
| POST | `/api/project/open` | `path` | Open a `.legion` file on the Legion host. |
| POST | `/api/project/save-as` | `path`, `replace` | Save the open project to `path` (job). |
| POST | `/api/project/rename` | `path`, `new_name` | Rename a saved project file and its `-tool-output` folder. The open project cannot be renamed. |
| POST | `/api/project/delete` | `path` | Delete a saved project file and its tool output. The open project cannot be deleted. |
| GET | `/api/project/download-zip` | | **file** Zip bundle of the project database, tool output and screenshots. |
| POST | `/api/project/restore-zip` | multipart `file` | Restore a bundle into the temp folder and open it (job). |

## Scans and imports

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| POST | `/api/nmap/scan` | `targets[]`, `discovery`, `staged`, `run_actions`, `nmap_path`, `nmap_args`, `scan_mode`, `scan_options{}` | Run nmap and import the result (job). `staged` runs the `[StagedNmapSettings]` stages and imports each one. |
| POST | `/api/nmap/import-xml` | `path`, `run_actions` | Import an nmap XML file that is on the Legion host (job). |
| POST | `/api/nmap/import-xml-upload` | multipart `file`, `run_actions` | Upload and import an nmap XML file (job). |
| POST | `/api/targets/import-file` | `path` | Import a target list (IPs, subnets, hostnames, URLs) from the host (job). |
| POST | `/api/targets/import-upload` | multipart `file` | Upload and import a target list (job). |
| GET | `/api/network/interfaces` | | Capture-capable interfaces and the default. |
| POST | `/api/scan/passive-capture` | `interface_name`, `duration_minutes`, `run_actions` | Passive capture (internal engagements only) and import (job). |
| POST | `/api/workspace/hosts/<id>/rescan` | | Rescan one host with the engagement profile (job). |
| POST | `/api/workspace/subnets/rescan` | `subnet` | Rescan a subnet, reusing the best earlier submission for it (job). |
| GET | `/api/scans/history` | `limit` | Submitted scans and imports with status and result summary. |
| POST | `/api/scans/history/<id>/rerun` | | Queue the same scan, import or capture again with its recorded settings (job). |

## Workspace: hosts and services

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET | `/api/workspace/overview` | | Counts for the summary card. |
| GET | `/api/workspace/hosts` | `filter` (`hide_down`, `show_all`), `service` (comma-separated), `category`, `limit` | Host rows with OS, categories, open ports and services. |
| GET | `/api/workspace/hosts/<id>` | | Host detail: ports, scripts, CVEs, notes, screenshots, recent processes. |
| GET | `/api/workspace/hosts/<id>/target-state` | | The scheduler's observed state for the host. |
| GET | `/api/workspace/services` | `limit`, `host_id`, `category` | Services aggregated across hosts. |
| GET | `/api/workspace/findings` | `host_id`, `limit` | Findings inferred from scripts, CVEs and tool output. |
| POST | `/api/workspace/hosts/<id>/note` | `text` | Save the operator note. |
| POST | `/api/workspace/hosts/<id>/categories` | `manual_categories[]`, `override_auto` | Set device categories. |
| POST | `/api/workspace/hosts/<id>/scripts` | `script_id`, `output`, `port`, `protocol` | Add a script result. |
| DELETE | `/api/workspace/scripts/<id>` | | Delete a script result. |
| GET | `/api/workspace/scripts/<id>/output` | `offset`, `max_chars` | Script output slice. |
| POST | `/api/workspace/hosts/<id>/cves` | `name`, `severity`, `product`, `version`, `url`, `source`, `exploit_id`, `exploit`, `exploit_url` | Add a CVE. |
| DELETE | `/api/workspace/cves/<id>` | | Delete a CVE. |
| POST | `/api/workspace/ports/delete` | `host_id`, `port`, `protocol` | Remove a port. |
| POST | `/api/workspace/services/delete` | `host_id`, `service` | Remove a service from a host. |
| POST | `/api/workspace/hosts/<id>/dig-deeper` | | Queue AI-assisted deep analysis of the host (job; needs a provider). |
| DELETE | `/api/workspace/hosts/<id>` | | Remove the host and everything attached to it. |
| POST | `/api/workspace/hosts/bulk-action` | `action` (`rescan`, `dig-deeper`, `refresh-screenshots`, `remove`), `host_ids[]` | Apply one action to many hosts (`202`). Rescan, dig-deeper and screenshots answer with the outcome per host; `remove` queues one job whose result lists the outcome per host. |

## Tools and processes

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET | `/api/workspace/tools` | `service`, `port`, `protocol`, `limit`, `offset` | Configured port actions and pipettes with availability of their executables. |
| GET | `/api/workspace/tool-targets` | `host_id`, `service`, `limit` | Open services a tool can be pointed at. |
| POST | `/api/workspace/tools/run` | `tool_id`, `host_ip`, `port`, `protocol`, `parameters{}`, `timeout`, or `targets[{host_ip, port, protocol}]` | Run a tool against one target, or against every entry of `targets` (one job each; `queued`, `jobs[]` and `errors[]` in the response). |
| GET | `/api/processes` | `limit` | Tracked tool processes. |
| GET | `/api/processes/<id>/output` | `offset`, `max_chars` | Output slice of a process. |
| POST | `/api/processes/<id>/kill` | | Kill a running process. |
| POST | `/api/processes/<id>/retry` | `timeout` | Run the same command again (job). |
| POST | `/api/processes/<id>/close` | | Hide a finished process (a running one is stopped first). |
| POST | `/api/processes/clear` | `reset_all` | Remove finished processes from the list. |
| GET | `/api/jobs` | `limit` | Background jobs. |
| GET | `/api/jobs/<id>` | | One job with payload and result. |
| POST | `/api/jobs/<id>/stop` | | Cancel a queued or running job. |

## Scheduler and approvals

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| POST | `/api/scheduler/run` | | Plan and run follow-up actions for the whole project (job). |
| GET | `/api/scheduler/plan-preview` | `host_id` or `host_ip`, `port`, `protocol`, `service`, `mode` (`deterministic`, `ai`, `compare`), `limit_targets`, `limit_actions` | Show what the planners would run without executing anything. |
| GET, POST | `/api/scheduler/preferences` | patch object | Mode, provider, concurrency, device categories, feature flags, pre-approved families, report delivery. |
| GET, POST | `/api/engagement-policy` | policy object | Engagement scope and risk policy (presets included in the GET). |
| POST | `/api/scheduler/provider/test` | provider fields | Test the AI provider connection. |
| GET | `/api/scheduler/provider/logs` | `limit` | Provider request log. |
| GET | `/api/scheduler/decisions` | `limit` | Decision audit log. |
| GET | `/api/scheduler/approvals` | `status`, `limit` | Approval queue (`pending` by default when `status` is given). |
| POST | `/api/scheduler/approvals/<id>/approve` | `run_now`, `approve_family`, `family_action` | Approve one action and optionally pre-approve its family. |
| POST | `/api/scheduler/approvals/<id>/reject` | `reason`, `family_action` | Reject one action and optionally block its family. |
| POST | `/api/scheduler/approve-family` | `family_id`, `metadata{}` | Pre-approve a command family. |
| POST | `/api/scheduler/family-policy` | `family_id`, `state` (`allowed`, `suppressed`, `approval_required`, `blocked`, or `clear`) | Set or clear a family's standing policy. |
| GET | `/api/scheduler/executions` | `limit`, `host_id`, `host_ip` | Execution traces of scheduled actions. |
| GET | `/api/scheduler/executions/<id>` | `max_chars` | One execution trace with its output. |

## Evidence graph

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET | `/api/graph` | `node_types`, `edge_types`, `source_kinds`, `min_confidence`, `q`, `host_id`, `host_filter`, `category`, `include_ai_suggested`, `hide_nmap_xml_artifacts`, `limit_nodes`, `limit_edges` | Nodes and edges for the graph workspace. |
| POST | `/api/graph/rebuild` | `host_id` (optional) | Rebuild the graph from the project database (job). |
| GET | `/api/graph/export/json`, `/api/graph/export/graphml` | `rebuild` | **file** Graph exports. |
| GET | `/api/graph/nodes/<node_id>/content` | `max_chars`, `download` | Artifact or output behind a node. |
| GET, POST | `/api/graph/layouts` | `view_id`, `name`, `layout{}`, `layout_id` | Saved node layouts. |
| GET, POST | `/api/graph/annotations` | `target_kind`, `target_ref`, `body`, `source_ref`, `annotation_id` | Operator annotations on nodes. |

## Screenshots and credentials

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET | `/api/screenshots/<filename>` | | **file** A stored screenshot. |
| POST | `/api/workspace/hosts/<id>/refresh-screenshots` | | Re-capture every web service of the host (job). |
| POST | `/api/workspace/screenshots/refresh` | `host_id`, `port`, `protocol` | Re-capture one service (job). |
| POST | `/api/workspace/screenshots/delete` | `host_id`, `artifact_ref` or `filename` | Delete a screenshot. |
| GET | `/api/workspace/credential-capture` | | Responder / ntlmrelayx capture state and configuration. |
| POST | `/api/workspace/credential-capture/config` | config fields | Save capture configuration. |
| POST | `/api/workspace/credential-capture/start`, `/stop` | `tool_id` | Start or stop a capture listener (`start` is a job). |
| GET | `/api/workspace/credential-capture/log` | `tool_id` | **file** Listener log. |
| GET | `/api/workspace/credentials` | `limit` | Captured credentials. |
| GET | `/api/workspace/credentials/download` | `format` (`txt`, `csv`, `json`) | **file** Captured credentials. |

## Reports and exports

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET | `/api/workspace/hosts/<id>/report` | `format` (`json`, `markdown`) | Graph-backed host report. |
| GET | `/api/workspace/hosts/<id>/ai-report` | `format` | AI-written host report (needs a provider). |
| GET | `/api/workspace/project-report` | `format` | Project report. |
| GET | `/api/workspace/project-ai-report` | `format` | AI-written project report. |
| POST | `/api/workspace/project-report/push`, `/api/workspace/project-ai-report/push` | `project_report_delivery{}` | Deliver the report through the configured integration. |
| GET | `/api/workspace/ai-reports/download-zip` | | **file** Every AI report as a zip. |
| GET | `/api/export/json` | | Full workspace export, uncapped: every table listed by `/api/export/tables`. |
| GET | `/api/export/csv` | | **file** The same export as one CSV with a titled section per table. |
| GET | `/api/export/tables` | | Names of the exportable tables. |
| GET | `/api/export/table/<table>.<csv\|json>` | | **file** One table (`hosts`, `services`, `ports`, `cves`, `findings`, `scripts`, `notes`, `processes`, `jobs`, `scan_history`, `scheduler_decisions`, `scheduler_approvals`, `scheduler_executions`, `credentials`, `tools`). |
| GET | `/api/export/hosts-json`, `/api/export/hosts-csv` | `filter`, `service`, `category` | The hosts table as the UI filters it. |

## Settings

| Method | Path | Body / query | Description |
| --- | --- | --- | --- |
| GET, POST | `/api/settings/legion-conf` | `text` | Read or replace `legion.conf`; the save response says whether the running instance reloaded it. |
| GET, POST | `/api/settings/display` | `colorful_ascii_background` | Display preferences. |
| GET | `/api/settings/tool-audit` | | Which external tools resolve on this host. |
| GET | `/api/settings/tool-audit/install-plan` | `platform` (`kali`, `ubuntu`), `scope`, `tool_keys` | Install script for the missing tools. |
| POST | `/api/settings/tool-audit/install` | `platform`, `scope`, `tool_keys[]` | Run that install plan (job). |
