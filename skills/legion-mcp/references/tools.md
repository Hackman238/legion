# Legion MCP tools

Generated from `app/mcpServer.py` by `scripts/generate_tools_reference.py`; edit the server, not this file.
Every tool takes a JSON object of arguments. Required arguments are marked; the rest are optional.
Mutating tools answer `{"status": "accepted", "job": {...}}` and run in the background: poll `get_job`.

## Projects

### `list_projects`

List Legion projects available on disk.

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |

### `open_project`

Open a Legion project file.

| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | required |

### `save_project`

Save the current Legion project to a path.

| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | required |
| `replace` | boolean |  |

## Scans and imports

### `run_discovery`

Run a quick discovery scan on a target and optionally invoke the shared scheduler.

| Argument | Type | Notes |
| --- | --- | --- |
| `target` | string |  |
| `run_actions` | boolean |  |

### `start_nmap_scan`

Queue an nmap scan of targets (IPs, CIDRs, hostnames) and import the results.

| Argument | Type | Notes |
| --- | --- | --- |
| `targets` | array of string | required |
| `discovery` | boolean |  |
| `staged` | boolean |  |
| `run_actions` | boolean |  |
| `nmap_args` | string |  |
| `scan_mode` | string | easy, hard, legacy or rfc1918_discovery |
| `scan_options` | object |  |

### `import_nmap_xml`

Import an nmap XML report that exists on the Legion host.

| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | required |
| `run_actions` | boolean |  |

### `list_scan_history`

Submitted scans and imports with their status and result summary.

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |

## Inventory

### `list_hosts`

List hosts in the open project with status, OS, categories and open port counts.

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |
| `filter` | string | hide_down (default) or show_all |
| `service` | string | Only hosts exposing this service name |
| `category` | string | Only hosts in this device category |

### `get_host`

Full detail for one host: ports, services, scripts, CVEs, notes, screenshots and AI analysis.

| Argument | Type | Notes |
| --- | --- | --- |
| `host_id` | integer | required |

### `list_services`

Services aggregated across hosts (optionally for one host or category).

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |
| `host_id` | integer |  |
| `category` | string |  |

## Tools and processes

### `list_tool_catalog`

Tools and pipettes that can be run against a service/port, with their risk categories.

| Argument | Type | Notes |
| --- | --- | --- |
| `service` | string |  |
| `port` | string |  |
| `protocol` | string |  |
| `limit` | integer |  |

### `run_tool`

Run one catalog tool against a host/port as a tracked process (dangerous tools follow the approval policy).

| Argument | Type | Notes |
| --- | --- | --- |
| `host_ip` | string | required |
| `port` | string | required |
| `protocol` | string |  |
| `tool_id` | string | required |
| `timeout` | integer |  |
| `parameters` | object |  |

### `list_processes`

Tracked tool processes (running and finished) with host, port, status and timing.

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |

### `get_process_output`

A slice of a process's captured output.

| Argument | Type | Notes |
| --- | --- | --- |
| `process_id` | integer | required |
| `offset` | integer |  |
| `limit` | integer | Max characters (default 20000) |

### `kill_process`

Stop a running tracked process.

| Argument | Type | Notes |
| --- | --- | --- |
| `process_id` | integer | required |

## Jobs

### `list_jobs`

Background jobs (scans, imports, tool runs, scheduler runs) with status.

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |

### `get_job`

Status, error and result of one background job.

| Argument | Type | Notes |
| --- | --- | --- |
| `job_id` | integer | required |

## Engagement policy and the scheduler

### `get_engagement_policy`

Get the current normalized Legion engagement policy.

No arguments.

### `set_engagement_policy`

Update the normalized Legion engagement policy.

| Argument | Type | Notes |
| --- | --- | --- |
| `preset` | string |  |
| `scope` | string |  |
| `intent` | string |  |
| `allow_exploitation` | boolean |  |
| `allow_lateral_movement` | boolean |  |
| `credential_attack_mode` | string |  |
| `lockout_risk_mode` | string |  |
| `stability_risk_mode` | string |  |
| `detection_risk_mode` | string |  |
| `approval_mode` | string |  |
| `runner_preference` | string |  |
| `noise_budget` | string |  |

### `get_plan_preview`

Preview the next governed plan steps for a target or service.

| Argument | Type | Notes |
| --- | --- | --- |
| `host_id` | integer |  |
| `host_ip` | string |  |
| `service` | string |  |
| `port` | string |  |
| `protocol` | string |  |
| `mode` | string |  |
| `limit_targets` | integer |  |
| `limit_actions` | integer |  |

### `run_scheduler`

Start a governed scheduler run over the open project.

No arguments.

## Approvals

### `list_approvals`

List pending or historical approval requests.

| Argument | Type | Notes |
| --- | --- | --- |
| `status` | string |  |
| `limit` | integer |  |

### `approve_approval`

Approve a pending approval request without necessarily executing it.

| Argument | Type | Notes |
| --- | --- | --- |
| `approval_id` | integer | required |
| `approve_family` | boolean |  |
| `run_now` | boolean |  |
| `family_action` | string |  |

### `execute_approved_plan_step`

Approve and execute a pending approval request through the shared approval flow.

| Argument | Type | Notes |
| --- | --- | --- |
| `approval_id` | integer | required |
| `approve_family` | boolean |  |
| `family_action` | string |  |

### `reject_approval`

Reject a pending approval request.

| Argument | Type | Notes |
| --- | --- | --- |
| `approval_id` | integer | required |
| `reason` | string |  |
| `family_action` | string |  |

## Results

### `query_findings`

Query findings from the shared target state.

| Argument | Type | Notes |
| --- | --- | --- |
| `host_id` | integer |  |
| `limit` | integer |  |

### `query_state`

Query shared target state for one host or the project.

| Argument | Type | Notes |
| --- | --- | --- |
| `host_id` | integer |  |
| `limit` | integer |  |

### `query_graph`

Query the project evidence graph.

| Argument | Type | Notes |
| --- | --- | --- |
| `node_types` | array of string |  |
| `edge_types` | array of string |  |
| `source_kinds` | array of string |  |
| `min_confidence` | number |  |
| `search` | string |  |
| `include_ai_suggested` | boolean |  |
| `host_id` | integer |  |
| `limit_nodes` | integer |  |
| `limit_edges` | integer |  |

### `list_execution_traces`

List execution traces from the normalized execution ledger.

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | integer |  |
| `host_id` | integer |  |
| `host_ip` | string |  |
| `tool_id` | string |  |
| `include_output` | boolean |  |

### `get_execution_trace`

Fetch a single execution trace and output excerpts.

| Argument | Type | Notes |
| --- | --- | --- |
| `execution_id` | string | required |
| `max_chars` | integer |  |

### `create_annotation`

Create or update a graph annotation.

| Argument | Type | Notes |
| --- | --- | --- |
| `target_kind` | string | required |
| `target_ref` | string | required |
| `body` | string | required |
| `created_by` | string |  |
| `source_ref` | string |  |
| `annotation_id` | string |  |

### `export_report`

Export a host or project report in JSON or Markdown.

| Argument | Type | Notes |
| --- | --- | --- |
| `scope` | string |  |
| `host_id` | integer |  |
| `format` | string |  |
