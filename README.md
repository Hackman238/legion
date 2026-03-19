# LEGION

[![Known Vulnerabilities](https://snyk.io/test/github/Hackman238/legion/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/Hackman238/legion?targetFile=requirements.txt)
[![Maintainability](https://api.codeclimate.com/v1/badges/c2055fddab6b95642b6e/maintainability)](https://codeclimate.com/github/Hackman238/legion/maintainability)

<p align="center">
  <img src="images/LegionBanner.png" alt="Legion banner">
</p>

<p align="center">
  <img src="images/LegionScreenshot.png" alt="Legion web interface screenshot">
</p>

## NOTICE

This is the active home of `LEGION`.

`0.6.0` is the release where Legion becomes meaningfully web-first: the web UI is now the primary operator interface, while headless CLI and MCP share the same orchestrator, approvals, evidence graph, state store, and reporting path.

After upgrading, review tool paths and provider settings under `Settings`, especially if you customize Nmap, browsers/screenshot tooling, Responder, NTLMRelay, or AI providers.

## ✨ About

Legion is a local-first, operator-guided reconnaissance and penetration testing platform with deterministic and AI-assisted orchestration.

It is MCP-enabled and supports governed deterministic and AI-assisted orchestration, project-based persistence, explicit approval gates, shared target state, evidence graphing, graph-backed reporting, and a web-first workflow for Kali and Ubuntu operators. AI providers supported include OpenAI, Claude and LM Studio. It also supports any local server that implements the OpenAI API.

The web interface is now the primary interface. Qt remains in-tree for compatibility, but the main product direction is the shared web, headless, and MCP workflow built on the same orchestration core.

## 🖥 Web Interface (Primary)

Start the primary interface with:

```shell
python3 legion.py --web --web-port 5000
```

Useful web launch variants:

```shell
# Bind on all interfaces
python3 legion.py --web --web-port 5000 --web-bind-all

# Disable transparency effects on slower hosts
python3 legion.py --web --web-port 5000 --web-opaque-ui
```

The web interface includes:

- project create/open/save/export workflows
- target import, Nmap XML import, and scan submission
- governed scheduler settings and AI/provider configuration
- live processes, retries, output viewing, and background jobs
- host and service workspace views
- host detail with notes, scripts, CVEs, screenshots, and contextual actions
- graph workspace with filters, exports, layout management, floating/docked detail inspector, and contextual node actions
- approval queue, submitted scans, scheduler decision history, and graph-backed reports
- tool audit visibility for checking whether Legion can resolve the external tools it depends on

## 🍿 What Legion Does

- Imports and scans hosts, subnets, FQDNs, and Nmap XML into a persistent project workspace.
- Correlates hosts, services, URLs, technologies, findings, screenshots, credentials, sessions, and evidence in a local graph.
- Runs governed deterministic and AI-assisted follow-up actions from the same action model.
- Applies engagement policy, risk classification, approval gates, and audit logging before risky execution.
- Keeps operator-visible evidence, artifacts, screenshots, execution history, and graph annotations in-project.
- Exposes the same orchestration path through the web UI, headless CLI, and MCP/API surfaces.

## 🚀 0.6.0 Highlights

- Web-first operator workflow with a ribbon-driven dashboard, compact project/process trays, logging modals, host exports/filters, and a graph-centric workspace.
- Shared orchestrator core across web, headless, MCP, and remaining Qt compatibility paths.
- First-class `deterministic` and `ai` scheduling modes using shared `ActionSpec`, `PlanStep`, and `ExecutionRecord` models.
- Engagement policy presets, richer risk taxonomy, auditable approvals, policy-aware blocking, and family-level approval controls.
- Shared target-state persistence and a local evidence graph with query/export APIs, graph layouts, annotations, and graph-backed reporting.
- Strategy-pack driven planning, optional runner abstraction, scan history, and intent-based process retry.
- Broader governed action coverage, including deeper web follow-up and safer internal SMB enumeration.
- Kali-first tool audit coverage with install hints for the external tools Legion launches or depends on.
- MCP expansion for governed project access, planning, approvals, graph queries, findings, state, execution traces, and reports.

## 🧰 Action And Tooling Coverage

Legion 0.6.0 now has two useful coverage counts:

- `273` normalized governed `ActionSpec` entries in the shared orchestrator registry.
- `338` checked-in configured action entries in `legion.conf`:
  - `42` scheduler mappings
  - `271` port actions
  - `11` host actions
  - `14` port terminal launchers

Additional runtime integrations outside static `legion.conf` include:

- normalized banner capture
- browser/screenshot runner with Chromium / Selenium / EyeWitness fallback paths
- Responder workspace integration
- NTLMRelay workspace integration

## 🔌 Other Interfaces

### Headless CLI

Legion can also run headless for automation:

```shell
python3 legion.py --headless --input-file targets.txt --staged-scan --run-actions --output-file results.json
```

### MCP Server

Legion can expose governed functionality over MCP:

```shell
python3 legion.py --mcp-server
```

The MCP surface covers project access, planning, approvals, graph queries, findings, state queries, execution traces, and report export through the same governed core used by the web interface.

### Qt Compatibility

Qt is still in-tree for compatibility and migration purposes, but it is no longer the primary documented path.

## 🌉 Recommended Environments

Legion is best supported today on recent Linux pentest/operator environments:

- current Kali rolling releases
- Ubuntu `22.04 LTS`
- Ubuntu `24.04 LTS`

Recommended baseline:

- Python `3.12+`
- a current Chromium or Firefox install for screenshot workflows
- Nmap plus whichever local tools you want Legion to orchestrate (`nuclei`, `ffuf`, `whatweb`, `smbmap`, `enum4linux-ng`, `wpscan`, and similar)

Legion is local-first by design. It does not require Docker, external databases, or remote services for its baseline workflow.

## 💻 Installation

### Quick Start From Source

```shell
git clone https://github.com/Hackman238/legion.git
cd legion
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 legion.py --web
```

Open `http://127.0.0.1:5000` unless you used `--web-bind-all`.

### Kali Side-By-Side Dev Install (No Package Overwrite)

To install a separate development copy on Kali without overwriting the packaged `legion`, use:

```shell
curl -fsSL https://raw.githubusercontent.com/Hackman238/legion/master/scripts/install-kali-side-by-side.sh | bash
```

This creates:

- source + venv under `~/.local/opt/legion-web-dev`
- isolated Legion data/config under `~/.local/share/legion-web-dev`
- launcher `~/.local/bin/legion-web-dev`

Re-running the installer replaces the prior side-by-side source tree with a fresh copy of the current branch before rebuilding the venv.

Recommended way to launch the side-by-side install:

```shell
cd ~/.local/opt/legion-web-dev
source ~/.local/opt/legion-web-dev/.venv/bin/activate
python3 legion.py --web
```

## 🏗 Development

### Command Line Flags

| Option | Description |
| --- | --- |
| `--web` | Run Legion with the web interface. |
| `--web-port` | Set the web interface port. Default: `5000`. |
| `--web-bind-all` | Bind the web interface to `0.0.0.0` instead of `127.0.0.1`. |
| `--web-opaque-ui` | Disable transparent UI effects for better responsiveness on slower hosts. |
| `--tool-audit` | Print an external tool availability audit and exit. |
| `--headless` | Run Legion in headless CLI mode. |
| `--mcp-server` | Start the MCP server for external automation / AI integration. |
| `--input-file` | Path to a text file of targets for headless mode. |
| `--discovery` | Enable host discovery in headless mode. |
| `--staged-scan` | Run staged Nmap scanning in headless mode. |
| `--output-file` | Export headless results to `.legion` or `.json`. |
| `--run-actions` | Run configured scripted actions / automated attacks after scan or import in headless mode. |

### Configuration Notes

- Legion stores its runtime data under `${LEGION_HOME:-~/.local/share/legion}`.
- Scheduler AI preferences are stored in plaintext at `${LEGION_HOME:-~/.local/share/legion}/scheduler-ai.json`.
- The checked-in action mappings still live in `legion.conf`.
- Tool paths, providers, and runtime behavior can be reviewed from the web UI under `Settings`.

To modify the action mappings directly:

```shell
sudoedit "${LEGION_HOME:-~/.local/share/legion}/legion.conf"
```

### Running Tests

To run the full test suite:

```shell
python3 -m unittest
```

## ⚖️ License

Legion is licensed under the GNU General Public License v3.0. See
[LICENSE](https://github.com/Hackman238/legion/blob/master/LICENSE).

## ⭐️ Attribution

- Fork based from <http://github.com/GoVanguard/legion> by Shane Scott.
- Refactored Python 3 codebase, expanded feature set, and ongoing Legion development are credited to Hackman238 and sscottgvit.
- The initial Sparta Python 2.7 codebase and application design are credited to SECFORCE.
- Several additional `PortActions`, `PortTerminalActions`, and `SchedulerSettings` are credited to batmancrew.
- The Nmap XML parsing engine was largely based on code by yunshu, modified by ketchup and SECFORCE.
- `ms08-067_check` used by `smbenum.sh` is credited to Bernardo Damele A.G.
- Legion depends heavily on Nmap, Hydra, Python, Flask, PyQt, SQLAlchemy, Selenium, Chromium/Firefox, and many other tools and projects.
- Special thanks to Dmitriy Dubson for continued contributions to the project.
