# Installing Legion and registering its MCP server

## Supported environments

Kali Linux (rolling), Ubuntu 22.04 or 24.04, Python 3.12 or newer. Nmap is the baseline external tool; the rest
(nikto, whatweb, hydra, sqlmap, enum4linux-ng, katana, httpx, ...) are optional and detected at run time.
`python3 legion.py --tool-audit` lists each tool, whether it was found, and the install command for Kali and
Ubuntu. Legion is local-first: no database server, Docker or network service is required. The Debian package
(`debian/`) and the Dockerfile are alternatives to the source install below.

## From source

```bash
git clone https://github.com/Hackman238/legion.git
cd legion
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap            # plus whatever --tool-audit says is missing
python3 legion.py --tool-audit
```

Re-run `pip install -r requirements.txt` after pulling updates. The web UI is `python3 legion.py --web`
(http://127.0.0.1:5000); it is useful alongside the MCP server because both read the same project file, so the
user can watch what the agent does.

## Kali side-by-side installer

Installs under `~/.local/opt/legion-web-dev` with its own virtualenv and data directory and a `legion`
launcher. Re-running it updates the checkout in place. With this install the Python is
`~/.local/opt/legion-web-dev/.venv/bin/python` and `legion.py` is in `~/.local/opt/legion-web-dev/`.

```bash
curl -fsSL https://raw.githubusercontent.com/Hackman238/legion/master/scripts/install-kali-side-by-side.sh | bash
```

## Docker

```bash
docker build -t legion .
docker run --rm -i -v legion-data:/data --cap-add=NET_RAW --cap-add=NET_ADMIN legion python3 legion.py --mcp-server
```

That `docker run` line is the MCP client's command (`command: docker`, the rest as `args`). `-i` keeps stdin
open for the JSON-RPC stream; the capabilities let nmap use raw sockets. When the container runs as a non-root
user, add `-e NMAP_PRIVILEGED=1`. Paths passed to `import_nmap_xml` or `save_project` are paths inside the
container, so mount the directories the agent needs.

## Privileges

OS detection (`-O`, part of `-A`) and SYN scans need raw sockets. Legion detects root, Windows `nmap.exe`
under WSL, and the `NMAP_PRIVILEGED=1` environment variable as privileged and `NMAP_UNPRIVILEGED=1` as not.
Without privilege it leaves OS detection out of every plan and logs one warning saying so; scans still run as
connect scans. Run the MCP client as root when the agent should get OS detection, or `setcap cap_net_raw+ep`
on the nmap binary and export `NMAP_PRIVILEGED=1` for the server.

## Data directory

`LEGION_HOME` (default `~/.local/share/legion`) holds `legion.conf` (tool and scheduler action mappings),
`scheduler-ai.json` (scheduler and AI provider preferences), autosaves and backups. API keys live in the OS
keyring or an encrypted local store; `SHODAN_API_KEY`, `CHAOS_API_KEY`, `GRAYHATWARFARE_API_KEY`,
`OPENAI_API_KEY` and `ANTHROPIC_API_KEY` are also honoured from the environment. Set `LEGION_HOME` in the MCP
server's `env` so the agent and the web UI share one configuration.

## Registering the server

Replace `/path/to/legion` with the checkout and use the interpreter that has the requirements installed.

### Claude Code

User scope (every project):

```bash
claude mcp add legion -e LEGION_HOME=$HOME/.local/share/legion -- /path/to/legion/.venv/bin/python /path/to/legion/legion.py --mcp-server
```

Project scope: a `.mcp.json` at the project root, which Claude Code asks to approve on first use:

```json
{
  "mcpServers": {
    "legion": {
      "command": "/path/to/legion/.venv/bin/python",
      "args": ["/path/to/legion/legion.py", "--mcp-server"],
      "env": {"LEGION_HOME": "/home/you/.local/share/legion"}
    }
  }
}
```

The Legion repository ships one that runs `python3 legion.py --mcp-server` from the checkout.

### Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.legion]
command = "/path/to/legion/.venv/bin/python"
args = ["/path/to/legion/legion.py", "--mcp-server"]
env = { LEGION_HOME = "/home/you/.local/share/legion" }
```

### Claude Desktop, Cursor and other JSON clients

The same `mcpServers.legion` object as the Claude Code project snippet, in the client's MCP settings file.

### Verify

```bash
python3 /path/to/legion/skills/legion-mcp/scripts/mcp_smoke_test.py --python /path/to/legion/.venv/bin/python --legion /path/to/legion/legion.py
```

It prints the server's name and version from `initialize`, the tool count from `tools/list` and the result
of `list_projects`. A JSON parse error means something wrote to stdout besides the server; start it with a
plain command rather than through a login shell that prints a banner.

## Installing this skill

The skill directory is `skills/legion-mcp` in the Legion repository. Copy or symlink it where the agent looks:

- Claude Code: `~/.claude/skills/legion-mcp` (every project) or `.claude/skills/legion-mcp` in a project.
- Codex: `~/.codex/skills/legion-mcp`, or `.agents/skills/legion-mcp` in a project.

The Legion repository carries both project-level links, so an agent working in the checkout has the skill.
