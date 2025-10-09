## NOTICE

This is the new home of "Legion". A major release is out!

Having [screenshot issues](#screenshot-issues)?

##
[![Known Vulnerabilities](https://snyk.io/test/github/Hackman238/legion/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/Hackman238/legion?targetFile=requirements.txt)
[![Maintainability](https://api.codeclimate.com/v1/badges/c2055fddab6b95642b6e/maintainability)](https://codeclimate.com/github/Hackman238/legion/maintainability)

![alt tag](https://github.com/Hackman238/legion/blob/master/images/LegionBanner.png)

## ✨ About

Legion, a fork of SECFORCE's Sparta, is an open source, easy-to-use, super-extensible, and semi-automated network
penetration testing framework that aids in discovery, reconnaissance, and exploitation of information systems.

## 🍿 Features

* Automatic recon and scanning with NMAP, whataweb, nikto, Vulners, Hydra, SMBenum, dirbuster, sslyzer, webslayer and
  more (with almost 100 auto-scheduled scripts).
* Easy to use graphical interface with rich context menus and panels that allow pentesters to quickly find and exploit
  attack vectors on hosts.
* Modular functionality allows users to easily customize Legion and automatically call their own scripts/tools.
* Multiple custom scan configurations ideal for testing different environments of various size and complexity. 
* Highly customizable stage scanning for ninja-like IPS evasion.
* Automatic detection of CPEs (Common Platform Enumeration) and CVEs (Common Vulnerabilities and Exposures), now with enhanced mapping to ExploitDB including direct links to exploits.
* Integrated screenshotting: Take, view, and manage screenshots of web services directly from the UI, with support for EyeWitness and advanced screenshot management.
* Optional IPv6 scanning support with automatic fallback when native IPv6 connectivity is unavailable.
* Smarter project restores: tool tabs return exactly as you left them, Tools listings deduplicate tidily, missing screenshots display a helpful placeholder instead of blocking dialogs, the process table shows only meaningful columns, and tool tabs now offer a one-click Save option. Automated screenshots prefer hostnames when available, falling back to IP when needed.
* Realtime auto-saving of project results and tasks.
* Numerous quality of life improvements: UI enhancements, improved error handling, more robust project export (sqlite abd json), and expanded configurability.

### Notable changes from Sparta

* Major overhaul of screenshotting subsystem: asynchronous operation, EyeWitness integration, deterministic filenames, and UI improvements for screenshot management.
* Enhanced CVE mapping: CVEs now include ExploitDB IDs and direct links, with improved association to services and hosts.
* Many quality of life improvements: better context menus, tab management, error handling, and expanded test coverage.
* Refactored from Python 2.7 to Python 3.10+ and the elimination of deprecated and unmaintained libraries.
* Upgraded to PyQT6, increased responsiveness, less buggy, more intuitive GUI that includes features like:
    * Task completion estimates
    * 1-Click scan lists of ips, hostnames and CIDR subnets
    * Ability to purge results, rescan hosts and delete hosts
    * Granular NMAP scanning options
* Support for hostname resolution and scanning of vhosts/sni hosts.
* Revise process queuing and execution routines for increased app reliability and performance.
* Simplification of installation with dependency resolution and installation routines.
* Realtime project auto-saving so in the event some goes wrong, you will not lose any progress!
* Docker container deployment option.
* Supported by a highly active development team.

## 🌉 Supported Distributions

### Docker runIt script support

RunIt script (`docker/runIt.sh`) supports:

- Ubuntu 20.04+
- Kali 2022+

It is possible to run the docker image on any Linux distribution, however, different distributions have different hoops
to jump through to get a docker app to be able to connect to the X server. Everyone is welcome to try to figure those
hoops out and create a PR for runIt.

### Traditional installation support

We can only promise correct operation on **Ubuntu 20.04** using the traditional installation at this time. While it should
work on ParrotOS, Kali, and others, until we have Legion packaged and placed into the repos for each of these distros,
it is musical chairs in regard to platform updates changing and breaking dependencies. Native a native package exists and is 
included by default on Kali.

## 💻 Installation

Two installation methods available:

- [Docker method](#traditional-installation-method)
- [Traditional installation method](#traditional-installation-method)

It is **preferable** to use the Docker method over a traditional installation. This is because of all the dependency
requirements and the complications that occur in environments which differ from a clean, non-default installation.

> NOTE: Docker versions of Legion are *unlikely* to work when run as root or under a root X!

### Docker method

**Note:** As of September 2025, the Docker images have been updated to use the official `python:3.10` base image with all required system dependencies (Qt6, git, etc.) installed via `apt-get`. If you previously relied on a custom or private base image, you no longer need access to it. See `docker/Dockerfile` for details.

Docker method includes support for various environments, choose the one that works for you.

- [Linux with local X11](#linux-with-local-x11)
- [Linux with remote X11](#linux-with-remote-x11)
- [Windows under WSL](#windows-under-wsl-using-xming-and-docker-desktop)
- [⚠️ Windows without WSL](#windows-using-xming-and-docker-desktop-without-wsl)
- [⚠️ OSX using XQuartz](#osx-using-xquartz)

#### Linux with local X11

Assumes **Docker** and **X11** are installed and set up (including running Docker commands as a non-root user).

It is critical to follow all the instructions for running as a non-root user. Skipping any of them will result in
complications getting Docker to communicate with the X server.

See detailed instructions to set up Docker [here](#configuring-docker) and enable running containers as non-root users
and granting Docker group SSH rights [here](#setup-docker-to-allow-non-root-users).

Within Terminal:

```shell
git clone https://github.com/Hackman238/legion.git
cd legion/docker
chmod +x runIt.sh
./runIt.sh
```

#### Linux with remote X11

Assumes **Docker** and **X11** are installed and set up.

Replace `X.X.X.X` with the IP address of the remote running X11.

Within Terminal:

```shell
git clone https://github.com/Hackman238/legion.git
cd legion/docker
chmod +x runIt.sh
./runIt.sh X.X.X.X
```

#### Windows under WSL using Xming and Docker Desktop

Assumes:

- Xming is installed in Windows.
- Docker Desktop is installed in Windows
- Docker Desktop is running in Linux containers mode
- Docker Desktop is connected to WSL.

See detailed Docker instructions [here](#setup-hyper-v-docker-desktop-xming-and-wsl)

Replace `X.X.X.X` with the IP address with which Xming has registered itself. Right click Xming in system tray -> View
log and see IP next to "XdmcpRegisterConnection: newAddress"

Within Terminal:

```shell
git clone https://github.com/Hackman238/legion.git
cd legion/docker
sudo chmod +x runIt.sh
sudo ./runIt.sh X.X.X.X
```

#### Windows using Xming and Docker Desktop without WSL

Why? Don't do this. :)

#### OSX using XQuartz

Not yet in `runIt.sh` script. Possible to set up using `socat`.
See [instructions here](https://kartoza.com/en/blog/how-to-run-a-linux-gui-application-on-osx-using-docker/)

#### Configuring Docker

#### Setting up Docker on Linux

To install Docker components typically needed and add set up the environment for Docker, under a term, run:

```shell
sudo apt-get update
sudo apt-get install -y docker.io python3-pip -y
sudo groupadd docker
pip install --user docker-compose
```

#### Setup Docker to allow non-root users

To enable non-root users to run Docker commands, under a term, run:

```shell
sudo usermod -aG docker $USER
sudo chmod 666 /var/run/docker.sock
sudo xhost +local:docker
```

#### Setup Hyper-V, Docker Desktop, Xming and WSL

The order is important for port reservation reasons. If you have WSL, HyperV, or Docker Desktop installed then please
uninstall those features before proceeding.

- Search -> cmd -> Right click -> Run as Administrator
- To reserve the Docker port, under CMD, run:
  ```shell
  netsh int ipv4 add excludedportrange protocol=tcp startport=2375 numberofports=1
  ```
    - This will likely fail if you have Hyper-V already enabled or Docker Desktop installed
- To install Hyper-V, under CMD, run:
  ```shell
  dism.exe /Online /Enable-Feature:Microsoft-Hyper-V /All
  ```
- Reboot
- Cortana / Search -> cmd -> Right click -> Run as Administrator
- To install WSL, under CMD, run:
  ```shell
  dism.exe /Online /Enable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux
  ```
- Reboot
- Download from <https://hub.docker.com/editions/community/docker-ce-desktop-windows> (Free account required)
- Run installer
- Optionally input your Docker Hub login
- Right click Docker Desktop in system tray -> Switch to Linux containers
    - If it says Switch to Windows containers then skip this step, it's already using Linux containers
- Right click Docker Desktop in system tray -> Settings
- General -> Expose on localhost without TLS
- Download <https://sourceforge.net/projects/xming/files/Xming/6.9.0.31/Xming-6-9-0-31-setup.exe/download>
- Run installer and select multi window mode
- Open Microsoft Store
- Install Kali, Ubuntu or one of the other WSL Linux Distributions
- Open the distribution, let it bootstrap and fill in the user creation details
- To install Docker components typically needed and add set up the environment for Docker redirection, under the WSL
  window, run:
  ```shell
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
  sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
  sudo apt-get update
  sudo apt-get install -y docker-ce python-pip -y
  sudo apt autoremove
  sudo usermod -aG docker $USER
  pip install --user docker-compose
  echo "export DOCKER_HOST=tcp://localhost:2375" >> ~/.bashrc && source ~/.bashrc
  ```
- Test Docker is reachable with:
  ```shell
  docker images
  ```

### Screenshot issues
If you have screenshot issues run the following:
```shell
sudo su -
cd /tmp
curl -L https://raw.githubusercontent.com/nagyist/hackman238.legion/refs/heads/master/deps/checkGeckodriver.sh > checkGekodriver.sh
curl -L https://raw.githubusercontent.com/Hackman238/legion/refs/heads/master/deps/checkEyewitness.sh > checkEyewitness.sh
chmod +x checkGekodriver.sh; chmod +x checkEyewitness.sh
./checkGekodriver.sh
./checkEyewitness.sh
```

### Traditional installation method

> Please use the Docker image where possible! It's becoming very difficult to support all the various platforms and
> their own quirks.

Assumes Ubuntu, Kali or Parrot Linux is being used with **Python 3.6** installed.

Within Terminal:

```shell
git clone https://github.com/Hackman238/legion.git
cd legion
sudo chmod +x startLegion.sh
sudo ./startLegion.sh
```

## 🏗 Development

### Command Line Options

Legion can be run in headless (CLI) mode for automation and scripting. The following command line options are available:

| Option            | Description                                                                                  |
|-------------------|----------------------------------------------------------------------------------------------|
| `--mcp-server`    | Start the MCP server for AI integration.                                                     |
| `--headless`      | Run Legion in headless (CLI) mode (no GUI).                                                  |
| `--input-file`    | Path to a text file with targets (hostnames, subnets, IPs, etc.). Required in headless mode. |
| `--discovery`     | Enable host discovery (default: enabled).                                                    |
| `--staged-scan`   | Enable staged scan (performs a fast scan, then a service scan).                              |
| `--output-file`   | Output file path. Supports `.legion` (project) or `.json` (exported results).                |
| `--run-actions`   | Run scripted actions/automated attacks (including screenshots) after scan/import in CLI mode. |

**Example usage:**

```shell
python legion.py --headless --input-file targets.txt --output-file results.json --run-actions
```

This will run Legion in CLI mode, import targets from `targets.txt`, perform scanning, run all configured scripted actions/automated attacks (including screenshots), and export results to `results.json`.

---

## 🧩 Model Context Protocol (MCP) Server Integration

Legion now supports the Model Context Protocol (MCP) server, enabling advanced automation, AI integration, and programmatic control of Legion's core features via JSON-RPC.

### What is the MCP Server?

The MCP server exposes Legion's internal functionality as a set of programmable "tools" accessible over a JSON-RPC interface. This allows external applications, scripts, or AI agents to interact with Legion, automate workflows, and retrieve structured results.

### How to Start the MCP Server

Start Legion with the `--mcp-server` flag:

```shell
python legion.py --mcp-server
```

The MCP server will listen for JSON-RPC requests via stdin/stdout.

### Available Tools

The MCP server currently exposes the following tools:

- **list_projects**: Lists all Legion project files in the temp folder.
  - **Input:** None
  - **Returns:** List of project filenames

- **run_discovery**: Runs a quick discovery scan (nmap -F) on a target (default: localhost), imports results, and returns structured host/port/service data.
  - **Input:** `{ "target": "host_or_ip" }` (optional, defaults to "localhost")
  - **Returns:** Structured scan results for the target

### Example JSON-RPC Requests

**List available tools:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "list_tools"
}
```

**Run a discovery scan:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "call_tool",
  "params": {
    "name": "run_discovery",
    "arguments": { "target": "192.168.1.1" }
  }
}
```

**Sample response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "target": "192.168.1.1",
    "results": [
      {
        "ip": "192.168.1.1",
        "hostname": "host1",
        "ports": [
          {
            "port": 22,
            "state": "open",
            "service": {
              "name": "ssh",
              "product": "OpenSSH"
            }
          }
        ]
      }
    ],
    "debug_info": { ... }
  }
}
```

### Use Cases

- **AI Integration:** Connect Legion to AI agents for automated reconnaissance, scanning, and reporting.
- **Automation:** Script complex workflows that require dynamic interaction with Legion's scanning and project management features.
- **External Tooling:** Build custom dashboards, orchestration tools, or integrations with other security platforms.

**Note:** The MCP server is under active development. See the source code (`app/mcp_server.py`) for the latest available tools and schemas.

---
### Executing test cases

To run all test cases, execute the following in root directory:

```shell
python -m unittest
```

### Modifying Configuration

The configuration of selected ports and associated terminal actions can be easily modified by editing the legion.conf file. 
> [StagedNmapSettings] defines what ports will be scanned in sequential order as well as any NSE scripts that will be called. 
> 
> [SchedulerSettings] defines what actions will occur automatically based upon port scan results.

```shell
sudoedit /root/.local/share/legion/legion.conf
```

## ⚖️ License

Legion is licensed under the GNU General Public License v3.0. Take a look at the
[LICENSE](https://github.com/Hackman238/legion/blob/master/LICENSE) for more information.

## ⭐️ Attribution

* Fork based from http://github.com/GoVanguard/legion by Shane Scott.
* Refactored Python 3.6+ codebase, added feature set and ongoing development of Legion is credited
  to [Hackman238] & [sscottgvit] (Shane Scott)
* The initial Sparta Python 2.7 codebase and application design is credited SECFORCE.
* Several additional PortActions, PortTerminalActions and SchedulerSettings are credited to batmancrew.
* The nmap XML output parsing engine was largely based on code by yunshu, modified by ketchup and modified SECFORCE.
* ms08-067_check script used by `smbenum.sh` is credited to Bernardo Damele A.G.
* Legion relies heavily on nmap, hydra, python, PyQt, SQLAlchemy and many other tools and technologies, so we would like
  to thank all of the people involved in the creation of those.
* Special thanks to Dmitriy Dubson [ddubson] for his continued contributions to the project!
