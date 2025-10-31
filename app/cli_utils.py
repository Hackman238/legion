"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""

import os
import sys
import subprocess
from db.entities.host import hostObj

def import_targets_from_textfile(session, hostRepository, filename):
    """
    Import targets (hostnames, subnets, IPs, etc.) from a text file into the database.
    Each line is treated as a target.
    """
    added = 0
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                target = line.strip()
                if not target or target.startswith("#"):
                    continue
                try:
                    db_host = hostRepository.getHostInformation(target)
                except Exception as repo_exc:
                    print(
                        f"Warning: unable to check existing host '{target}' ({filename}:{line_number}): {repo_exc}",
                        file=sys.stderr
                    )
                    continue
                if db_host:
                    continue
                hid = hostObj(ip=target, ipv4=target, ipv6='', macaddr='', status='', hostname=target,
                              vendor='', uptime='', lastboot='', distance='', state='', count='')
                try:
                    session.add(hid)
                    session.commit()
                    added += 1
                except Exception as db_exc:
                    session.rollback()
                    print(
                        f"Error importing target '{target}' ({filename}:{line_number}): {db_exc}",
                        file=sys.stderr
                    )
    except FileNotFoundError:
        print(f"Error: input file '{filename}' not found.", file=sys.stderr)
        return 0
    except OSError as exc:
        print(f"Error opening input file '{filename}': {exc}", file=sys.stderr)
        return added
    return added

def is_wsl():
    try:
        with open('/proc/version', 'r') as f:
            return 'Microsoft' in f.read()
    except Exception:
        return False

def to_windows_path(path):
    try:
        import subprocess
        return subprocess.check_output(['wslpath', '-w', path]).decode().strip()
    except Exception:
        # Fallback: naive conversion for /mnt/c/...
        if path.startswith('/mnt/'):
            drive = path[5]
            rest = path[6:]
            rest_win = rest.replace('/', '\\')
            return f"{drive.upper()}:\\{rest_win}"
        return path

def run_nmap_scan(targets, output_prefix, discovery=True, staged=False, nmap_path="nmap"):
    """
    Run nmap scan on the given targets.
    - targets: string of targets (space/comma separated)
    - output_prefix: path prefix for nmap output files
    - discovery: if True, enable host discovery; if False, use -Pn
    - staged: if True, run a staged scan (simple implementation: run a basic scan, then a service scan)
    Returns the path to the main nmap XML output.
    """
    # Convert output_prefix to Windows path if running under WSL and using nmap.exe
    def convert_if_needed(prefix):
        if is_wsl() and nmap_path.lower().endswith('.exe'):
            return to_windows_path(prefix)
        return prefix

    if staged:
        # Example staged: first a fast scan, then a service scan
        # Stage 1: host discovery
        output_prefix1 = output_prefix + "_stage1"
        output_prefix1_conv = convert_if_needed(output_prefix1)
        cmd1 = [nmap_path, "-sn"] + targets.split() + ["-oA", output_prefix1_conv]
        try:
            subprocess.run(cmd1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(f"Error running nmap stage 1: {e}", file=sys.stderr)
            return None
        # Stage 2: service/version scan on discovered hosts (for demo, just rerun on all)
        output_prefix2 = output_prefix + "_stage2"
        output_prefix2_conv = convert_if_needed(output_prefix2)
        cmd2 = [nmap_path, "-sV", "-O"] + targets.split() + ["-oA", output_prefix2_conv]
        if not discovery:
            cmd2.insert(1, "-Pn")
        try:
            subprocess.run(cmd2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(f"Error running nmap stage 2: {e}", file=sys.stderr)
            return None
        return output_prefix + "_stage2.xml"
    else:
        output_prefix_conv = convert_if_needed(output_prefix)
        cmd = [nmap_path]
        if not discovery:
            cmd.append("-Pn")
        cmd += ["-T4", "-sV", "-O"] + targets.split() + ["-oA", output_prefix_conv]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(f"Error running nmap: {e}", file=sys.stderr)
            return None
        return output_prefix + ".xml"
