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
import subprocess
from logging import Logger

from app.shell.Shell import Shell
from app.timing import timing
from app.tools.nmap.NmapExporter import NmapExporter
import os


def findNmapXsl() -> str:
    # The repo ships nmap.xsl at its root; packaged nmap also installs one
    # (Homebrew on macOS, /usr/share on Linux). First existing wins.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    candidates = [
        os.path.join(repo_root, "nmap.xsl"),
        "/opt/homebrew/share/nmap/nmap.xsl",
        "/usr/local/share/nmap/nmap.xsl",
        "/usr/share/nmap/nmap.xsl",
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


class DefaultNmapExporter(NmapExporter):
    def __init__(self, shell: Shell, logger: Logger):
        self.logger = logger
        self.shell = shell

    @timing
    def exportOutputToHtml(self, fileName: str, outputFolder: str) -> None:
        try:
            # Argv list (no shell): paths may contain spaces.
            p = subprocess.Popen(
                ["xsltproc", "-o", f"{fileName}.html", findNmapXsl(), f"{fileName}.xml"]
            )
            p.wait()
            self.shell.move(f"{fileName}.html", outputFolder)
        except:
            self.logger.error("nmap output export to html attempted, but failed.")
            self.logger.error('Could not convert nmap XML to HTML. '
                              'Install xsltproc (brew install libxslt / apt-get install xsltproc)')
