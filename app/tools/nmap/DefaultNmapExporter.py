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


class DefaultNmapExporter(NmapExporter):
    def __init__(self, shell: Shell, logger: Logger):
        self.logger = logger
        self.shell = shell

    # xsltproc runs synchronously because the caller moves the XML right after conversion; bound it so a
    # hung conversion cannot freeze the caller (this runs on the UI thread in the desktop app).
    XSLTPROC_TIMEOUT_SECONDS = 60

    @timing
    def exportOutputToHtml(self, fileName: str, outputFolder: str) -> None:
        command = ["xsltproc", "-o", f"{fileName}.html", "/usr/share/nmap/nmap.xsl", f"{fileName}.xml"]
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=self.XSLTPROC_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            self.logger.error('Could not convert nmap XML to HTML: xsltproc not found. Try: apt-get install xsltproc')
            return
        except subprocess.TimeoutExpired:
            self.logger.error(f"nmap output export to html timed out after {self.XSLTPROC_TIMEOUT_SECONDS}s: {fileName}")
            return
        except subprocess.CalledProcessError as exc:
            # xsltproc can report errors (e.g. for a partial XML from a killed scan) and still write a
            # usable report, so keep going and move whatever it produced.
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace").strip()
            self.logger.error(f"nmap output export to html reported errors (exit {exc.returncode}): {stderr}")
        except OSError as exc:
            self.logger.error(f"nmap output export to html attempted, but failed: {exc}")
            return
        if not self.shell.isFile(f"{fileName}.html"):
            return
        try:
            self.shell.move(f"{fileName}.html", outputFolder)
        except OSError as exc:
            self.logger.error(f"Could not move nmap HTML report to {outputFolder}: {exc}")
