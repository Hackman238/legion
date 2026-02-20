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

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from PyQt6 import QtCore

from app.logging.legionLog import getAppLogger
from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.httputil.isHttps import isHttps
from app.timing import getTimestamp

logger = getAppLogger()

class Screenshooter(QtCore.QThread):
    done = QtCore.pyqtSignal(str, str, str, name="done")  # signal sent after each individual screenshot is taken
    log = QtCore.pyqtSignal(str, name="log")

    def __init__(self, timeout):
        QtCore.QThread.__init__(self, parent=None)
        self.queue = []
        self.processing = False
        self.timeout = timeout  # screenshooter timeout (ms)

    def tsLog(self, msg):
        self.log.emit(str(msg))
        logger.info(msg)

    def addToQueue(self, ip, port, url):
        self.queue.append([ip, port, url])

    # this function should be called when the project is saved/saved as as the tool-output folder changes
    def updateOutputFolder(self, screenshotsFolder):
        self.outputfolder = screenshotsFolder

    def run(self):
        while self.processing == True:
            self.sleep(1)  # effectively a semaphore

        self.processing = True

        for i in range(0, len(self.queue)):
            try:
                queueItem = self.queue.pop(0)
                ip = queueItem[0]
                port = queueItem[1]
                url = queueItem[2]
                outputfile = getTimestamp() + '-screenshot-' + url.replace(':', '-') + '.png'
                self.save(url, ip, port, outputfile)

            except Exception as e:
                self.tsLog('Unable to take the screenshot. Error follows.')
                self.tsLog(e)
                continue

        self.processing = False

        if not len(self.queue) == 0:
            # if meanwhile queue were added to the queue, start over unless we are in pause mode
            self.run()

    def save(self, url, ip, port, outputfile):
        # Handle single node URI case by pivot to IP
        if len(str(url).split('.')) == 1:
            url = '{0}:{1}'.format(str(ip), str(port))

        host_for_https = str(url)
        if '://' in host_for_https:
            host_for_https = host_for_https.split('://', 1)[1]
        host_for_https = host_for_https.split(':', 1)[0]

        prefer_https = bool(isHttps(host_for_https, port))
        host_port = str(url)
        url_candidates = [
            'https://{0}'.format(host_port),
            'http://{0}'.format(host_port),
        ] if prefer_https else [
            'http://{0}'.format(host_port),
            'https://{0}'.format(host_port),
        ]
        self.tsLog('Taking Screenshot of: {0}'.format(str(url_candidates[0])))

        try:
            capture = None
            failure_capture = None
            for current_url in url_candidates:
                current_capture = run_eyewitness_capture(
                    url=current_url,
                    output_parent_dir=self.outputfolder,
                    delay=5,
                    use_xvfb=True,
                    timeout=180,
                )
                if current_capture.get("ok"):
                    capture = current_capture
                    break
                failure_capture = current_capture
                if str(current_capture.get("reason", "") or "") == "eyewitness missing":
                    break

            if not capture:
                failed = failure_capture or {}
                reason = str(failed.get("reason", "") or "")
                if reason == "eyewitness missing":
                    raise FileNotFoundError("EyeWitness executable was not found.")
                detail = summarize_eyewitness_failure(failed.get("attempts", []))
                if detail:
                    raise FileNotFoundError(
                        f"No screenshot PNG found in EyeWitness output. Last error: {detail}"
                    )
                raise FileNotFoundError("No screenshot PNG found in EyeWitness output.")

            command = capture.get("command", [])
            if command:
                self.tsLog(f"Executing: {' '.join(command)}")
            src_path = str(capture.get("screenshot_path", "") or "")
            if not src_path or not os.path.isfile(src_path):
                raise FileNotFoundError("EyeWitness did not return a usable screenshot file.")

            fileName = os.path.basename(src_path)
            outputfile = os.path.relpath(src_path, self.outputfolder)
            # Normalize for DB/UI
            normalized_outputfile = outputfile.replace("\\", "/")
            outputfile = normalized_outputfile

            # Copy/rename to deterministic filename for deduplication
            deterministic_name = f"{ip}-{port}-screenshot.png"
            deterministic_path = os.path.join(self.outputfolder, deterministic_name)
            try:
                import shutil
                shutil.copy2(src_path, deterministic_path)
                self.tsLog(
                f"Copied screenshot to deterministic filename: {deterministic_path}"
            )
            except Exception as e:
                self.tsLog(f"Failed to copy screenshot to deterministic filename: {e}")

        except Exception as e:
            self.tsLog(f"EyeWitness screenshot failed: {e}")
            self.done.emit(ip, port, "")
            return
        
        self.tsLog('Saving screenshot as: {0}'.format(str(outputfile)))
        self.done.emit(ip, port, outputfile)  # send a signal to add the 'process' to the DB
