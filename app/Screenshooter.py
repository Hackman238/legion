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
from app.httputil.isHttps import isHttps
from app.timing import getTimestamp
from app.auxiliary import isKali

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

        if isHttps(host_for_https, port):
            url = 'https://{0}'.format(url)
        else:
            url = 'http://{0}'.format(url)

        self.tsLog('Taking Screenshot of: {0}'.format(str(url)))

        # Use eyewitness under Kali.
        # Use webdriver if not Kali.
        # Once eyewitness is more broadly available, the counter case can be eliminated.
        if isKali():
            eyewitness_path = "/usr/bin/eyewitness"
        else:
            eyewitness_path = "/usr/local/bin/eyewitness"

        import tempfile
        import subprocess

        try:
            tmpOutputfolder = tempfile.mkdtemp(dir=self.outputfolder)
            if not os.path.isfile(eyewitness_path):
                raise FileNotFoundError("EyeWitness not found at /usr/bin/eyewitness. Please install it.")

            command = (
                'xvfb-run -a {eyewitness} --single {url} --no-prompt --web --delay 5 -d {outputfolder}'
            ).format(
                eyewitness=eyewitness_path,
                url=url,
                outputfolder=tmpOutputfolder
            )
            self.tsLog(f'Executing: {command}')
            # Flake8: break up long command string if needed
            p = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p.wait()  # wait for command to finish

            screens_dir = os.path.join(tmpOutputfolder, 'screens')
            if not os.path.isdir(screens_dir):
                raise FileNotFoundError(f"EyeWitness did not create expected directory: {screens_dir}")

            files = [f for f in os.listdir(screens_dir) if f.lower().endswith('.png')]
            if not files:
                raise FileNotFoundError(f"No screenshot PNG found in {screens_dir}. EyeWitness may have failed.")

            fileName = files[0]
            # Remove prefix in a way compatible with all Python versions
            if tmpOutputfolder.startswith(self.outputfolder):
                rel_tmp = tmpOutputfolder[len(self.outputfolder):].lstrip(os.sep)
            else:
                rel_tmp = tmpOutputfolder
            outputfile = os.path.join(rel_tmp, 'screens', fileName)
            # Normalize for DB/UI
            normalized_outputfile = outputfile.replace("\\", "/")
            outputfile = normalized_outputfile

            # Copy/rename to deterministic filename for deduplication
            deterministic_name = f"{ip}-{port}-screenshot.png"
            deterministic_path = os.path.join(self.outputfolder, deterministic_name)
            try:
                import shutil
                src_path = os.path.join(tmpOutputfolder, 'screens', fileName)
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
