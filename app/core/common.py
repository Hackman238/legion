"""
Qt-free shared helpers for non-desktop execution paths.
"""

import os
import platform
import tempfile

from app.logging.legionLog import getAppLogger
from app.timing import timing

log = getAppLogger()


def winPath2Unix(windowsPath):
    windowsPath = windowsPath.replace("\\", "/")
    windowsPath = windowsPath.replace("C:", "/mnt/c")
    return windowsPath


def unixPath2Win(posixPath):
    posixPath = posixPath.replace("/", "\\")
    posixPath = posixPath.replace("\\mnt\\c", "C:")
    return posixPath


def isWsl():
    release = str(platform.uname().release).lower()
    return "microsoft" in release


def isKali():
    release = str(platform.uname().release).lower()
    return "kali" in release


def getAppdataTemp():
    try:
        username = os.environ["WSL_USER_NAME"]
    except KeyError as exc:
        raise Exception(
            "WSL detected but environment variable 'WSL_USER_NAME' is unset. "
            "Please run 'export WSL_USER_NAME=' followed by your username as it appears in c:\\Users\\"
        ) from exc

    appDataTemp = "C:\\Users\\{0}\\AppData\\Local\\Temp".format(username)
    appDataTempUnix = winPath2Unix(appDataTemp)

    if os.path.exists(appDataTempUnix):
        return appDataTemp
    raise Exception("The AppData Temp directory path {0} does not exist.".format(appDataTemp))


def getTempFolder():
    tempPath = os.environ.get("LEGION_TMPDIR")
    if tempPath is None:
        tempPath = os.path.join(tempfile.gettempdir(), "legion")
    if not os.path.isdir(tempPath):
        os.makedirs(tempPath, exist_ok=True)
    log.info(f"Using temp directory: {tempPath}")
    return tempPath


@timing
def sortArrayWithArray(array, arrayToSort):
    combined = sorted(zip(array, arrayToSort), key=lambda x: x[0])
    if combined:
        array[:], arrayToSort[:] = zip(*combined)
    else:
        array[:], arrayToSort[:] = [], []


class Wordlist:
    def __init__(self, filename):
        self.filename = filename
        self.wordlist = []
        with open(filename, "a+") as f:
            self.wordlist = f.readlines()
            log.info("Wordlist was created/opened: " + str(filename))

    def setFilename(self, filename):
        self.filename = filename

    def add(self, word):
        with open(self.filename, "a+") as f:
            f.seek(0)
            self.wordlist = f.readlines()
            if not word + "\n" in self.wordlist:
                log.info("Adding " + word + " to the wordlist..")
                self.wordlist.append(word + "\n")
                f.write(word + "\n")


class Filters:
    def __init__(self):
        self.checked = True
        self.up = True
        self.down = False
        self.tcp = True
        self.udp = True
        self.portopen = True
        self.portclosed = False
        self.portfiltered = False
        self.keywords = []

    @timing
    def apply(self, up, down, checked, portopen, portfiltered, portclosed, tcp, udp, keywords=None):
        self.checked = checked
        self.up = up
        self.down = down
        self.tcp = tcp
        self.udp = udp
        self.portopen = portopen
        self.portclosed = portclosed
        self.portfiltered = portfiltered
        self.keywords = keywords or []

    @timing
    def setKeywords(self, keywords):
        log.info(str(keywords))
        self.keywords = keywords

    @timing
    def getFilters(self):
        return [
            self.up,
            self.down,
            self.checked,
            self.portopen,
            self.portfiltered,
            self.portclosed,
            self.tcp,
            self.udp,
            self.keywords,
        ]

    @timing
    def display(self):
        log.info("Filters are:")
        log.info("Show checked hosts: " + str(self.checked))
        log.info("Show up hosts: " + str(self.up))
        log.info("Show down hosts: " + str(self.down))
        log.info("Show tcp: " + str(self.tcp))
        log.info("Show udp: " + str(self.udp))
        log.info("Show open ports: " + str(self.portopen))
        log.info("Show closed ports: " + str(self.portclosed))
        log.info("Show filtered ports: " + str(self.portfiltered))
        log.info("Keyword search:")
        for keyword in self.keywords:
            log.info(keyword)

