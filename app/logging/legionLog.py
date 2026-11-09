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
import logging
from logging import Logger

# Python 3.12's LogRecord.taskName path calls asyncio.current_task().
# In this environment that segfaults once sqlalchemy/greenlet are loaded,
# so disable asyncio task-name capture globally before any records are created.
if hasattr(logging, "logAsyncioTasks"):
    logging.logAsyncioTasks = False

cachedAppLogger = None
cachedStartupLogger = None
cachedDbLogger = None

cache_path = os.environ.get("LEGION_LOG_DIR") or os.path.expanduser("~/.cache/legion/log")
try:
    os.makedirs(cache_path, exist_ok=True)
except OSError:
    # A read-only or absent home (containers, service accounts): log under the temp dir instead of crashing.
    import tempfile
    cache_path = os.path.join(tempfile.gettempdir(), "legion", "log")
    try:
        os.makedirs(cache_path, exist_ok=True)
    except OSError:
        cache_path = tempfile.gettempdir()
log_path = os.path.join(cache_path, 'legion.log')

def getStartupLogger() -> Logger:
    global cachedStartupLogger
    logger = getOrCreateCachedLogger("legion-startup",
            os.path.join(cache_path, "legion-startup.log"), True, cachedStartupLogger)
    cachedStartupLogger = logger
    return logger


def getAppLogger() -> Logger:
    global cachedAppLogger
    logger = getOrCreateCachedLogger("legion",
            log_path, True, cachedAppLogger)
    cachedAppLogger = logger
    return logger


def getDbLogger() -> Logger:
    global cachedDbLogger
    logger = getOrCreateCachedLogger("legion-db",
            os.path.join(cache_path, "legion-db.log"), False, cachedDbLogger)
    cachedDbLogger = logger
    return logger


def getOrCreateCachedLogger(logName: str, logPath: str, console: bool, cachedLogger):
    if cachedLogger:
        return cachedLogger

    from rich.logging import RichHandler

    import sys
    from rich.console import Console
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=Console(file=sys.stderr))]
    )

    log = logging.getLogger("rich")
    log.setLevel(logging.INFO)
    return log
