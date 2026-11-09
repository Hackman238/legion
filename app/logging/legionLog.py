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

import logging
from logging import Logger

# Python 3.12's LogRecord.taskName path calls asyncio.current_task().
# In this environment that segfaults once sqlalchemy/greenlet are loaded,
# so disable asyncio task-name capture globally before any records are created.
if hasattr(logging, "logAsyncioTasks"):
    logging.logAsyncioTasks = False

# Legion logs to the console (stderr) through Rich; nothing is written to a log file, so importing this module
# touches no directory and works with a read-only or absent home (containers, service accounts).

cachedAppLogger = None
cachedStartupLogger = None
cachedDbLogger = None


def getStartupLogger() -> Logger:
    global cachedStartupLogger
    cachedStartupLogger = getOrCreateCachedLogger("legion-startup", cachedStartupLogger)
    return cachedStartupLogger


def getAppLogger() -> Logger:
    global cachedAppLogger
    cachedAppLogger = getOrCreateCachedLogger("legion", cachedAppLogger)
    return cachedAppLogger


def getDbLogger() -> Logger:
    global cachedDbLogger
    cachedDbLogger = getOrCreateCachedLogger("legion-db", cachedDbLogger)
    return cachedDbLogger


def getOrCreateCachedLogger(logName: str, cachedLogger):
    if cachedLogger:
        return cachedLogger

    import sys
    from rich.console import Console
    from rich.logging import RichHandler
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=Console(file=sys.stderr))]
    )

    log = logging.getLogger("rich")
    log.setLevel(logging.INFO)
    return log
