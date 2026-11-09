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
import unittest
from datetime import datetime
from time import time
from unittest.mock import patch

from app.timing import getTimestamp


class TimingTest(unittest.TestCase):
    def test_getTimestamp_WhenInvokedWithNoParameters_ReturnsStandardFormattedTimestamp(self):
        expectedStandardTimestampFormat = "%Y%m%d%H%M%S%f"
        parsed = datetime.strptime(getTimestamp(), expectedStandardTimestampFormat)
        currentTime = datetime.fromtimestamp(time())
        self.assertLess(abs((currentTime - parsed).total_seconds()), 2)

    def test_getTimestamp_WhenInvokedWithHumanParameter_ReturnsHumanFormattedTimestamp(self):
        expectedHumanTimestampFormat = "%d %b %Y %H:%M:%S.%f"
        parsed = datetime.strptime(getTimestamp(human=True), expectedHumanTimestampFormat)
        currentTime = datetime.fromtimestamp(time())
        self.assertLess(abs((currentTime - parsed).total_seconds()), 2)
