"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2024 Shane Scott

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

from db.validation import sanitise


class validationTests(unittest.TestCase):
    def test_sanitise_whenGivenAStringIncludingSingleQuotes_EscapesSingleQuotes(self):
        self.assertEqual(sanitise("my' escaped ' string"), "my'' escaped '' string")

    def test_sanitise_whenGivenAStringWithNoSingleQuotes_ReturnsSameString(self):
        self.assertEqual("my string", sanitise("my string"))
