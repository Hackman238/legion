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

applicationInfo = {
    "name": "LEGION",
    "version": "0.6.0",
    "build": '1773752754',
    "author": "Shane Scott",
    "copyright": "2026",
    "links": ["http://github.com/Hackman238/legion/issues"],
    "emails": [],
    "update": '03/17/2026',
    "license": "GPL v3",
    "desc": "Legion is a local-first, operator-guided reconnaissance and penetration testing platform with \n" +
            "governed deterministic and AI-assisted orchestration, evidence graphing, and MCP-enabled \n" +
            "automation surfaces.",
    "smallIcon": "./images/icons/Legion-N_128x128.svg",
    "bigIcon": "./images/icons/Legion-N_128x128.svg"
}


def getVersion():
    return f"{applicationInfo['version']}-{applicationInfo['build']}"


def getConsoleLogo():
    fileObj = open('./app/legionLogo.txt', 'r')
    allData = fileObj.read()
    return allData
