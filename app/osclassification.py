#!/usr/bin/env python
"""
Utilities for normalizing operating system detection strings and providing
centralized icon mappings across the Legion UI.
"""

from __future__ import annotations

from typing import Dict

DEFAULT_CATEGORY = "Unknown"

# Ordered list makes it easy to control display precedence across the UI.
ORDERED_OS_CATEGORIES = [
    "Windows",
    "Linux",
    "Darwin",
    "FreeBSD",
    "OpenBSD",
    "NetBSD",
    "Solaris",
    "AIX",
    "HP-UX",
    "VMware",
    "Cisco IOS",
    "Android",
    "iOS",
    "Unix",
    DEFAULT_CATEGORY,
]

# Icon mapping is centralized here so new operating systems can be added quickly.
OS_ICON_MAP: Dict[str, str] = {
    "Windows": "./images/windows-icon.png",
    "Linux": "./images/linux-icon.png",
    "Darwin": "./images/question-icon.png",
    "FreeBSD": "./images/question-icon.png",
    "OpenBSD": "./images/question-icon.png",
    "NetBSD": "./images/question-icon.png",
    "Solaris": "./images/solaris-icon.png",
    "AIX": "./images/question-icon.png",
    "HP-UX": "./images/hp-icon.png",
    "VMware": "./images/vmware-big.jpg",
    "Cisco IOS": "./images/cisco-icon.png",
    "Android": "./images/question-icon.png",
    "iOS": "./images/question-icon.png",
    "Unix": "./images/question-icon.png",
    DEFAULT_CATEGORY: "./images/question-icon.png",
}


def _contains(token: str, substrings) -> bool:
    token = token.lower()
    return any(sub in token for sub in substrings)


def classify_os(os_match: str) -> str:
    """Return a normalized OS category label for the provided detection string."""
    if not os_match:
        return DEFAULT_CATEGORY

    token = os_match.lower()
    if _contains(token, ["windows", "microsoft"]):
        return "Windows"
    if _contains(token, ["freebsd"]):
        return "FreeBSD"
    if _contains(token, ["openbsd"]):
        return "OpenBSD"
    if _contains(token, ["netbsd"]):
        return "NetBSD"
    if _contains(token, ["linux"]):
        return "Linux"
    if _contains(token, ["darwin", "mac os", "osx", "macos"]):
        return "Darwin"
    if _contains(token, ["solaris", "sunos"]):
        return "Solaris"
    if _contains(token, ["hp-ux", "hpux"]):
        return "HP-UX"
    if _contains(token, ["aix"]):
        return "AIX"
    if _contains(token, ["vmware", "esxi"]):
        return "VMware"
    if _contains(token, ["cisco ios", "ios firewall", "ios software", "cisco "]):
        return "Cisco IOS"
    if _contains(token, ["android"]):
        return "Android"
    if _contains(token, ["iphone os", "ipad os", "ios"]):
        return "iOS"
    if _contains(token, ["vxworks"]):
        return "Unix"
    if _contains(token, ["unix"]):
        return "Unix"
    return DEFAULT_CATEGORY


def get_icon_path(os_category: str) -> str:
    """Return the icon path associated with a normalized OS category."""
    return OS_ICON_MAP.get(os_category, OS_ICON_MAP[DEFAULT_CATEGORY])
