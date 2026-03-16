"""
modules/os_profiler/utils.py
Private helpers for file reading and package database parsing.
"""

import os
import re
from typing import Optional

def _safe_read(path: str, max_bytes: int = 4096) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""

def _first_matching_line(content: str, pattern: re.Pattern) -> str:
    for line in content.splitlines():
        if pattern.search(line):
            return line.strip()[:120]
    return ""

def _find_dpkg_status(root: str) -> Optional[str]:
    for c in [f"{root}/var/lib/dpkg/status", f"{root}/var/lib/dpkg/status.d"]:
        if os.path.exists(c):
            return c
    return None

def _find_pacman_local(root: str) -> Optional[str]:
    path = f"{root}/var/lib/pacman/local"
    return path if os.path.isdir(path) else None

def _parse_dpkg_package_names(dpkg_content: str) -> set[str]:
    names: set[str] = set()
    for line in dpkg_content.splitlines():
        if line.startswith("Package:"):
            pkg = line.split(":", 1)[1].strip().lower()
            names.add(pkg)
    return names
