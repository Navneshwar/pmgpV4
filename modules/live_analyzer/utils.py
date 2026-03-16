"""
live_analyzer/utils.py
Low-level I/O helpers and IP-address utilities shared across
the process and network scanner sub-modules.
No imports from other live_analyzer sub-modules allowed here
(this module sits at the base of the dependency graph).
"""

import re
from typing import Optional


# ── Safe filesystem readers ───────────────────────────────────────────────────

def safe_read(path: str, max_bytes: int = 4096) -> str:
    """Read a text file, returning '' on any OSError."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def safe_read_binary(path: str, max_bytes: int = 65536) -> bytes:
    """Read a binary file, returning b'' on any OSError."""
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return b""


# ── /proc data parsers ────────────────────────────────────────────────────────

def parse_environ(raw: bytes) -> dict[str, str]:
    """
    Parse the NUL-delimited key=value pairs from /proc/<pid>/environ.
    Returns an empty dict if raw is empty.
    """
    env: dict[str, str] = {}
    for entry in raw.split(b"\x00"):
        decoded = entry.decode("utf-8", errors="replace")
        if "=" in decoded:
            key, _, val = decoded.partition("=")
            env[key] = val
    return env


def parse_cmdline(raw: bytes) -> str:
    """
    Parse the NUL-delimited argv array from /proc/<pid>/cmdline
    into a single space-joined string.
    """
    if not raw:
        return ""
    return " ".join(
        p.decode("utf-8", errors="replace")
        for p in raw.split(b"\x00")
        if p
    )


# ── IP address utilities ──────────────────────────────────────────────────────

_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def extract_ip(value: str) -> Optional[str]:
    """Extract the first IPv4 address found in *value*, or None."""
    match = _IP_RE.search(value)
    return match.group(1) if match else None


def is_private_ip(ip: str) -> bool:
    """
    Return True for RFC-1918 / loopback / unspecified addresses,
    and for anything that cannot be parsed as IPv4 (e.g. IPv6).
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return True   # IPv6 or malformed – treat as non-alerting
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or a == 0
        )
    except ValueError:
        return True