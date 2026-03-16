"""
live_analyzer/network_scanner.py
Read and classify active network connections from /proc/net/{tcp,tcp6,udp,udp6}.

Public API
----------
read_connections(proc_path)         -> list[NetworkConnection]
filter_suspicious(connections, ...) -> list[NetworkConnection]
collect_offensive_comms(proc_path)  -> set[str]
"""

import os
import socket
from typing import Optional

from .models import NetworkConnection
from .signatures import TCP_STATES, SUSPICIOUS_PORTS, OFFENSIVE_COMM_NAMES
from .utils import safe_read, is_private_ip


# ── Public functions ──────────────────────────────────────────────────────────

def read_connections(proc_path: str) -> list[NetworkConnection]:
    """
    Parse /proc/net/{tcp,tcp6,udp,udp6} and return all connections.
    Silently skips files that are absent or unreadable.
    """
    connections: list[NetworkConnection] = []
    proto_files = [
        ("tcp",  "net/tcp"),
        ("tcp6", "net/tcp6"),
        ("udp",  "net/udp"),
        ("udp6", "net/udp6"),
    ]
    for proto, filename in proto_files:
        filepath = os.path.join(proc_path, filename)
        content  = safe_read(filepath, max_bytes=524288)
        for line in content.splitlines()[1:]:   # skip header row
            conn = _parse_net_line(line, proto)
            if conn:
                connections.append(conn)
    return connections


def collect_offensive_comms(proc_path: str) -> set[str]:
    """
    Walk /proc and return the set of OFFENSIVE_COMM_NAMES currently running.
    Used for cross-referencing with outbound connections.
    """
    found: set[str] = set()
    for entry in os.listdir(proc_path):
        if not entry.isdigit():
            continue
        comm_path = os.path.join(proc_path, entry, "comm")
        try:
            with open(comm_path, "r", errors="replace") as fh:
                comm = fh.read(64).strip().lower()
        except OSError:
            continue
        if comm in OFFENSIVE_COMM_NAMES:
            found.add(comm)
    return found


def filter_suspicious(
    connections: list[NetworkConnection],
    offensive_comms: set[str],
) -> list[NetworkConnection]:
    """Return only connections that meet the suspicion threshold."""
    return [c for c in connections if _is_suspicious(c, offensive_comms)]


# ── Line parser ───────────────────────────────────────────────────────────────

def _parse_net_line(line: str, proto: str) -> Optional[NetworkConnection]:
    parts = line.split()
    if len(parts) < 4:
        return None
    try:
        local_addr,  local_port  = _decode_addr(parts[1])
        remote_addr, remote_port = _decode_addr(parts[2])
        state = TCP_STATES.get(parts[3].upper(), parts[3])
        return NetworkConnection(
            local_addr=local_addr,   local_port=local_port,
            remote_addr=remote_addr, remote_port=remote_port,
            state=state,             protocol=proto,
        )
    except Exception:
        return None


def _decode_addr(hex_addr: str) -> tuple[str, int]:
    """
    Decode a hex 'ADDR:PORT' field from /proc/net/tcp*.
    IPv4 addresses are 8 hex chars, little-endian.
    IPv6 addresses are 32 hex chars, each 4-byte group little-endian.
    """
    addr_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)

    if len(addr_hex) == 8:
        # IPv4 – little-endian 4 bytes
        packed = bytes.fromhex(addr_hex)
        ip = socket.inet_ntoa(packed[::-1])
    else:
        # IPv6 – 16 bytes, each 4-byte word is little-endian
        raw = bytes.fromhex(addr_hex)
        reordered = b"".join(raw[i:i+4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, reordered)

    return ip, port


# ── Suspicion classifier ──────────────────────────────────────────────────────

def _is_suspicious(conn: NetworkConnection, offensive_comms: set[str]) -> bool:
    """
    A connection is suspicious when it is established (or initiating) to a
    non-private external IP **and** at least one of:
      • the remote or local port is a known C2/reverse-shell port
      • an offensive tool process is making outbound connections
    """
    if conn.state not in ("ESTABLISHED", "SYN_SENT"):
        return False
    if is_private_ip(conn.remote_addr) or conn.remote_addr in (
        "0.0.0.0", "::", "::1", "127.0.0.1"
    ):
        return False
    if conn.remote_port in SUSPICIOUS_PORTS:
        return True
    if conn.local_port in SUSPICIOUS_PORTS:
        return True
    if offensive_comms:     # any offensive tool running → flag all external conns
        return True
    return False