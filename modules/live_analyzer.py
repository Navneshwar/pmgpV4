"""
modules/live_analyzer.py
Volatile artifact extraction from /proc on a live Linux system.
Inspects process cmdlines, environment variables, memory maps,
active network connections, and suspicious indicators without
executing any processes.
"""

import os
import re
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Suspicious env-var patterns ───────────────────────────────────────────────

SUSPICIOUS_ENV_VARS = {
    "LD_PRELOAD":             "Shared library injection – may hijack execution flow",
    "LD_LIBRARY_PATH":        "Custom library path – may redirect to malicious libraries",
    "LD_AUDIT":               "Library audit hook – used for stealthy function interception",
    "LD_DEBUG":               "Dynamic linker debug output – may indicate reconnaissance",
    "DYLD_INSERT_LIBRARIES":  "macOS library injection equivalent (unusual on Linux)",
    "PYTHONPATH":             "Python module path override",
    "RUBYLIB":                "Ruby library path override",
    "PERL5LIB":               "Perl library path override",
}

ATTACKER_IP_VARS = {
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "REMOTE_ADDR",
    "HTTP_X_FORWARDED_FOR",
}

# Suspicious binary paths often used by attackers
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"/tmp/",     re.IGNORECASE),
    re.compile(r"/dev/shm/", re.IGNORECASE),
    re.compile(r"/var/tmp/", re.IGNORECASE),
    re.compile(r"\.\./",     re.IGNORECASE),
]

# Process names / cmdline fragments strongly associated with offensive tools
SUSPICIOUS_CMDLINE_PATTERNS = [
    (re.compile(r"\bnmap\b",            re.IGNORECASE), "T1046",     "Discovery",           "nmap detected in process cmdline"),
    (re.compile(r"\bmsfconsole\b",      re.IGNORECASE), "T1210",     "Exploitation",        "Metasploit console running"),
    (re.compile(r"\bmsfvenom\b",        re.IGNORECASE), "T1587.001", "Resource Development","msfvenom payload generator running"),
    (re.compile(r"\bhydra\b",           re.IGNORECASE), "T1110.001", "Credential Access",   "Hydra brute-forcer running"),
    (re.compile(r"\bhashcat\b",         re.IGNORECASE), "T1110.002", "Credential Access",   "Hashcat password cracker running"),
    (re.compile(r"\bjohn\b",            re.IGNORECASE), "T1110.002", "Credential Access",   "John the Ripper running"),
    (re.compile(r"\baircrack",          re.IGNORECASE), "T1110",     "Credential Access",   "Aircrack-ng wireless cracker running"),
    (re.compile(r"\btcpdump\b",         re.IGNORECASE), "T1040",     "Collection",          "tcpdump packet capture running"),
    (re.compile(r"\bwireshark\b",       re.IGNORECASE), "T1040",     "Collection",          "Wireshark packet capture running"),
    (re.compile(r"\bnetcat\b|\bnc\b",   re.IGNORECASE), "T1059",     "Execution",           "Netcat running"),
    (re.compile(r"\bsqlmap\b",          re.IGNORECASE), "T1190",     "Exploitation",        "SQLmap injection tool running"),
    (re.compile(r"\btorsocks\b|\btor\b",re.IGNORECASE), "T1090.003", "Command and Control", "Tor anonymizer running"),
    (re.compile(r"\bproxychains",       re.IGNORECASE), "T1090",     "Command and Control", "Proxychains proxy chainer running"),
    (re.compile(r"\bburpsuite\b",       re.IGNORECASE), "T1190",     "Exploitation",        "Burp Suite proxy running"),
    (re.compile(r"\bgobuster\b",        re.IGNORECASE), "T1595.003", "Reconnaissance",      "Gobuster directory scanner running"),
    (re.compile(r"\bnikto\b",           re.IGNORECASE), "T1595",     "Reconnaissance",      "Nikto web scanner running"),
    (re.compile(r"\bresponder\b",       re.IGNORECASE), "T1557.001", "Collection",          "Responder LLMNR poisoner running"),
    (re.compile(r"\bettercap\b",        re.IGNORECASE), "T1557",     "Collection",          "Ettercap MitM tool running"),
    (re.compile(r"\bimpacket\b",        re.IGNORECASE), "T1550",     "Lateral Movement",    "Impacket toolkit running"),
]

# Memory-mapped paths that are suspicious
SUSPICIOUS_MAP_PATTERNS = [
    re.compile(r"/tmp/",     re.IGNORECASE),
    re.compile(r"/dev/shm/", re.IGNORECASE),
    re.compile(r"\.so\b.*deleted", re.IGNORECASE),  # deleted shared libs – common rootkit trick
]

# Known offensive tool binary names for connection cross-referencing
OFFENSIVE_COMM_NAMES = {
    "nmap", "msfconsole", "msfvenom", "hydra", "hashcat", "john", "aircrack-ng",
    "tcpdump", "tshark", "nc", "netcat", "ncat", "sqlmap", "tor", "proxychains",
    "proxychains4", "gobuster", "nikto", "dirb", "ffuf", "responder", "ettercap",
    "wifite", "reaver", "bettercap", "crackmapexec", "impacket",
}


@dataclass
class NetworkConnection:
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    protocol: str  # "tcp" | "udp"


@dataclass
class ProcessFinding:
    pid: int
    comm: str                # process name from /proc/<pid>/comm
    cmdline: str = ""        # full command line
    suspicious_vars:   dict[str, str]  = field(default_factory=dict)
    attacker_ips:      dict[str, str]  = field(default_factory=dict)
    suspicious_paths:  list[str]       = field(default_factory=list)
    suspicious_maps:   list[str]       = field(default_factory=list)
    cmdline_matches:   list[tuple[str, str, str]] = field(default_factory=list)  # (note, technique, category)
    notes:             list[str]       = field(default_factory=list)


@dataclass
class LiveAnalysisResult:
    is_live_system: bool
    process_findings:       list[ProcessFinding]    = field(default_factory=list)
    network_connections:    list[NetworkConnection] = field(default_factory=list)
    suspicious_connections: list[NetworkConnection] = field(default_factory=list)
    total_processes_scanned: int = 0
    error_message: Optional[str] = None

    @property
    def has_findings(self) -> bool:
        return bool(self.process_findings or self.suspicious_connections)


# ── Public entry-point ────────────────────────────────────────────────────────

def analyze_live_system(proc_path: str = "/proc") -> LiveAnalysisResult:
    """
    Scan /proc for volatile forensic artifacts.
    Safe to run on a live system – read-only /proc access only.
    """
    if not os.path.isdir(proc_path):
        return LiveAnalysisResult(is_live_system=False)

    if not os.path.exists(os.path.join(proc_path, "version")):
        return LiveAnalysisResult(
            is_live_system=False,
            error_message="Directory exists but does not appear to be /proc",
        )

    result = LiveAnalysisResult(is_live_system=True)

    # ── Per-process scan ──────────────────────────────────────────────────
    for entry in os.listdir(proc_path):
        if not entry.isdigit():
            continue
        try:
            pid = int(entry)
        except ValueError:
            continue

        pid_dir = os.path.join(proc_path, entry)
        finding = _analyze_pid(pid, pid_dir)
        result.total_processes_scanned += 1

        if finding and (
            finding.suspicious_vars
            or finding.attacker_ips
            or finding.suspicious_paths
            or finding.suspicious_maps
            or finding.cmdline_matches
            or finding.notes
        ):
            result.process_findings.append(finding)

    # ── Network connection scan ───────────────────────────────────────────
    all_conns = _read_network_connections(proc_path)
    result.network_connections = all_conns

    # Collect process comm names for cross-referencing
    running_offensive = _running_offensive_comms(proc_path)

    for conn in all_conns:
        if _is_suspicious_connection(conn, running_offensive):
            result.suspicious_connections.append(conn)

    return result


# ── Per-process analysis ──────────────────────────────────────────────────────

def _analyze_pid(pid: int, pid_dir: str) -> Optional[ProcessFinding]:
    comm = _safe_read(os.path.join(pid_dir, "comm")).strip() or f"pid-{pid}"
    environ_raw = _safe_read_binary(os.path.join(pid_dir, "environ"))
    cmdline_raw = _safe_read_binary(os.path.join(pid_dir, "cmdline"))

    # Need at least something to work with
    if not environ_raw and not cmdline_raw:
        return None

    env_vars = _parse_environ(environ_raw) if environ_raw else {}
    cmdline  = _parse_cmdline(cmdline_raw)

    finding = ProcessFinding(pid=pid, comm=comm, cmdline=cmdline)

    # ── LD_PRELOAD / library injection checks ─────────────────────────────
    for var, description in SUSPICIOUS_ENV_VARS.items():
        if var in env_vars:
            finding.suspicious_vars[var] = env_vars[var]
            finding.notes.append(f"{var} set – {description}")

    # ── Attacker IP extraction ────────────────────────────────────────────
    for var in ATTACKER_IP_VARS:
        if var in env_vars:
            val = env_vars[var]
            ip = _extract_ip(val)
            if ip and not _is_private_ip(ip):
                finding.attacker_ips[var] = val
                finding.notes.append(
                    f"Non-private IP in {var}: {ip} – potential attacker origin"
                )

    # ── Suspicious PATH entries ───────────────────────────────────────────
    path_val = env_vars.get("PATH", "")
    for component in path_val.split(":"):
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern.search(component):
                finding.suspicious_paths.append(component)
                finding.notes.append(f"Suspicious directory in PATH: {component}")
                break

    # ── Cmdline pattern matching ──────────────────────────────────────────
    if cmdline:
        for pattern, technique, category, note in SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern.search(cmdline):
                finding.cmdline_matches.append((note, technique, category))
                finding.notes.append(f"[{technique}] {note} — cmdline: {cmdline[:120]}")

    # ── Memory map scanning (/proc/<pid>/maps) ────────────────────────────
    maps_content = _safe_read(os.path.join(pid_dir, "maps"), max_bytes=131072)
    for line in maps_content.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            path_field = parts[-1]
            for pat in SUSPICIOUS_MAP_PATTERNS:
                if pat.search(path_field):
                    if path_field not in finding.suspicious_maps:
                        finding.suspicious_maps.append(path_field)
                        finding.notes.append(
                            f"Suspicious mapped file: {path_field}"
                        )
                    break

    has_anything = (
        finding.suspicious_vars
        or finding.attacker_ips
        or finding.suspicious_paths
        or finding.suspicious_maps
        or finding.cmdline_matches
        or finding.notes
    )
    return finding if has_anything else None


# ── Network connection scanning ───────────────────────────────────────────────

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

# Ports commonly used by C2 frameworks / offensive tools
SUSPICIOUS_PORTS = {
    4444, 4445, 4446,   # default Metasploit reverse shells
    1234, 5555, 6666, 7777, 8888, 9999,  # common reverse shell ports
    31337,              # classic "elite" port
    12345, 54321,
}


def _read_network_connections(proc_path: str) -> list[NetworkConnection]:
    connections: list[NetworkConnection] = []
    for proto, filename in [("tcp", "net/tcp"), ("tcp6", "net/tcp6"),
                             ("udp", "net/udp"), ("udp6", "net/udp6")]:
        filepath = os.path.join(proc_path, filename)
        content = _safe_read(filepath, max_bytes=524288)
        for line in content.splitlines()[1:]:  # skip header
            conn = _parse_net_line(line, proto)
            if conn:
                connections.append(conn)
    return connections


def _parse_net_line(line: str, proto: str) -> Optional[NetworkConnection]:
    parts = line.split()
    if len(parts) < 4:
        return None
    try:
        local_hex  = parts[1]
        remote_hex = parts[2]
        state_hex  = parts[3]
        local_addr,  local_port  = _decode_addr(local_hex)
        remote_addr, remote_port = _decode_addr(remote_hex)
        state = _TCP_STATES.get(state_hex.upper(), state_hex)
        return NetworkConnection(
            local_addr=local_addr, local_port=local_port,
            remote_addr=remote_addr, remote_port=remote_port,
            state=state, protocol=proto,
        )
    except Exception:
        return None


def _decode_addr(hex_addr: str) -> tuple[str, int]:
    addr_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    # IPv4: 8 hex chars, little-endian
    if len(addr_hex) == 8:
        packed = bytes.fromhex(addr_hex)
        # little-endian byte order
        ip = socket.inet_ntoa(packed[::-1])
    else:
        # IPv6: 32 hex chars
        raw = bytes.fromhex(addr_hex)
        # Each 4-byte group is little-endian
        reordered = b"".join(raw[i:i+4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, reordered)
    return ip, port


def _running_offensive_comms(proc_path: str) -> set[str]:
    found: set[str] = set()
    for entry in os.listdir(proc_path):
        if not entry.isdigit():
            continue
        comm = _safe_read(os.path.join(proc_path, entry, "comm")).strip().lower()
        if comm in OFFENSIVE_COMM_NAMES:
            found.add(comm)
    return found


def _is_suspicious_connection(conn: NetworkConnection, offensive_comms: set[str]) -> bool:
    # Only care about established connections to non-private external IPs
    if conn.state not in ("ESTABLISHED", "SYN_SENT"):
        return False
    if _is_private_ip(conn.remote_addr) or conn.remote_addr in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return False
    # Suspicious port OR offensive process is making outbound connections
    if conn.remote_port in SUSPICIOUS_PORTS:
        return True
    if conn.local_port in SUSPICIOUS_PORTS:
        return True
    if offensive_comms:  # any offensive tool has external connections
        return True
    return False


# ── Parsers / utilities ───────────────────────────────────────────────────────

def _parse_environ(raw: bytes) -> dict[str, str]:
    env: dict[str, str] = {}
    for entry in raw.split(b"\x00"):
        decoded = entry.decode("utf-8", errors="replace")
        if "=" in decoded:
            key, _, val = decoded.partition("=")
            env[key] = val
    return env


def _parse_cmdline(raw: bytes) -> str:
    """Parse null-delimited /proc/<pid>/cmdline into a readable string."""
    if not raw:
        return ""
    return " ".join(
        p.decode("utf-8", errors="replace")
        for p in raw.split(b"\x00")
        if p
    )


def _extract_ip(value: str) -> Optional[str]:
    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", value)
    return match.group(1) if match else None


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # IPv6 or parse fail – treat as non-alerting
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


def _safe_read(path: str, max_bytes: int = 4096) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def _safe_read_binary(path: str, max_bytes: int = 65536) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return b""
