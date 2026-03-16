"""
live_analyzer/process_scanner.py
Per-process volatile artifact extraction.

Reads /proc/<pid>/{comm,cmdline,environ,maps} and flags:
  - Suspicious environment variables (LD_PRELOAD, etc.)
  - Non-private IPs in SSH_CONNECTION / REMOTE_ADDR
  - Suspicious directories in the process PATH
  - Offensive tool names / patterns in the cmdline
  - Suspicious memory-mapped paths (deleted .so files, /tmp, /dev/shm)
"""

import os
from typing import Optional

from .models import ProcessFinding
from .signatures import (
    SUSPICIOUS_ENV_VARS,
    ATTACKER_IP_VARS,
    SUSPICIOUS_PATH_PATTERNS,
    SUSPICIOUS_CMDLINE_PATTERNS,
    SUSPICIOUS_MAP_PATTERNS,
)
from .utils import (
    safe_read,
    safe_read_binary,
    parse_environ,
    parse_cmdline,
    extract_ip,
    is_private_ip,
)


def scan_all_processes(proc_path: str) -> tuple[list[ProcessFinding], int]:
    """
    Iterate over every numeric entry in *proc_path* and analyse each PID.

    Returns:
        (findings, total_scanned)
        where *findings* contains only PIDs with at least one suspicious signal.
    """
    findings: list[ProcessFinding] = []
    total = 0

    for entry in os.listdir(proc_path):
        if not entry.isdigit():
            continue
        try:
            pid = int(entry)
        except ValueError:
            continue

        total += 1
        pid_dir = os.path.join(proc_path, entry)
        finding = _analyze_pid(pid, pid_dir)

        if finding and _has_signals(finding):
            findings.append(finding)

    return findings, total


# ── Internal helpers ──────────────────────────────────────────────────────────

def _analyze_pid(pid: int, pid_dir: str) -> Optional[ProcessFinding]:
    """
    Inspect a single PID directory and return a ProcessFinding
    (or None when there is nothing to work with).
    """
    comm        = safe_read(os.path.join(pid_dir, "comm")).strip() or f"pid-{pid}"
    environ_raw = safe_read_binary(os.path.join(pid_dir, "environ"))
    cmdline_raw = safe_read_binary(os.path.join(pid_dir, "cmdline"))

    if not environ_raw and not cmdline_raw:
        return None

    env_vars = parse_environ(environ_raw) if environ_raw else {}
    cmdline  = parse_cmdline(cmdline_raw)
    finding  = ProcessFinding(pid=pid, comm=comm, cmdline=cmdline)

    _check_env_vars(finding, env_vars)
    _check_attacker_ips(finding, env_vars)
    _check_path_components(finding, env_vars)
    _check_cmdline(finding, cmdline)
    _check_memory_maps(finding, pid_dir)

    return finding


def _check_env_vars(finding: ProcessFinding, env_vars: dict[str, str]) -> None:
    """Flag dangerous LD_PRELOAD / library-path variables."""
    for var, description in SUSPICIOUS_ENV_VARS.items():
        if var in env_vars:
            finding.suspicious_vars[var] = env_vars[var]
            finding.notes.append(f"{var} set – {description}")


def _check_attacker_ips(finding: ProcessFinding, env_vars: dict[str, str]) -> None:
    """Extract non-private IPs from SSH_CONNECTION, REMOTE_ADDR, etc."""
    for var in ATTACKER_IP_VARS:
        if var in env_vars:
            val = env_vars[var]
            ip  = extract_ip(val)
            if ip and not is_private_ip(ip):
                finding.attacker_ips[var] = val
                finding.notes.append(
                    f"Non-private IP in {var}: {ip} – potential attacker origin"
                )


def _check_path_components(finding: ProcessFinding, env_vars: dict[str, str]) -> None:
    """Warn when the process PATH contains writable/attacker-controlled dirs."""
    path_val = env_vars.get("PATH", "")
    for component in path_val.split(":"):
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern.search(component):
                finding.suspicious_paths.append(component)
                finding.notes.append(f"Suspicious directory in PATH: {component}")
                break


def _check_cmdline(finding: ProcessFinding, cmdline: str) -> None:
    """Match cmdline against known offensive-tool patterns."""
    if not cmdline:
        return
    for pattern, technique, category, note in SUSPICIOUS_CMDLINE_PATTERNS:
        if pattern.search(cmdline):
            finding.cmdline_matches.append((note, technique, category))
            finding.notes.append(
                f"[{technique}] {note} — cmdline: {cmdline[:120]}"
            )


def _check_memory_maps(finding: ProcessFinding, pid_dir: str) -> None:
    """Scan /proc/<pid>/maps for suspicious mapped-file paths."""
    maps_content = safe_read(os.path.join(pid_dir, "maps"), max_bytes=131072)
    for line in maps_content.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path_field = parts[-1]
        for pat in SUSPICIOUS_MAP_PATTERNS:
            if pat.search(path_field):
                if path_field not in finding.suspicious_maps:
                    finding.suspicious_maps.append(path_field)
                    finding.notes.append(f"Suspicious mapped file: {path_field}")
                break


def _has_signals(finding: ProcessFinding) -> bool:
    return bool(
        finding.suspicious_vars
        or finding.attacker_ips
        or finding.suspicious_paths
        or finding.suspicious_maps
        or finding.cmdline_matches
        or finding.notes
    )