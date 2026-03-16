"""
live_analyzer package
Re-exports the public surface so callers can do:
    from modules.live_analyzer import analyze_live_system, LiveAnalysisResult
    from modules.live_analyzer import NetworkConnection, ProcessFinding
"""

import os

from .models import NetworkConnection, ProcessFinding, LiveAnalysisResult
from .process_scanner import scan_all_processes
from .network_scanner import read_connections, collect_offensive_comms, filter_suspicious


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

    result.process_findings, result.total_processes_scanned = scan_all_processes(proc_path)

    all_conns                     = read_connections(proc_path)
    result.network_connections    = all_conns

    offensive_comms               = collect_offensive_comms(proc_path)
    result.suspicious_connections = filter_suspicious(all_conns, offensive_comms)

    return result


__all__ = [
    "analyze_live_system",
    "NetworkConnection",
    "ProcessFinding",
    "LiveAnalysisResult",
    "scan_all_processes",
    "read_connections",
    "collect_offensive_comms",
    "filter_suspicious",
]