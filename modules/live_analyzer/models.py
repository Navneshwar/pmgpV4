"""
live_analyzer/models.py
Data containers for live /proc analysis results.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetworkConnection:
    local_addr:  str
    local_port:  int
    remote_addr: str
    remote_port: int
    state:       str
    protocol:    str   # "tcp" | "tcp6" | "udp" | "udp6"


@dataclass
class ProcessFinding:
    pid:    int
    comm:   str        # process name from /proc/<pid>/comm
    cmdline: str = ""  # full command line

    suspicious_vars:  dict[str, str]            = field(default_factory=dict)
    attacker_ips:     dict[str, str]            = field(default_factory=dict)
    suspicious_paths: list[str]                 = field(default_factory=list)
    suspicious_maps:  list[str]                 = field(default_factory=list)
    cmdline_matches:  list[tuple[str, str, str]] = field(default_factory=list)  # (note, technique, category)
    notes:            list[str]                 = field(default_factory=list)


@dataclass
class LiveAnalysisResult:
    is_live_system: bool

    process_findings:        list[ProcessFinding]    = field(default_factory=list)
    network_connections:     list[NetworkConnection] = field(default_factory=list)
    suspicious_connections:  list[NetworkConnection] = field(default_factory=list)
    total_processes_scanned: int                     = 0
    error_message:           Optional[str]           = None

    @property
    def has_findings(self) -> bool:
        return bool(self.process_findings or self.suspicious_connections)