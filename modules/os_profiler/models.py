"""
modules/os_profiler/models.py
Data structures for OS profiling.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OSType(str, Enum):
    KALI_LINUX     = "Kali Linux"
    BLACKARCH_LINUX= "BlackArch Linux"
    TAILS_OS       = "Tails OS"
    DEBIAN         = "Debian/Ubuntu"
    ARCH_LINUX     = "Arch Linux"
    WINDOWS        = "Windows"
    UNKNOWN        = "Unknown Linux"


@dataclass
class FilesystemArtefact:
    path: str
    artefact_type: str   # "shell_history" | "ssh_key" | "cron" | "recent_files" | "hosts_mod"
    description: str
    risk_level: str      # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    snippet: str = ""    # first relevant line / excerpt (truncated)


@dataclass
class OSProfile:
    os_type:    OSType
    confidence: float                            # 0.0 – 1.0
    indicators: list[str]                        = field(default_factory=list)
    pkg_db_path: Optional[str]                   = None
    pkg_db_type: str                             = "unknown"   # "dpkg" | "pacman"
    raw_notes:  list[str]                        = field(default_factory=list)
    filesystem_artefacts: list[FilesystemArtefact] = field(default_factory=list)
    # Tails confidence boost from disk analyzer cross-signal
    tails_disk_confirmed: bool                   = False
