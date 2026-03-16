"""
modules/os_profiler.py
Heuristic OS identification from filesystem metadata.
Reads filesystem artefacts, package databases, and configuration files.
Also performs shell history, cron, SSH, and recently-used file scanning.
No binaries are executed; only metadata files are read.
"""

import os
import re
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


# ── Structural indicator sets ─────────────────────────────────────────────────

KALI_METAPACKAGES = {
    "kali-linux-core", "kali-linux-default", "kali-linux-full",
    "kali-linux-everything", "kali-linux-headless", "kali-linux-nethunter",
    "kali-menu", "kali-desktop-xfce", "kali-themes",
}

BLACKARCH_GROUPS_RE = re.compile(
    r"^(blackarch|blackarch-exploitation|blackarch-recon|"
    r"blackarch-anti-forensic|blackarch-wireless|blackarch-crypto|"
    r"blackarch-scanner|blackarch-forensic)$",
    re.IGNORECASE,
)

KALI_REPO_RE    = re.compile(r"kali\.org",          re.IGNORECASE)
KALI_GPG_RE     = re.compile(r"ED444FF07D8D0BF6",   re.IGNORECASE)
TAILS_CMDLINE_MARKER = "module=Tails"

# Shell history files to scan
HISTORY_FILES = [
    "root/.bash_history",
    "root/.zsh_history",
    "root/.sh_history",
    "home/*/.bash_history",
    "home/*/.zsh_history",
]

# Offensive tool patterns to look for in shell history
OFFENSIVE_HISTORY_RE = re.compile(
    r"\b(nmap|msfconsole|msfvenom|hydra|hashcat|john|aircrack|sqlmap|"
    r"gobuster|nikto|dirb|ffuf|netcat|nc\s+-[lvp]|tcpdump|tshark|"
    r"responder|ettercap|proxychains|torsocks|setoolkit|beef|burpsuite|"
    r"crackmapexec|impacket|wifite|reaver|bettercap)\b",
    re.IGNORECASE,
)

# SSH-related paths indicating lateral movement preparation
SSH_ARTEFACT_PATHS = [
    "root/.ssh/known_hosts",
    "root/.ssh/authorized_keys",
    "root/.ssh/id_rsa",
    "root/.ssh/id_ed25519",
    "root/.ssh/config",
]

# Persistence mechanism paths
CRON_PATHS = [
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "etc/crontab",
    "var/spool/cron/crontabs",
    "var/spool/cron/root",
]

# /etc/hosts modification pattern (C2 infrastructure)
SUSPICIOUS_HOSTS_RE = re.compile(
    r"^\s*(?!127\.|0\.0\.0\.0|::1|#)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+",
    re.MULTILINE,
)


# ── Public entry-point ────────────────────────────────────────────────────────

def identify_os(root_path: str, tails_disk_confirmed: bool = False) -> OSProfile:
    """
    Walk the given root path (a mounted image or '/' for live analysis)
    and return an OSProfile without executing any binaries.

    tails_disk_confirmed: set to True when disk_analyzer has already found
    a TailsData LUKS partition – boosts Tails confidence even when the
    in-memory filesystem markers are absent (amnesic boot).
    """
    root_path = root_path.rstrip("/")

    # Priority order: Tails → Kali → BlackArch → generic Debian/Arch
    profile = _check_tails(root_path, tails_disk_confirmed)
    if profile:
        _scan_filesystem_artefacts(root_path, profile)
        return profile

    dpkg_status = _find_dpkg_status(root_path)
    if dpkg_status:
        profile = _check_kali_from_dpkg(dpkg_status, root_path)
        if not profile:
            profile = _build_debian_profile(dpkg_status)
        _scan_filesystem_artefacts(root_path, profile)
        return profile

    pacman_dir = _find_pacman_local(root_path)
    if pacman_dir:
        profile = _check_blackarch_from_pacman(pacman_dir)
        if not profile:
            profile = OSProfile(
                os_type=OSType.ARCH_LINUX,
                confidence=0.7,
                indicators=["pacman local database found"],
                pkg_db_path=pacman_dir,
                pkg_db_type="pacman",
            )
        _scan_filesystem_artefacts(root_path, profile)
        return profile
        
    # Check for Windows
    import sys
    if os.path.exists(os.path.join(root_path, "Windows", "System32")) or (sys.platform == "win32" and root_path in ("/", "\\")):
        profile = OSProfile(
            os_type=OSType.WINDOWS,
            confidence=0.9,
            indicators=["Windows System32 directory found or Windows host detected"],
        )
        _scan_filesystem_artefacts(root_path, profile)
        return profile

    profile = OSProfile(
        os_type=OSType.UNKNOWN,
        confidence=0.1,
        indicators=["no recognised package database found"],
    )
    _scan_filesystem_artefacts(root_path, profile)
    return profile


# ── Filesystem artefact scanning ──────────────────────────────────────────────

def _scan_filesystem_artefacts(root_path: str, profile: OSProfile) -> None:
    """
    Scan for shell history, SSH artefacts, cron jobs, /etc/hosts modifications,
    and recently-used file traces. Findings are added to profile.filesystem_artefacts.
    """
    _scan_shell_histories(root_path, profile)
    _scan_ssh_artefacts(root_path, profile)
    _scan_cron_artefacts(root_path, profile)
    _scan_hosts_file(root_path, profile)
    _scan_recently_used(root_path, profile)


def _scan_shell_histories(root_path: str, profile: OSProfile) -> None:
    """Scan shell history files for offensive tool usage."""
    # Build actual paths – handle home/* glob manually
    candidates: list[str] = []
    for rel in HISTORY_FILES:
        if "*" in rel:
            # e.g. home/*/.bash_history
            parts = rel.split("*")
            parent = os.path.join(root_path, parts[0].strip("/"))
            suffix = parts[1].lstrip("/")
            if os.path.isdir(parent):
                try:
                    for user_dir in os.listdir(parent):
                        candidates.append(os.path.join(parent, user_dir, suffix))
                except OSError:
                    pass
        else:
            candidates.append(os.path.join(root_path, rel))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        content = _safe_read(path, max_bytes=524288)
        if not content:
            continue

        matches = OFFENSIVE_HISTORY_RE.findall(content)
        if matches:
            unique_cmds = list(dict.fromkeys(m.lower() for m in matches))[:10]
            rel_path = path.replace(root_path, "")
            profile.filesystem_artefacts.append(FilesystemArtefact(
                path=rel_path,
                artefact_type="shell_history",
                description=(
                    f"Shell history contains {len(matches)} offensive tool invocation(s): "
                    + ", ".join(unique_cmds)
                ),
                risk_level="HIGH",
                snippet=_first_matching_line(content, OFFENSIVE_HISTORY_RE),
            ))
            profile.indicators.append(
                f"Offensive commands in {rel_path}: {', '.join(unique_cmds[:5])}"
            )
            # Boost confidence if this is already a known offensive OS
            if profile.os_type in (OSType.KALI_LINUX, OSType.BLACKARCH_LINUX, OSType.TAILS_OS):
                profile.confidence = min(profile.confidence + 0.05, 1.0)


def _scan_ssh_artefacts(root_path: str, profile: OSProfile) -> None:
    """Detect SSH keys and known_hosts (lateral movement indicators)."""
    for rel_path in SSH_ARTEFACT_PATHS:
        full = os.path.join(root_path, rel_path)
        if not os.path.isfile(full):
            continue
        content = _safe_read(full, max_bytes=32768)
        if not content.strip():
            continue

        if "known_hosts" in rel_path:
            line_count = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])
            if line_count > 0:
                profile.filesystem_artefacts.append(FilesystemArtefact(
                    path=rel_path,
                    artefact_type="ssh_key",
                    description=f"SSH known_hosts with {line_count} host(s) – lateral movement evidence",
                    risk_level="MEDIUM",
                    snippet=content.splitlines()[0][:120] if content else "",
                ))
        elif "authorized_keys" in rel_path:
            key_count = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])
            if key_count > 0:
                profile.filesystem_artefacts.append(FilesystemArtefact(
                    path=rel_path,
                    artefact_type="ssh_key",
                    description=f"SSH authorized_keys with {key_count} key(s) – backdoor access indicator",
                    risk_level="HIGH",
                    snippet="",
                ))
        elif "id_rsa" in rel_path or "id_ed25519" in rel_path:
            profile.filesystem_artefacts.append(FilesystemArtefact(
                path=rel_path,
                artefact_type="ssh_key",
                description="Private SSH key found in root home directory",
                risk_level="HIGH",
                snippet="",
            ))


def _scan_cron_artefacts(root_path: str, profile: OSProfile) -> None:
    """Detect cron jobs that may indicate persistence mechanisms."""
    for rel_path in CRON_PATHS:
        full = os.path.join(root_path, rel_path)
        if os.path.isfile(full):
            content = _safe_read(full, max_bytes=32768)
            non_comment = [l for l in content.splitlines()
                           if l.strip() and not l.startswith("#")]
            if non_comment:
                profile.filesystem_artefacts.append(FilesystemArtefact(
                    path=rel_path,
                    artefact_type="cron",
                    description=f"Cron job file with {len(non_comment)} active entry(s) – potential persistence",
                    risk_level="MEDIUM",
                    snippet=non_comment[0][:120],
                ))
        elif os.path.isdir(full):
            try:
                jobs = [f for f in os.listdir(full)
                        if not f.startswith(".") and f != "README"]
                if jobs:
                    profile.filesystem_artefacts.append(FilesystemArtefact(
                        path=rel_path,
                        artefact_type="cron",
                        description=f"Cron directory with {len(jobs)} job(s): {', '.join(jobs[:5])}",
                        risk_level="LOW",
                        snippet="",
                    ))
            except OSError:
                pass


def _scan_hosts_file(root_path: str, profile: OSProfile) -> None:
    """Detect non-standard /etc/hosts entries (C2 redirects, domain masking)."""
    hosts_path = os.path.join(root_path, "etc/hosts")
    content = _safe_read(hosts_path, max_bytes=65536)
    if not content:
        return

    custom_entries = [
        l.strip() for l in content.splitlines()
        if l.strip() and not l.startswith("#")
        and not re.match(r"^\s*(127\.|0\.0\.0\.0|::1|fe80:)", l)
    ]
    if custom_entries:
        profile.filesystem_artefacts.append(FilesystemArtefact(
            path="etc/hosts",
            artefact_type="hosts_mod",
            description=(
                f"/etc/hosts has {len(custom_entries)} custom entry(s) – "
                "possible C2 infrastructure mapping or domain hijacking"
            ),
            risk_level="MEDIUM",
            snippet=custom_entries[0][:120],
        ))


def _scan_recently_used(root_path: str, profile: OSProfile) -> None:
    """Scan recently-used file registries for evidence of tool execution."""
    recent_paths = [
        "root/.local/share/recently-used.xbel",
        "home/*/.local/share/recently-used.xbel",
    ]
    for rel in recent_paths:
        if "*" in rel:
            parts = rel.split("*")
            parent = os.path.join(root_path, parts[0].strip("/"))
            suffix = parts[1].lstrip("/")
            if os.path.isdir(parent):
                try:
                    for user_dir in os.listdir(parent):
                        _check_recently_used(
                            os.path.join(parent, user_dir, suffix),
                            rel.replace("*", user_dir),
                            profile,
                        )
                except OSError:
                    pass
        else:
            _check_recently_used(os.path.join(root_path, rel), rel, profile)


def _check_recently_used(full_path: str, rel_path: str, profile: OSProfile) -> None:
    if not os.path.isfile(full_path):
        return
    content = _safe_read(full_path, max_bytes=131072)
    matches = OFFENSIVE_HISTORY_RE.findall(content)
    if matches:
        unique = list(dict.fromkeys(m.lower() for m in matches))[:5]
        profile.filesystem_artefacts.append(FilesystemArtefact(
            path=rel_path,
            artefact_type="recent_files",
            description=f"Recently-used registry references offensive tools: {', '.join(unique)}",
            risk_level="MEDIUM",
            snippet="",
        ))


# ── Private helpers ───────────────────────────────────────────────────────────

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


# ── Tails detection ───────────────────────────────────────────────────────────

def _check_tails(root: str, disk_confirmed: bool = False) -> Optional[OSProfile]:
    indicators: list[str] = []

    # 1. /proc/cmdline (live system)
    cmdline = _safe_read(f"{root}/proc/cmdline")
    if TAILS_CMDLINE_MARKER in cmdline:
        indicators.append(f"kernel parameter '{TAILS_CMDLINE_MARKER}' found in /proc/cmdline")

    # 2. Tails-specific filesystem paths
    for p in [f"{root}/etc/amnesia", f"{root}/lib/live/config/0000default",
              f"{root}/usr/share/tails"]:
        if os.path.exists(p):
            indicators.append(f"Tails path found: {p.replace(root, '')}")

    # 3. /etc/os-release
    os_release = _safe_read(f"{root}/etc/os-release")
    if re.search(r"tails", os_release, re.IGNORECASE):
        indicators.append("'Tails' found in /etc/os-release")

    # 4. squashfs live filesystem signature (ISO/USB boot image)
    squashfs_path = f"{root}/live/filesystem.squashfs"
    if os.path.exists(squashfs_path):
        indicators.append("Tails live squashfs filesystem detected")

    # 5. Cross-signal from disk analyzer (TailsData LUKS partition)
    #    Tails is amnesic – this is often the ONLY reliable on-disk marker
    if disk_confirmed:
        indicators.append("TailsData LUKS partition confirmed by disk analyzer")

    if indicators:
        base_confidence = 0.5 + 0.15 * len(indicators)
        if disk_confirmed:
            base_confidence = max(base_confidence, 0.85)
        return OSProfile(
            os_type=OSType.TAILS_OS,
            confidence=min(base_confidence, 1.0),
            indicators=indicators,
            pkg_db_type="dpkg",
            tails_disk_confirmed=disk_confirmed,
        )
    return None


# ── Kali detection ────────────────────────────────────────────────────────────

def _check_kali_from_dpkg(dpkg_status: str, root: str) -> Optional[OSProfile]:
    indicators: list[str] = []
    content = _safe_read(dpkg_status, max_bytes=512_000)

    installed_packages = _parse_dpkg_package_names(content)
    kali_found = KALI_METAPACKAGES & installed_packages
    if kali_found:
        indicators.append(f"Kali metapackages found: {', '.join(sorted(kali_found))}")

    sources_content = ""
    for sources_path in [f"{root}/etc/apt/sources.list",
                         f"{root}/etc/apt/sources.list.d"]:
        sources_content += _safe_read(sources_path)
    if os.path.isdir(f"{root}/etc/apt/sources.list.d"):
        try:
            for fname in os.listdir(f"{root}/etc/apt/sources.list.d"):
                sources_content += _safe_read(f"{root}/etc/apt/sources.list.d/{fname}")
        except OSError:
            pass
    if KALI_REPO_RE.search(sources_content):
        indicators.append("Kali repository URL found in apt sources")

    gpg_content = (_safe_read(f"{root}/etc/apt/trusted.gpg") +
                   _safe_read(f"{root}/etc/apt/trusted.gpg.d/kali-archive-keyring.gpg"))
    if KALI_GPG_RE.search(gpg_content):
        indicators.append("Kali official GPG signing key detected")

    os_release = _safe_read(f"{root}/etc/os-release")
    if re.search(r"kali", os_release, re.IGNORECASE):
        indicators.append("'Kali' found in /etc/os-release")

    if indicators:
        return OSProfile(
            os_type=OSType.KALI_LINUX,
            confidence=min(0.4 + 0.2 * len(indicators), 1.0),
            indicators=indicators,
            pkg_db_path=dpkg_status,
            pkg_db_type="dpkg",
        )
    return None


def _build_debian_profile(dpkg_status: str) -> OSProfile:
    return OSProfile(
        os_type=OSType.DEBIAN,
        confidence=0.75,
        indicators=["dpkg status database found; no Kali markers detected"],
        pkg_db_path=dpkg_status,
        pkg_db_type="dpkg",
    )


# ── BlackArch detection ───────────────────────────────────────────────────────

def _check_blackarch_from_pacman(pacman_dir: str) -> Optional[OSProfile]:
    indicators: list[str] = []
    try:
        pkg_dirs = os.listdir(pacman_dir)
    except OSError:
        return None

    blackarch_groups: set[str] = set()
    for pkg_dir in pkg_dirs:
        desc_path = os.path.join(pacman_dir, pkg_dir, "desc")
        content = _safe_read(desc_path, max_bytes=2048)
        in_groups = False
        for line in content.splitlines():
            line = line.strip()
            if line == "%GROUPS%":
                in_groups = True
                continue
            if in_groups:
                if not line:
                    break
                if BLACKARCH_GROUPS_RE.match(line):
                    blackarch_groups.add(line)
        if len(blackarch_groups) >= 3:
            break

    if blackarch_groups:
        indicators.append(
            f"BlackArch package groups found: {', '.join(sorted(blackarch_groups))}"
        )
        return OSProfile(
            os_type=OSType.BLACKARCH_LINUX,
            confidence=min(0.5 + 0.1 * len(blackarch_groups), 1.0),
            indicators=indicators,
            pkg_db_path=pacman_dir,
            pkg_db_type="pacman",
        )
    return None


# ── Utility ───────────────────────────────────────────────────────────────────

def _parse_dpkg_package_names(dpkg_content: str) -> set[str]:
    names: set[str] = set()
    for line in dpkg_content.splitlines():
        if line.startswith("Package:"):
            pkg = line.split(":", 1)[1].strip().lower()
            names.add(pkg)
    return names
