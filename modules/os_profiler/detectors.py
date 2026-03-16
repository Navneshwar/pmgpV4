"""
modules/os_profiler/detectors.py
OS Specific Detection Logic.
"""

import os
import re
from typing import Optional
from .models import OSProfile, OSType
from .constants import KALI_METAPACKAGES, KALI_REPO_RE, KALI_GPG_RE, TAILS_CMDLINE_MARKER, BLACKARCH_GROUPS_RE
from .utils import _safe_read, _parse_dpkg_package_names


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
