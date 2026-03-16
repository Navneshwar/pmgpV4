"""
modules/os_profiler/core.py
Main entry-point for heuristic OS identification.
"""

import os
from .models import OSProfile, OSType
from .detectors import _check_tails, _check_kali_from_dpkg, _build_debian_profile, _check_blackarch_from_pacman
from .utils import _find_dpkg_status, _find_pacman_local
from .scanners import _scan_filesystem_artefacts

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
