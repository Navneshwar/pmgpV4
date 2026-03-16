"""
modules/os_profiler/scanners.py
Filesystem artefact scanning.
"""

import os
import re
from .models import OSProfile, FilesystemArtefact, OSType
from .constants import HISTORY_FILES, OFFENSIVE_HISTORY_RE, SSH_ARTEFACT_PATHS, CRON_PATHS, SUSPICIOUS_HOSTS_RE
from .utils import _safe_read, _first_matching_line

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
