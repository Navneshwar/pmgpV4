"""
modules/tool_detector.py
Cross-references installed packages AND filesystem paths against the PMGP
tool signature dictionary.
Supports both dpkg (Debian/Kali) and pacman (Arch/BlackArch) backends.
Also performs a direct binary/path scan so tools installed outside the
package manager (git clones, manual drops, USB payloads) are caught.
No binaries are executed; only metadata files are read.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from modules.live_analyzer import LiveAnalysisResult
from modules.os_profiler import OSProfile, OSType

# Path to the bundled signature dictionary
_DATA_DIR = Path(__file__).parent.parent / "data"
_SIGNATURES_PATH = _DATA_DIR / "tool_signatures.json"
_PATH_STATS_FILE = ".pmgp_path_stats.tsv"

_DPKG_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(install|upgrade)\s+([A-Za-z0-9.+_-]+)(?::\S+)?\s+"
)
_PACMAN_LOG_RE = re.compile(
    r"^\[(.+?)\]\s+\[ALPM\]\s+(installed|upgraded)\s+([A-Za-z0-9.+_-]+)\s+\("
)
_GENERIC_OSES = {
    OSType.DEBIAN,
    OSType.ARCH_LINUX,
    OSType.UNKNOWN,
    OSType.WINDOWS,
}
_ARTEFACT_EVIDENCE = {
    "shell_history": "shell_history",
    "recent_files": "recent_files",
}


@dataclass
class DetectedTool:
    name: str
    risk_level: str           # "high_risk" | "dual_use" | "anonymization"
    matched_package: str      # package name OR filesystem path
    description: str
    mitre_technique: str
    category: str
    detection_method: str = "package_db"  # "package_db" | "filesystem" | "config"
    mtime: Optional[float] = None
    atime: Optional[float] = None
    binary_paths: list[str] = field(default_factory=list)
    config_paths: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    install_time_source: str = ""
    last_used_source: str = ""
    corroborated: bool = False


@dataclass
class ToolDetectionResult:
    detected_tools: list[DetectedTool] = field(default_factory=list)
    total_packages_scanned: int = 0
    raw_package_list: list[str] = field(default_factory=list)
    filesystem_hits: list[str] = field(default_factory=list)  # real paths found
    config_hits: list[str] = field(default_factory=list)      # real config traces

    @property
    def by_risk(self) -> dict[str, list[DetectedTool]]:
        result: dict[str, list[DetectedTool]] = {
            "high_risk": [], "dual_use": [], "anonymization": [],
        }
        for tool in self.detected_tools:
            result.setdefault(tool.risk_level, []).append(tool)
        return result

    @property
    def risk_counts(self) -> dict[str, int]:
        counts = {"high_risk": 0, "dual_use": 0, "anonymization": 0}
        for tool in self.detected_tools:
            counts[tool.risk_level] = counts.get(tool.risk_level, 0) + 1
        return counts


def detect_tools(
    root_path: str,
    pkg_db_type: str,
    pkg_db_path: Optional[str] = None,
    signatures_path: Optional[str] = None,
) -> ToolDetectionResult:
    """
    Detect offensive / suspicious tools installed on a system image.

    Three passes are run:
      1. Package database cross-reference (dpkg / pacman)
      2. Direct filesystem binary path scan (catches non-packaged installs)
      3. Configuration file trace scan (e.g. torrc, proxychains.conf)
    """
    sigs = _load_signatures(signatures_path or str(_SIGNATURES_PATH))
    root_path = _normalise_root(root_path)
    path_stats = _load_path_stats(root_path)

    if pkg_db_type == "dpkg":
        installed, install_sources = _read_dpkg_packages(root_path, pkg_db_path)
    elif pkg_db_type == "pacman":
        installed, install_sources = _read_pacman_packages(root_path, pkg_db_path)
    else:
        installed, install_sources = {}, {}

    result = ToolDetectionResult(
        total_packages_scanned=len(installed),
        raw_package_list=sorted(installed),
    )
    detected_by_name: dict[str, DetectedTool] = {}

    # Pass 1: package DB matches
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            for pkg_variant in meta.get("packages", []):
                pkg_key = pkg_variant.lower()
                if pkg_key not in installed:
                    continue

                binary_hits, latest_atime = _find_binary_hits(
                    root_path, path_stats, meta.get("binary_paths", []), result
                )
                config_hits, config_mtime = _find_config_hits(
                    root_path, path_stats, meta.get("config_traces", []), result
                )

                install_time = installed.get(pkg_key)
                install_source = install_sources.get(pkg_key, "")
                if (not install_time) and config_mtime:
                    install_time = config_mtime
                    install_source = "config_mtime"

                tool = DetectedTool(
                    name=tool_name,
                    risk_level=risk_level,
                    matched_package=pkg_variant,
                    description=meta.get("description", ""),
                    mitre_technique=meta.get("mitre_technique", ""),
                    category=meta.get("category", ""),
                    detection_method="package_db",
                    mtime=install_time,
                    atime=latest_atime,
                    binary_paths=binary_hits,
                    config_paths=config_hits,
                    aliases=_build_aliases(tool_name, meta),
                    evidence_sources=_build_evidence_sources(
                        package_db=True,
                        has_binary_hits=bool(binary_hits),
                        has_config_hits=bool(config_hits),
                    ),
                    install_time_source=install_source,
                    last_used_source="binary_atime" if latest_atime else "",
                    corroborated=bool(config_hits),
                )
                result.detected_tools.append(tool)
                detected_by_name[tool_name] = tool
                break

    # Pass 2: direct filesystem binary hits
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            hit_path = None
            hit_mtime = None
            hit_atime = None

            for rel_path in meta.get("binary_paths", []):
                found, actual_path, path_mtime, path_atime = _path_metadata(
                    root_path, path_stats, rel_path
                )
                if not found:
                    continue

                hit_path = actual_path
                hit_mtime = path_mtime
                hit_atime = path_atime
                _append_unique(result.filesystem_hits, actual_path)

                if tool_name in detected_by_name:
                    tool = detected_by_name[tool_name]
                    _append_unique(tool.binary_paths, _display_path(rel_path))
                    _append_unique(tool.evidence_sources, "binary_present")
                    if path_atime and ((tool.atime or 0) < path_atime):
                        tool.atime = path_atime
                        tool.last_used_source = "binary_atime"
                break

            if hit_path is None or tool_name in detected_by_name:
                continue

            tool = DetectedTool(
                name=tool_name,
                risk_level=risk_level,
                matched_package=_display_path(hit_path),
                description=meta.get("description", "") + " [filesystem path]",
                mitre_technique=meta.get("mitre_technique", ""),
                category=meta.get("category", ""),
                detection_method="filesystem",
                mtime=hit_mtime,
                atime=hit_atime,
                binary_paths=[_display_path(hit_path)],
                aliases=_build_aliases(tool_name, meta),
                evidence_sources=["filesystem_path"],
                install_time_source="filesystem_mtime" if hit_mtime else "",
                last_used_source="binary_atime" if hit_atime else "",
                corroborated=True,
            )
            result.detected_tools.append(tool)
            detected_by_name[tool_name] = tool

    # Pass 3: configuration traces
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            config_hits, config_mtime = _find_config_hits(
                root_path, path_stats, meta.get("config_traces", []), result
            )
            if not config_hits:
                continue

            if tool_name in detected_by_name:
                tool = detected_by_name[tool_name]
                for rel_path in config_hits:
                    _append_unique(tool.config_paths, rel_path)
                _append_unique(tool.evidence_sources, "config_trace")
                tool.corroborated = True
                if (not tool.mtime) and config_mtime:
                    tool.mtime = config_mtime
                    if not tool.install_time_source:
                        tool.install_time_source = "config_mtime"
                continue

            tool = DetectedTool(
                name=tool_name,
                risk_level=risk_level,
                matched_package=config_hits[0],
                description=meta.get("description", "") + " [config trace]",
                mitre_technique=meta.get("mitre_technique", ""),
                category=meta.get("category", ""),
                detection_method="config",
                mtime=config_mtime,
                atime=None,
                config_paths=config_hits,
                aliases=_build_aliases(tool_name, meta),
                evidence_sources=["config_trace"],
                install_time_source="config_mtime" if config_mtime else "",
                corroborated=True,
            )
            result.detected_tools.append(tool)
            detected_by_name[tool_name] = tool

    return result


def correlate_tool_evidence(
    os_profile: OSProfile,
    tool_result: ToolDetectionResult,
    live_result: Optional[LiveAnalysisResult] = None,
    observed_at: Optional[float] = None,
) -> ToolDetectionResult:
    """
    Correlate tool package hits with stronger evidence sources such as shell
    history, recent-file traces, config traces, and live /proc observations.

    On generic Debian/Arch hosts, package-only dual-use and anonymization
    utilities are suppressed unless a corroborating signal is present.
    """
    if not tool_result.detected_tools:
        return tool_result

    observed_at = observed_at or time.time()
    artefact_texts = [
        (
            artefact.artefact_type,
            " ".join(
                piece for piece in [artefact.path, artefact.description, artefact.snippet]
                if piece
            ).lower(),
        )
        for artefact in os_profile.filesystem_artefacts
    ]
    findings = live_result.process_findings if live_result and live_result.is_live_system else []

    for tool in tool_result.detected_tools:
        if tool.config_paths:
            _append_unique(tool.evidence_sources, "config_trace")
            tool.corroborated = True
        if tool.detection_method in ("filesystem", "config"):
            tool.corroborated = True

        alias_patterns = [
            re.compile(rf"\b{re.escape(alias.lower())}\b")
            for alias in (tool.aliases or [tool.name])
            if alias
        ]

        for artefact_type, text in artefact_texts:
            if not _text_mentions_any(text, alias_patterns):
                continue
            evidence = _ARTEFACT_EVIDENCE.get(artefact_type)
            if evidence:
                _append_unique(tool.evidence_sources, evidence)
                tool.corroborated = True

        for finding in findings:
            proc_text = " ".join(
                [
                    finding.comm or "",
                    finding.cmdline or "",
                    " ".join(note for note in finding.notes),
                ]
            ).lower()
            if not _text_mentions_any(proc_text, alias_patterns):
                continue
            _append_unique(tool.evidence_sources, "live_proc")
            tool.corroborated = True
            if observed_at and ((tool.atime or 0) < observed_at):
                tool.atime = observed_at
                tool.last_used_source = "live_proc_snapshot"
            break

    if os_profile.os_type in _GENERIC_OSES:
        tool_result.detected_tools = [
            tool for tool in tool_result.detected_tools
            if not (
                tool.detection_method == "package_db"
                and tool.risk_level in {"dual_use", "anonymization"}
                and not tool.corroborated
            )
        ]

    return tool_result


def _find_binary_hits(
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    binary_paths: list[str],
    result: ToolDetectionResult,
) -> tuple[list[str], Optional[float]]:
    hits: list[str] = []
    latest_atime = None
    for rel_path in binary_paths:
        found, actual_path, _mtime, atime = _path_metadata(root_path, path_stats, rel_path)
        if not found:
            continue
        _append_unique(result.filesystem_hits, actual_path)
        hits.append(_display_path(rel_path))
        if atime and (latest_atime is None or atime > latest_atime):
            latest_atime = atime
    return hits, latest_atime


def _find_config_hits(
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    config_paths: list[str],
    result: ToolDetectionResult,
) -> tuple[list[str], Optional[float]]:
    hits: list[str] = []
    earliest_mtime = None
    for rel_path in config_paths:
        found, actual_path, mtime, _atime = _path_metadata(root_path, path_stats, rel_path)
        if not found:
            continue
        _append_unique(result.config_hits, actual_path)
        hits.append(_display_path(rel_path))
        if mtime and (earliest_mtime is None or mtime < earliest_mtime):
            earliest_mtime = mtime
    return hits, earliest_mtime


def _path_metadata(
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    rel_path: str,
) -> tuple[bool, str, Optional[float], Optional[float]]:
    rel_key = _normalise_rel_path(rel_path)
    actual_path = _join_root(root_path, rel_path)

    if rel_key in path_stats:
        atime, mtime = path_stats[rel_key]
        return True, actual_path, mtime, atime

    if os.path.exists(actual_path):
        mtime = None
        atime = None
        try:
            mtime = os.path.getmtime(actual_path)
        except OSError:
            pass
        try:
            atime = os.path.getatime(actual_path)
        except OSError:
            pass
        return True, actual_path, mtime, atime

    return False, actual_path, None, None


def _read_dpkg_packages(
    root: str,
    explicit_path: Optional[str],
) -> tuple[dict[str, float], dict[str, str]]:
    status_path = explicit_path or _join_root(root, "var/lib/dpkg/status")
    info_dir = _join_root(root, "var/lib/dpkg/info")

    content = _safe_read(status_path, max_bytes=10_000_000)
    if not content and os.path.isdir(status_path):
        parts: list[str] = []
        try:
            for fname in os.listdir(status_path):
                parts.append(_safe_read(os.path.join(status_path, fname)))
        except OSError:
            pass
        content = "".join(parts)

    names = _parse_dpkg_names(content)
    log_times = _parse_dpkg_log_install_times(root)
    result: dict[str, float] = {}
    sources: dict[str, str] = {}

    for pkg in names:
        install_time = 0.0
        source = ""
        list_file = os.path.join(info_dir, f"{pkg}.list")
        if os.path.exists(list_file):
            try:
                install_time = os.path.getmtime(list_file)
                source = "dpkg_info"
            except OSError:
                pass

        if (not install_time) and pkg in log_times:
            install_time = log_times[pkg]
            source = "dpkg_log"

        result[pkg] = install_time
        sources[pkg] = source

    return result, sources


def _read_pacman_packages(
    root: str,
    explicit_path: Optional[str],
) -> tuple[dict[str, float], dict[str, str]]:
    db_dir = explicit_path or _join_root(root, "var/lib/pacman/local")
    log_times = _parse_pacman_log_install_times(root)
    result: dict[str, float] = {}
    sources: dict[str, str] = {}
    if not os.path.isdir(db_dir):
        return result, sources

    try:
        for entry in os.listdir(db_dir):
            desc_path = os.path.join(db_dir, entry, "desc")
            content = _safe_read(desc_path, max_bytes=2048)
            pkg_name = _parse_pacman_name(content)
            if not pkg_name:
                continue

            mtime = 0.0
            source = ""
            try:
                mtime = os.path.getmtime(desc_path)
                source = "pacman_db"
            except OSError:
                pass

            if (not mtime) and pkg_name in log_times:
                mtime = log_times[pkg_name]
                source = "pacman_log"

            result[pkg_name] = mtime
            sources[pkg_name] = source
    except OSError:
        pass

    return result, sources


def _parse_dpkg_log_install_times(root: str) -> dict[str, float]:
    times: dict[str, float] = {}
    for rel_path in ("var/log/dpkg.log", "var/log/dpkg.log.1"):
        content = _safe_read(_join_root(root, rel_path), max_bytes=5_000_000)
        if not content:
            continue
        for line in content.splitlines():
            match = _DPKG_LOG_RE.match(line.strip())
            if not match:
                continue
            timestamp, _action, pkg_name = match.groups()
            ts_value = _parse_log_timestamp(timestamp, "%Y-%m-%d %H:%M:%S")
            if ts_value is None:
                continue
            pkg_name = pkg_name.lower()
            if pkg_name not in times or ts_value < times[pkg_name]:
                times[pkg_name] = ts_value
    return times


def _parse_pacman_log_install_times(root: str) -> dict[str, float]:
    content = _safe_read(_join_root(root, "var/log/pacman.log"), max_bytes=5_000_000)
    if not content:
        return {}

    times: dict[str, float] = {}
    for line in content.splitlines():
        match = _PACMAN_LOG_RE.match(line.strip())
        if not match:
            continue
        timestamp, _action, pkg_name = match.groups()
        ts_value = _parse_log_timestamp(timestamp, "%Y-%m-%dT%H:%M:%S%z")
        if ts_value is None:
            continue
        pkg_name = pkg_name.lower()
        if pkg_name not in times or ts_value < times[pkg_name]:
            times[pkg_name] = ts_value
    return times


def _build_aliases(tool_name: str, meta: dict) -> list[str]:
    aliases: set[str] = {tool_name.lower()}
    for package_name in meta.get("packages", []):
        aliases.add(package_name.lower())
        aliases.add(package_name.lower().split(":")[0])
    for rel_path in meta.get("binary_paths", []):
        base = os.path.basename(rel_path).lower()
        aliases.add(base)
        aliases.add(base.rsplit(".", 1)[0])
    return sorted(alias for alias in aliases if alias)


def _build_evidence_sources(
    *,
    package_db: bool,
    has_binary_hits: bool,
    has_config_hits: bool,
) -> list[str]:
    sources: list[str] = []
    if package_db:
        sources.append("package_db")
    if has_binary_hits:
        sources.append("binary_present")
    if has_config_hits:
        sources.append("config_trace")
    return sources


def _load_path_stats(root_path: str) -> dict[str, tuple[Optional[float], Optional[float]]]:
    stats_path = os.path.join(root_path, _PATH_STATS_FILE)
    if not os.path.isfile(stats_path):
        return {}

    stats: dict[str, tuple[Optional[float], Optional[float]]] = {}
    for line in _safe_read(stats_path, max_bytes=10_000_000).splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        raw_path, raw_atime, raw_mtime = parts
        rel_path = _normalise_rel_path(raw_path)
        atime = _parse_float(raw_atime)
        mtime = _parse_float(raw_mtime)
        stats[rel_path] = (atime, mtime)
    return stats


def _parse_dpkg_names(content: str) -> set[str]:
    names: set[str] = set()
    for line in content.splitlines():
        if line.startswith("Package:"):
            names.add(line.split(":", 1)[1].strip().lower())
    return names


def _parse_pacman_name(desc_content: str) -> Optional[str]:
    lines = desc_content.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "%NAME%" and i + 1 < len(lines):
            return lines[i + 1].strip().lower()
    return None


def _parse_log_timestamp(value: str, fmt: str) -> Optional[float]:
    try:
        import datetime

        parsed = datetime.datetime.strptime(value, fmt)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def _parse_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except ValueError:
        return None


def _text_mentions_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _display_path(path: str) -> str:
    cleaned = path.replace("\\", "/")
    return cleaned if cleaned.startswith("/") else f"/{cleaned.lstrip('/')}"


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _join_root(root_path: str, rel_path: str) -> str:
    return os.path.join(root_path, rel_path.lstrip("/\\"))


def _normalise_root(root_path: str) -> str:
    cleaned = root_path.rstrip("/\\")
    return cleaned or root_path


def _normalise_rel_path(path: str) -> str:
    cleaned = path.replace("\\", "/")
    if ":/" in cleaned:
        cleaned = cleaned.split(":/", 1)[1]
    return cleaned.lstrip("/").strip()


def _safe_read(path: str, max_bytes: int = 4096) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def _load_signatures(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
