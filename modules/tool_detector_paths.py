import os
from typing import Optional

from modules.tool_detector_models import ToolDetectionResult
from modules.tool_detector_support import append_unique, display_path, join_root, normalise_rel_path


def find_binary_hits(
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    binary_paths: list[str],
    result: ToolDetectionResult,
) -> tuple[list[str], Optional[float]]:
    hits: list[str] = []
    latest_atime = None
    for rel_path in binary_paths:
        found, actual_path, _mtime, atime = path_metadata(root_path, path_stats, rel_path)
        if not found:
            continue
        append_unique(result.filesystem_hits, actual_path)
        hits.append(display_path(rel_path))
        if atime and (latest_atime is None or atime > latest_atime):
            latest_atime = atime
    return hits, latest_atime


def find_config_hits(
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    config_paths: list[str],
    result: ToolDetectionResult,
) -> tuple[list[str], Optional[float]]:
    hits: list[str] = []
    earliest_mtime = None
    for rel_path in config_paths:
        found, actual_path, mtime, _atime = path_metadata(root_path, path_stats, rel_path)
        if not found:
            continue
        append_unique(result.config_hits, actual_path)
        hits.append(display_path(rel_path))
        if mtime and (earliest_mtime is None or mtime < earliest_mtime):
            earliest_mtime = mtime
    return hits, earliest_mtime


def path_metadata(
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    rel_path: str,
) -> tuple[bool, str, Optional[float], Optional[float]]:
    rel_key = normalise_rel_path(rel_path)
    actual_path = join_root(root_path, rel_path)

    if rel_key in path_stats:
        atime, mtime = path_stats[rel_key]
        return True, actual_path, mtime, atime

    if os.path.exists(actual_path):
        mtime = atime = None
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


def build_aliases(tool_name: str, meta: dict) -> list[str]:
    aliases: set[str] = {tool_name.lower()}
    for package_name in meta.get("packages", []):
        package_name = package_name.lower()
        aliases.add(package_name)
        aliases.add(package_name.split(":")[0])
    for rel_path in meta.get("binary_paths", []):
        base = os.path.basename(rel_path).lower()
        aliases.add(base)
        aliases.add(base.rsplit(".", 1)[0])
    return sorted(alias for alias in aliases if alias)


def build_evidence_sources(*, package_db: bool, has_binary_hits: bool, has_config_hits: bool) -> list[str]:
    sources: list[str] = []
    if package_db:
        sources.append("package_db")
    if has_binary_hits:
        sources.append("binary_present")
    if has_config_hits:
        sources.append("config_trace")
    return sources
