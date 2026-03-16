from typing import Optional

from modules.tool_detector_models import DetectedTool, ToolDetectionResult
from modules.tool_detector_paths import (
    build_aliases,
    build_evidence_sources,
    find_binary_hits,
    find_config_hits,
    path_metadata,
)
from modules.tool_detector_support import append_unique, display_path


def package_db_pass(
    sigs: dict,
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    installed: dict[str, float],
    install_sources: dict[str, str],
    result: ToolDetectionResult,
    detected_by_name: dict[str, DetectedTool],
) -> None:
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            for pkg_variant in meta.get("packages", []):
                pkg_key = pkg_variant.lower()
                if pkg_key not in installed:
                    continue

                binary_hits, latest_atime = find_binary_hits(
                    root_path, path_stats, meta.get("binary_paths", []), result
                )
                config_hits, config_mtime = find_config_hits(
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
                    aliases=build_aliases(tool_name, meta),
                    evidence_sources=build_evidence_sources(
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


def filesystem_pass(
    sigs: dict,
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    result: ToolDetectionResult,
    detected_by_name: dict[str, DetectedTool],
) -> None:
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            hit_path = None
            hit_mtime = None
            hit_atime = None

            for rel_path in meta.get("binary_paths", []):
                found, actual_path, path_mtime, path_atime = path_metadata(root_path, path_stats, rel_path)
                if not found:
                    continue
                hit_path = actual_path
                hit_mtime = path_mtime
                hit_atime = path_atime
                append_unique(result.filesystem_hits, actual_path)

                if tool_name in detected_by_name:
                    tool = detected_by_name[tool_name]
                    append_unique(tool.binary_paths, display_path(rel_path))
                    append_unique(tool.evidence_sources, "binary_present")
                    if path_atime and ((tool.atime or 0) < path_atime):
                        tool.atime = path_atime
                        tool.last_used_source = "binary_atime"
                break

            if hit_path is None or tool_name in detected_by_name:
                continue

            result.detected_tools.append(
                DetectedTool(
                    name=tool_name,
                    risk_level=risk_level,
                    matched_package=display_path(hit_path),
                    description=meta.get("description", "") + " [filesystem path]",
                    mitre_technique=meta.get("mitre_technique", ""),
                    category=meta.get("category", ""),
                    detection_method="filesystem",
                    mtime=hit_mtime,
                    atime=hit_atime,
                    binary_paths=[display_path(hit_path)],
                    aliases=build_aliases(tool_name, meta),
                    evidence_sources=["filesystem_path"],
                    install_time_source="filesystem_mtime" if hit_mtime else "",
                    last_used_source="binary_atime" if hit_atime else "",
                    corroborated=True,
                )
            )
            detected_by_name[tool_name] = result.detected_tools[-1]


def config_pass(
    sigs: dict,
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    result: ToolDetectionResult,
    detected_by_name: dict[str, DetectedTool],
) -> None:
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            config_hits, config_mtime = find_config_hits(
                root_path, path_stats, meta.get("config_traces", []), result
            )
            if not config_hits:
                continue

            if tool_name in detected_by_name:
                tool = detected_by_name[tool_name]
                for rel_path in config_hits:
                    append_unique(tool.config_paths, rel_path)
                append_unique(tool.evidence_sources, "config_trace")
                tool.corroborated = True
                if (not tool.mtime) and config_mtime:
                    tool.mtime = config_mtime
                    if not tool.install_time_source:
                        tool.install_time_source = "config_mtime"
                continue

            result.detected_tools.append(
                DetectedTool(
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
                    aliases=build_aliases(tool_name, meta),
                    evidence_sources=["config_trace"],
                    install_time_source="config_mtime" if config_mtime else "",
                    corroborated=True,
                )
            )
            detected_by_name[tool_name] = result.detected_tools[-1]


def removed_package_pass(
    sigs: dict,
    root_path: str,
    path_stats: dict[str, tuple[Optional[float], Optional[float]]],
    installed: dict[str, float],
    historical_installs: dict[str, float],
    historical_install_sources: dict[str, str],
    removed: dict[str, float],
    removal_sources: dict[str, str],
    result: ToolDetectionResult,
    detected_by_name: dict[str, DetectedTool],
) -> None:
    for risk_level, tools in sigs.items():
        for tool_name, meta in tools.items():
            if tool_name in detected_by_name:
                continue

            removed_pkg = None
            install_time = None
            removal_time = None
            install_source = ""

            for pkg_variant in meta.get("packages", []):
                pkg_key = pkg_variant.lower()
                if pkg_key in installed or pkg_key not in removed:
                    continue
                removed_pkg = pkg_variant
                install_time = historical_installs.get(pkg_key)
                install_source = historical_install_sources.get(pkg_key, "")
                removal_time = removed[pkg_key]
                break

            if removed_pkg is None:
                continue

            binary_hits, latest_atime = find_binary_hits(
                root_path, path_stats, meta.get("binary_paths", []), result
            )
            config_hits, config_mtime = find_config_hits(
                root_path, path_stats, meta.get("config_traces", []), result
            )

            if binary_hits:
                continue

            if (not install_time) and config_mtime:
                install_time = config_mtime
                install_source = "config_mtime"

            result.detected_tools.append(
                DetectedTool(
                    name=tool_name,
                    risk_level=risk_level,
                    matched_package=removed_pkg,
                    description=meta.get("description", "") + " [historical package removed]",
                    mitre_technique=meta.get("mitre_technique", ""),
                    category=meta.get("category", ""),
                    detection_method="removed_package",
                    mtime=install_time,
                    atime=latest_atime,
                    binary_paths=[],
                    config_paths=config_hits,
                    aliases=build_aliases(tool_name, meta),
                    evidence_sources=["package_log_remove"],
                    install_time_source=install_source,
                    removal_time=removal_time,
                    removal_time_source=removal_sources.get(removed_pkg.lower(), ""),
                    last_used_source="binary_atime" if latest_atime else "",
                    present_on_disk=False,
                    corroborated=bool(config_hits),
                )
            )
            detected_by_name[tool_name] = result.detected_tools[-1]
