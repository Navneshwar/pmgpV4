from typing import Optional

from modules.tool_detector_correlate import correlate_tool_evidence
from modules.tool_detector_models import DetectedTool, ToolDetectionResult
from modules.tool_detector_scan import (
    config_pass,
    filesystem_pass,
    package_db_pass,
    removed_package_pass,
)
from modules.tool_detector_support import (
    _SIGNATURES_PATH,
    load_path_stats,
    load_signatures,
    normalise_root,
    parse_dpkg_log_install_times,
    parse_dpkg_log_removal_times,
    parse_pacman_log_install_times,
    parse_pacman_log_removal_times,
    read_dpkg_packages,
    read_pacman_packages,
)


def detect_tools(
    root_path: str,
    pkg_db_type: str,
    pkg_db_path: Optional[str] = None,
    signatures_path: Optional[str] = None,
) -> ToolDetectionResult:
    sigs = load_signatures(signatures_path or str(_SIGNATURES_PATH))
    root_path = normalise_root(root_path)
    path_stats = load_path_stats(root_path)
    installed, install_sources = read_packages(root_path, pkg_db_type, pkg_db_path)
    historical_installs, historical_install_sources = read_historical_installs(root_path, pkg_db_type)
    removed, removal_sources = read_removed_packages(root_path, pkg_db_type)

    result = ToolDetectionResult(
        total_packages_scanned=len(installed),
        raw_package_list=sorted(installed),
    )
    detected_by_name: dict[str, DetectedTool] = {}

    package_db_pass(sigs, root_path, path_stats, installed, install_sources, result, detected_by_name)
    filesystem_pass(sigs, root_path, path_stats, result, detected_by_name)
    config_pass(sigs, root_path, path_stats, result, detected_by_name)
    removed_package_pass(
        sigs,
        root_path,
        path_stats,
        installed,
        historical_installs,
        historical_install_sources,
        removed,
        removal_sources,
        result,
        detected_by_name,
    )
    return result


def read_packages(
    root_path: str,
    pkg_db_type: str,
    pkg_db_path: Optional[str],
) -> tuple[dict[str, float], dict[str, str]]:
    if pkg_db_type == "dpkg":
        return read_dpkg_packages(root_path, pkg_db_path)
    if pkg_db_type == "pacman":
        return read_pacman_packages(root_path, pkg_db_path)
    return {}, {}


def read_removed_packages(
    root_path: str,
    pkg_db_type: str,
) -> tuple[dict[str, float], dict[str, str]]:
    if pkg_db_type == "dpkg":
        removed = parse_dpkg_log_removal_times(root_path)
        return removed, {pkg: "dpkg_log_remove" for pkg in removed}
    if pkg_db_type == "pacman":
        removed = parse_pacman_log_removal_times(root_path)
        return removed, {pkg: "pacman_log_remove" for pkg in removed}
    return {}, {}


def read_historical_installs(
    root_path: str,
    pkg_db_type: str,
) -> tuple[dict[str, float], dict[str, str]]:
    if pkg_db_type == "dpkg":
        installs = parse_dpkg_log_install_times(root_path)
        return installs, {pkg: "dpkg_log" for pkg in installs}
    if pkg_db_type == "pacman":
        installs = parse_pacman_log_install_times(root_path)
        return installs, {pkg: "pacman_log" for pkg in installs}
    return {}, {}


__all__ = [
    "DetectedTool",
    "ToolDetectionResult",
    "correlate_tool_evidence",
    "detect_tools",
]
