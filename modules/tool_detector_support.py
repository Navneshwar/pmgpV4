import json
import os
import re
from pathlib import Path
from typing import Optional

_DATA_DIR = Path(__file__).parent.parent / "data"
_SIGNATURES_PATH = _DATA_DIR / "tool_signatures.json"
_PATH_STATS_FILE = ".pmgp_path_stats.tsv"
_DPKG_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(install|upgrade)\s+([A-Za-z0-9.+_-]+)(?::\S+)?\s+"
)
_DPKG_REMOVE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(remove|purge)\s+([A-Za-z0-9.+_-]+)(?::\S+)?\s+"
)
_PACMAN_LOG_RE = re.compile(
    r"^\[(.+?)\]\s+\[ALPM\]\s+(installed|upgraded)\s+([A-Za-z0-9.+_-]+)\s+\("
)
_PACMAN_REMOVE_RE = re.compile(
    r"^\[(.+?)\]\s+\[ALPM\]\s+(removed)\s+([A-Za-z0-9.+_-]+)\s+\("
)


def load_signatures(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_path_stats(root_path: str) -> dict[str, tuple[Optional[float], Optional[float]]]:
    stats_path = os.path.join(root_path, _PATH_STATS_FILE)
    if not os.path.isfile(stats_path):
        return {}

    stats: dict[str, tuple[Optional[float], Optional[float]]] = {}
    for line in safe_read(stats_path, max_bytes=10_000_000).splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        raw_path, raw_atime, raw_mtime = parts
        stats[normalise_rel_path(raw_path)] = (parse_float(raw_atime), parse_float(raw_mtime))
    return stats


def read_dpkg_packages(root: str, explicit_path: Optional[str]) -> tuple[dict[str, float], dict[str, str]]:
    status_path = explicit_path or join_root(root, "var/lib/dpkg/status")
    info_dir = join_root(root, "var/lib/dpkg/info")
    content = safe_read(status_path, max_bytes=10_000_000)

    if not content and os.path.isdir(status_path):
        parts: list[str] = []
        try:
            for fname in os.listdir(status_path):
                parts.append(safe_read(os.path.join(status_path, fname)))
        except OSError:
            pass
        content = "".join(parts)

    names = parse_dpkg_names(content)
    log_times = parse_dpkg_log_install_times(root)
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


def read_pacman_packages(root: str, explicit_path: Optional[str]) -> tuple[dict[str, float], dict[str, str]]:
    db_dir = explicit_path or join_root(root, "var/lib/pacman/local")
    log_times = parse_pacman_log_install_times(root)
    result: dict[str, float] = {}
    sources: dict[str, str] = {}
    if not os.path.isdir(db_dir):
        return result, sources

    try:
        for entry in os.listdir(db_dir):
            desc_path = os.path.join(db_dir, entry, "desc")
            pkg_name = parse_pacman_name(safe_read(desc_path, max_bytes=2048))
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


def parse_dpkg_log_install_times(root: str) -> dict[str, float]:
    times: dict[str, float] = {}
    for rel_path in ("var/log/dpkg.log", "var/log/dpkg.log.1"):
        for line in safe_read(join_root(root, rel_path), max_bytes=5_000_000).splitlines():
            match = _DPKG_LOG_RE.match(line.strip())
            if not match:
                continue
            timestamp, _action, pkg_name = match.groups()
            ts_value = parse_log_timestamp(timestamp, "%Y-%m-%d %H:%M:%S")
            if ts_value is None:
                continue
            pkg_name = pkg_name.lower()
            if pkg_name not in times or ts_value < times[pkg_name]:
                times[pkg_name] = ts_value
    return times


def parse_pacman_log_install_times(root: str) -> dict[str, float]:
    times: dict[str, float] = {}
    for line in safe_read(join_root(root, "var/log/pacman.log"), max_bytes=5_000_000).splitlines():
        match = _PACMAN_LOG_RE.match(line.strip())
        if not match:
            continue
        timestamp, _action, pkg_name = match.groups()
        ts_value = parse_log_timestamp(timestamp, "%Y-%m-%dT%H:%M:%S%z")
        if ts_value is None:
            continue
        pkg_name = pkg_name.lower()
        if pkg_name not in times or ts_value < times[pkg_name]:
            times[pkg_name] = ts_value
    return times


def parse_dpkg_log_removal_times(root: str) -> dict[str, float]:
    times: dict[str, float] = {}
    for rel_path in ("var/log/dpkg.log", "var/log/dpkg.log.1"):
        for line in safe_read(join_root(root, rel_path), max_bytes=5_000_000).splitlines():
            match = _DPKG_REMOVE_RE.match(line.strip())
            if not match:
                continue
            timestamp, _action, pkg_name = match.groups()
            ts_value = parse_log_timestamp(timestamp, "%Y-%m-%d %H:%M:%S")
            if ts_value is None:
                continue
            pkg_name = pkg_name.lower()
            if pkg_name not in times or ts_value > times[pkg_name]:
                times[pkg_name] = ts_value
    return times


def parse_pacman_log_removal_times(root: str) -> dict[str, float]:
    times: dict[str, float] = {}
    for line in safe_read(join_root(root, "var/log/pacman.log"), max_bytes=5_000_000).splitlines():
        match = _PACMAN_REMOVE_RE.match(line.strip())
        if not match:
            continue
        timestamp, _action, pkg_name = match.groups()
        ts_value = parse_log_timestamp(timestamp, "%Y-%m-%dT%H:%M:%S%z")
        if ts_value is None:
            continue
        pkg_name = pkg_name.lower()
        if pkg_name not in times or ts_value > times[pkg_name]:
            times[pkg_name] = ts_value
    return times


def parse_dpkg_names(content: str) -> set[str]:
    return {line.split(":", 1)[1].strip().lower() for line in content.splitlines() if line.startswith("Package:")}


def parse_pacman_name(desc_content: str) -> Optional[str]:
    lines = desc_content.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "%NAME%" and i + 1 < len(lines):
            return lines[i + 1].strip().lower()
    return None


def parse_log_timestamp(value: str, fmt: str) -> Optional[float]:
    try:
        import datetime

        parsed = datetime.datetime.strptime(value, fmt)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def parse_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except ValueError:
        return None


def display_path(path: str) -> str:
    cleaned = path.replace("\\", "/")
    return cleaned if cleaned.startswith("/") else f"/{cleaned.lstrip('/')}"


def append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def join_root(root_path: str, rel_path: str) -> str:
    return os.path.join(root_path, rel_path.lstrip("/\\"))


def normalise_root(root_path: str) -> str:
    cleaned = root_path.rstrip("/\\")
    return cleaned or root_path


def normalise_rel_path(path: str) -> str:
    cleaned = path.replace("\\", "/")
    if ":/" in cleaned:
        cleaned = cleaned.split(":/", 1)[1]
    return cleaned.lstrip("/").strip()


def safe_read(path: str, max_bytes: int = 4096) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""
