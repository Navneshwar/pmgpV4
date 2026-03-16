from dataclasses import dataclass, field
from typing import Optional


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
    filesystem_hits: list[str] = field(default_factory=list)
    config_hits: list[str] = field(default_factory=list)

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
