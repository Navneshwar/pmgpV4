import re
import time
from typing import Optional

from modules.live_analyzer import LiveAnalysisResult
from modules.os_profiler import OSProfile, OSType
from modules.tool_detector_models import ToolDetectionResult
from modules.tool_detector_support import append_unique

_GENERIC_OSES = {OSType.DEBIAN, OSType.ARCH_LINUX, OSType.UNKNOWN, OSType.WINDOWS}
_ARTEFACT_EVIDENCE = {"shell_history": "shell_history", "recent_files": "recent_files"}


def correlate_tool_evidence(
    os_profile: OSProfile,
    tool_result: ToolDetectionResult,
    live_result: Optional[LiveAnalysisResult] = None,
    observed_at: Optional[float] = None,
) -> ToolDetectionResult:
    if not tool_result.detected_tools:
        return tool_result

    observed_at = observed_at or time.time()
    artefact_texts = [
        (
            artefact.artefact_type,
            " ".join(
                piece for piece in [artefact.path, artefact.description, artefact.snippet] if piece
            ).lower(),
        )
        for artefact in os_profile.filesystem_artefacts
    ]
    findings = live_result.process_findings if live_result and live_result.is_live_system else []

    for tool in tool_result.detected_tools:
        if tool.config_paths:
            append_unique(tool.evidence_sources, "config_trace")
            tool.corroborated = True
        if tool.detection_method in ("filesystem", "config"):
            tool.corroborated = True

        alias_patterns = compile_alias_patterns(tool.aliases or [tool.name])

        for artefact_type, text in artefact_texts:
            if not text_mentions_any(text, alias_patterns):
                continue
            evidence = _ARTEFACT_EVIDENCE.get(artefact_type)
            if evidence:
                append_unique(tool.evidence_sources, evidence)
                tool.corroborated = True
                if not tool.last_used_source and artefact_type in {"shell_history", "recent_files"}:
                    tool.last_used_source = artefact_type

        for finding in findings:
            proc_text = " ".join([finding.comm or "", finding.cmdline or "", " ".join(finding.notes)]).lower()
            if not text_mentions_any(proc_text, alias_patterns):
                continue
            append_unique(tool.evidence_sources, "live_proc")
            tool.corroborated = True
            if observed_at and ((tool.atime or 0) < observed_at):
                tool.atime = observed_at
                tool.last_used_source = "live_proc_snapshot"
            break

    if os_profile.os_type in _GENERIC_OSES:
        tool_result.detected_tools = [
            tool for tool in tool_result.detected_tools
            if not (
                tool.detection_method in {"package_db", "removed_package"}
                and tool.risk_level in {"dual_use", "anonymization"}
                and not tool.corroborated
            )
        ]

    tool_result.detected_tools = [
        tool for tool in tool_result.detected_tools
        if tool.detection_method != "removed_package" or tool.corroborated
    ]

    return tool_result


def compile_alias_patterns(aliases: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(rf"\b{re.escape(alias.lower())}\b") for alias in aliases if alias]


def text_mentions_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)
