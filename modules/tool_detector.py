"""Compatibility wrapper for the tool detector public API."""

from modules.tool_detector_core import correlate_tool_evidence, detect_tools
from modules.tool_detector_models import DetectedTool, ToolDetectionResult

__all__ = [
    "DetectedTool",
    "ToolDetectionResult",
    "detect_tools",
    "correlate_tool_evidence",
]
