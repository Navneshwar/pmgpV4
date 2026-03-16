"""
modules/live_analyzer.py
Public entry-point — delegates entirely to the live_analyzer sub-package.

Keeping this file means nothing else in the project needs to change:
    from modules.live_analyzer import analyze_live_system   # still works
    from modules.live_analyzer import LiveAnalysisResult    # still works
"""

from modules.live_analyzer import (       # noqa: F401  (re-export)
    analyze_live_system,
    LiveAnalysisResult,
    ProcessFinding,
    NetworkConnection,
)

__all__ = [
    "analyze_live_system",
    "LiveAnalysisResult",
    "ProcessFinding",
    "NetworkConnection",
]