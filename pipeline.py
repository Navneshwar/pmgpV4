"""
pipeline.py
Top-level PMGP orchestrator.
Chains: OS profiler → tool detector → live analyzer → disk analyzer → risk classifier → report generator
Can be used as a library or called directly from the CLI / Streamlit UI.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

from modules.os_profiler import identify_os, OSProfile
from modules.tool_detector import (
    correlate_tool_evidence,
    detect_tools,
    ToolDetectionResult,
)
from modules.live_analyzer import analyze_live_system, LiveAnalysisResult
from modules.disk_analyzer import analyze_disk, DiskAnalysisResult
from modules.risk_classifier import classify_risk, RiskReport
from modules.report_generator import generate_json_report, generate_html_report


@dataclass
class PipelineConfig:
    """Configures which pipeline stages are enabled."""
    root_path:        str           = "/"
    run_live_analysis: bool         = True
    disk_image_path:  Optional[str] = None
    output_dir:       str           = "reports"
    save_json:        bool          = True
    save_html:        bool          = True


@dataclass
class PipelineResult:
    os_profile:      Optional[OSProfile]         = None
    tool_result:     Optional[ToolDetectionResult] = None
    live_result:     Optional[LiveAnalysisResult]  = None
    disk_result:     Optional[DiskAnalysisResult]  = None
    risk_report:     Optional[RiskReport]          = None
    json_report:     str                           = ""
    html_report:     str                           = ""
    json_path:       Optional[str]                 = None
    html_path:       Optional[str]                 = None
    elapsed_seconds: float                         = 0.0
    errors:          list[str]                     = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.risk_report is not None


# ── Public entry-point ────────────────────────────────────────────────────────

def run_pipeline(
    config: PipelineConfig,
    progress_callback: Optional[Callable[[str, int], None]] = None,
) -> PipelineResult:
    """
    Execute the full PMGP forensic pipeline.
    progress_callback(message, percent) is called at each stage.
    """
    result = PipelineResult()
    t0 = time.monotonic()

    def _progress(msg: str, pct: int) -> None:
        if progress_callback:
            progress_callback(msg, pct)

    # ── Stage 1: Disk analysis (run BEFORE OS profiler so Tails cross-signal
    #             can be passed into identify_os for amnesic systems) ──────
    tails_disk_confirmed = False
    if config.disk_image_path:
        _progress("Inspecting disk image for encrypted partitions…", 15)
        try:
            result.disk_result = analyze_disk(config.disk_image_path)
            if result.disk_result and result.disk_result.tails_data_found:
                tails_disk_confirmed = True
        except Exception as exc:
            result.errors.append(f"Disk analyzer error: {exc}")
            result.disk_result = None

    # ── Stage 2: OS identification (cross-signal from disk) ───────────────
    _progress("Identifying operating system…", 30)
    try:
        result.os_profile = identify_os(
            config.root_path,
            tails_disk_confirmed=tails_disk_confirmed,
        )
    except Exception as exc:
        result.errors.append(f"OS profiler error: {exc}")
        result.elapsed_seconds = time.monotonic() - t0
        return result

    # ── Stage 3: Tool detection ───────────────────────────────────────────
    _progress("Scanning for offensive tools (packages + filesystem + configs)…", 50)
    try:
        result.tool_result = detect_tools(
            root_path=config.root_path,
            pkg_db_type=result.os_profile.pkg_db_type,
            pkg_db_path=result.os_profile.pkg_db_path,
        )
    except Exception as exc:
        result.errors.append(f"Tool detector error: {exc}")
        result.tool_result = ToolDetectionResult()

    # ── Stage 4: Live analysis (optional) ────────────────────────────────
    if config.run_live_analysis:
        _progress("Analysing live /proc — processes, cmdlines, network connections…", 68)
        try:
            proc_path = os.path.join(config.root_path.rstrip("/"), "proc")
            if not os.path.isdir(proc_path):
                proc_path = "/proc"
            result.live_result = analyze_live_system(proc_path)
        except Exception as exc:
            result.errors.append(f"Live analyzer error: {exc}")
            result.live_result = None

    if result.os_profile and result.tool_result:
        try:
            result.tool_result = correlate_tool_evidence(
                result.os_profile,
                result.tool_result,
                result.live_result,
                observed_at=time.time(),
            )
        except Exception as exc:
            result.errors.append(f"Tool evidence correlation error: {exc}")

    # ── Stage 5: Risk classification ──────────────────────────────────────
    _progress("Classifying risk, inferring kill chains, mapping MITRE ATT&CK…", 82)
    try:
        result.risk_report = classify_risk(
            os_profile=result.os_profile,
            tool_result=result.tool_result,
            live_result=result.live_result,
            disk_result=result.disk_result,
        )
    except Exception as exc:
        result.errors.append(f"Risk classifier error: {exc}")
        result.elapsed_seconds = time.monotonic() - t0
        return result

    # ── Stage 6: Report generation ────────────────────────────────────────
    _progress("Generating forensic reports…", 94)
    try:
        json_path = None
        html_path = None
        if config.save_json or config.save_html:
            os.makedirs(config.output_dir, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            json_path = os.path.join(config.output_dir, f"pmgp_{timestamp}.json")
            html_path = os.path.join(config.output_dir, f"pmgp_{timestamp}.html")

        result.json_report = generate_json_report(
            os_profile=result.os_profile,
            tool_result=result.tool_result,
            risk_report=result.risk_report,
            live_result=result.live_result,
            disk_result=result.disk_result,
            output_path=json_path if config.save_json else None,
        )
        result.html_report = generate_html_report(
            os_profile=result.os_profile,
            tool_result=result.tool_result,
            risk_report=result.risk_report,
            live_result=result.live_result,
            disk_result=result.disk_result,
            output_path=html_path if config.save_html else None,
        )
        result.json_path = json_path if config.save_json else None
        result.html_path = html_path if config.save_html else None
    except Exception as exc:
        result.errors.append(f"Report generator error: {exc}")

    _progress("Done.", 100)
    result.elapsed_seconds = time.monotonic() - t0
    return result
