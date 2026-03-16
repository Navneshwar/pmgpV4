"""
modules/report_generator.py
Generates structured JSON and self-contained HTML forensic reports.
"""

import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from modules.disk_analyzer import DiskAnalysisResult
from modules.live_analyzer import LiveAnalysisResult
from modules.os_profiler import OSProfile
from modules.risk_classifier import RISK_COLOURS, RiskReport
from modules.tool_detector import ToolDetectionResult


def generate_html_report(
    os_profile: OSProfile,
    tool_result: ToolDetectionResult,
    risk_report: RiskReport,
    live_result: Optional[LiveAnalysisResult] = None,
    disk_result: Optional[DiskAnalysisResult] = None,
    output_path: Optional[str] = None,
) -> str:
    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PMGP Report - {_esc(os_profile.os_type.value)}</title>
  {_html_style()}
</head>
<body>
  <main class="page">
    {_html_body(os_profile, tool_result, risk_report, live_result, disk_result)}
  </main>
</body>
</html>"""
    if output_path:
        _write(output_path, html_report)
    return html_report


def generate_json_report(
    os_profile: OSProfile,
    tool_result: ToolDetectionResult,
    risk_report: RiskReport,
    live_result: Optional[LiveAnalysisResult] = None,
    disk_result: Optional[DiskAnalysisResult] = None,
    output_path: Optional[str] = None,
) -> str:
    doc = {
        "report_meta": {
            "tool": "Passive Metadata-Graph Protocol (PMGP)",
            "version": "2.0",
            "generated_at": _now_iso(),
        },
        "os_profile": _os_profile_dict(os_profile),
        "risk_assessment": {
            "overall_risk": risk_report.overall_risk,
            "risk_score": risk_report.risk_score,
            "summary": list(risk_report.summary_lines),
            "kill_chains": list(risk_report.kill_chains),
            "time_of_attack": risk_report.time_of_attack,
        },
        "detected_tools": [_tool_dict(tool) for tool in tool_result.detected_tools],
        "mitre_coverage": [_mitre_dict(entry) for entry in risk_report.mitre_coverage],
        "risk_items": [_risk_item_dict(item) for item in risk_report.items],
        "live_analysis": _live_analysis_dict(live_result),
        "disk_analysis": _disk_analysis_dict(disk_result),
    }
    json_report = json.dumps(doc, indent=2, ensure_ascii=False)
    if output_path:
        _write(output_path, json_report)
    return json_report


def _html_body(
    os_profile: OSProfile,
    tool_result: ToolDetectionResult,
    risk_report: RiskReport,
    live_result: Optional[LiveAnalysisResult],
    disk_result: Optional[DiskAnalysisResult],
) -> str:
    return "\n".join(
        [
            _header(os_profile, tool_result, risk_report),
            _section_case_info(os_profile, live_result, disk_result, risk_report),
            _section_methodology(),
            _section_os_profile(os_profile),
            _section_tool_assessment(tool_result),
            _section_timeline(tool_result, risk_report),
            _section_live_analysis(live_result),
            _section_disk_analysis(disk_result),
            _section_mitre(risk_report),
            _section_risk_graphs(tool_result, risk_report),
            _section_limitations(disk_result),
            _section_conclusion(tool_result, risk_report),
            _section_appendix(tool_result, risk_report),
            _footer(),
        ]
    )


def _header(os_profile: OSProfile, tool_result: ToolDetectionResult, risk_report: RiskReport) -> str:
    risk_colour = RISK_COLOURS.get(risk_report.overall_risk, "#475569")
    stats = [
        ("OS Profile", os_profile.os_type.value),
        ("Risk", f"{risk_report.overall_risk} ({risk_report.risk_score}/100)"),
        ("Tools Found", str(len(tool_result.detected_tools))),
        ("Packages Scanned", str(tool_result.total_packages_scanned)),
    ]
    cards = "".join(
        f"<div class='hero-stat'><div class='hero-label'>{_esc(label)}</div>"
        f"<div class='hero-value'>{_esc(value)}</div></div>"
        for label, value in stats
    )
    return (
        "<section class='hero'>"
        "<div class='hero-kicker'>Passive Metadata-Graph Protocol v2.0</div>"
        "<div class='hero-row'>"
        "<div>"
        "<h1>Digital Forensic Investigation Report</h1>"
        f"<p class='hero-sub'>Evidence-based passive inspection of {_esc(os_profile.os_type.value)} with structured ATT&CK and timeline correlation.</p>"
        "</div>"
        f"<div class='risk-pill' style='background:{risk_colour};'>{_esc(risk_report.overall_risk)} RISK</div>"
        "</div>"
        f"<div class='hero-grid'>{cards}</div>"
        "</section>"
    )


def _section_case_info(
    os_profile: OSProfile,
    live_result: Optional[LiveAnalysisResult],
    disk_result: Optional[DiskAnalysisResult],
    risk_report: RiskReport,
) -> str:
    evidence_source = "Live system metadata"
    if disk_result and disk_result.image_path:
        evidence_source = f"Filesystem and disk image metadata ({disk_result.image_path})"
    elif live_result and live_result.is_live_system:
        evidence_source = "Live system metadata and /proc inspection"

    rows = [
        ("Case Identifier", f"PMGP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"),
        ("Investigation Date", _now_iso()),
        ("Analyst / Engine", "PMGP Engine (v2.0)"),
        ("Detected Platform", os_profile.os_type.value),
        ("Evidence Source", evidence_source),
        ("Earliest Suspicious Install", risk_report.time_of_attack),
    ]
    return _table_section("1. Case Information", rows)


def _section_methodology() -> str:
    items = [
        "Non-destructive metadata inspection only. No binaries are executed.",
        "Package databases, filesystem traces, and config artefacts are correlated.",
        "Live process and network metadata are inspected from read-only /proc sources when available.",
        "Tools are mapped to MITRE ATT&CK tactics and weighted into a structured risk model.",
        "Reported timestamps prioritize corroborated installed and last-used evidence.",
    ]
    body = "".join(f"<li>{_esc(item)}</li>" for item in items)
    return f"<section><h2>2. Methodology</h2><ul class='clean-list'>{body}</ul></section>"


def _section_os_profile(os_profile: OSProfile) -> str:
    artefacts = "".join(
        "<li><strong>{}</strong> - {}{}</li>".format(
            _esc(artefact.path),
            _esc(artefact.description),
            f" <code>{_esc(artefact.snippet)}</code>" if artefact.snippet else "",
        )
        for artefact in os_profile.filesystem_artefacts[:8]
    )
    indicators = "".join(f"<li>{_esc(ind)}</li>" for ind in os_profile.indicators) or "<li>No strong indicators captured.</li>"
    return (
        "<section>"
        "<h2>3. Operating System Profile</h2>"
        "<div class='panel-grid'>"
        f"<div class='panel'><h3>Distribution</h3><p><strong>{_esc(os_profile.os_type.value)}</strong></p>"
        f"<p>Confidence: {int(os_profile.confidence * 100)}%</p>"
        f"<p>Package DB: <code>{_esc(os_profile.pkg_db_type or 'unknown')}</code></p>"
        f"<p>DB Path: <code>{_esc(os_profile.pkg_db_path or 'N/A')}</code></p></div>"
        f"<div class='panel'><h3>Indicators</h3><ul class='clean-list'>{indicators}</ul></div>"
        "</div>"
        "<div class='panel'>"
        "<h3>Filesystem Artefacts</h3>"
        f"<ul class='clean-list'>{artefacts or '<li>No filesystem artefacts recorded.</li>'}</ul>"
        "</div>"
        "</section>"
    )


def _section_tool_assessment(tool_result: ToolDetectionResult) -> str:
    rows = []
    for tool in tool_result.detected_tools:
        status = "Present" if tool.present_on_disk else "Removed"
        rows.append(
            "<tr>"
            f"<td><strong>{_esc(tool.name)}</strong></td>"
            f"<td>{_esc(tool.description)}</td>"
            f"<td><code>{_esc(tool.mitre_technique)}</code><br><span class='muted'>{_esc(tool.category)}</span></td>"
            f"<td>{_badge(tool.risk_level)}</td>"
            f"<td>{_esc(tool.detection_method)}</td>"
            f"<td>{_esc(status)}</td>"
            f"<td>{_esc(_timestamp_text(tool.mtime, 'Not recovered'))}</td>"
            f"<td>{_esc(_timestamp_text(tool.atime, 'Not observed'))}</td>"
            f"<td>{_esc(_timestamp_text(tool.removal_time, 'Not observed'))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='9' class='empty'>No suspicious tools detected.</td></tr>")
    return (
        "<section>"
        "<h2>4. Tool And Capability Assessment</h2>"
        "<p>Only corroborated tool findings are retained in the final report. Installed, last-used, and removal timestamps are shown when evidence exists.</p>"
        "<table>"
        "<tr><th>Identifier</th><th>Functionality Note</th><th>MITRE Mapping</th><th>Classification</th><th>Detection</th><th>Status</th><th>Installed</th><th>Last Used</th><th>Removed</th></tr>"
        + "".join(rows)
        + "</table>"
        "</section>"
    )


def _section_timeline(tool_result: ToolDetectionResult, risk_report: RiskReport) -> str:
    events = []
    for tool in tool_result.detected_tools:
        if tool.mtime:
            events.append((tool.mtime, f"{tool.name} installed ({tool.install_time_source or tool.detection_method})"))
        if tool.atime:
            events.append((tool.atime, f"{tool.name} last used ({tool.last_used_source or 'usage evidence'})"))
        if tool.removal_time:
            events.append((tool.removal_time, f"{tool.name} removed ({tool.removal_time_source or 'package_log_remove'})"))
    if risk_report.time_of_attack and risk_report.time_of_attack not in ("Not determined", "No attack detected"):
        events.append((None, f"Earliest suspicious install inferred: {risk_report.time_of_attack}"))
    ordered = sorted([e for e in events if e[0] is not None], key=lambda item: item[0])
    rows = []
    for ts, note in ordered[:20]:
        rows.append(f"<tr><td>{_esc(_timestamp_text(ts))}</td><td>{_esc(note)}</td></tr>")
    if len(rows) == 0 and events:
        for _, note in events:
            rows.append(f"<tr><td>Derived</td><td>{_esc(note)}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan='2' class='empty'>No definitive forensic timestamps were recovered.</td></tr>")
    return (
        "<section>"
        "<h2>5. Timeline Of Notable Events</h2>"
        "<table>"
        "<tr><th>Timestamp (UTC)</th><th>Artifact Activity / Indicator</th></tr>"
        + "".join(rows)
        + "</table>"
        "</section>"
    )


def _section_live_analysis(live_result: Optional[LiveAnalysisResult]) -> str:
    if not live_result:
        return "<section><h2>6. Volatile System Analysis</h2><p>No live analysis data was supplied.</p></section>"
    findings = []
    for pf in live_result.process_findings:
        findings.append(
            "<tr>"
            f"<td>{pf.pid}</td>"
            f"<td><code>{_esc(pf.comm)}</code></td>"
            f"<td>{_esc(', '.join(pf.suspicious_vars) or '-')}</td>"
            f"<td>{_esc('; '.join(pf.notes[:3]) or pf.cmdline[:120] or 'Suspicious runtime evidence')}</td>"
            "</tr>"
        )
    if not findings:
        findings.append("<tr><td colspan='4' class='empty'>No suspicious live-process indicators observed.</td></tr>")
    return (
        "<section>"
        "<h2>6. Volatile System Analysis</h2>"
        f"<p>Processes scanned: <strong>{live_result.total_processes_scanned}</strong> | Suspicious processes: <strong>{len(live_result.process_findings)}</strong> | Suspicious connections: <strong>{len(live_result.suspicious_connections)}</strong></p>"
        "<table>"
        "<tr><th>PID</th><th>Command Name</th><th>Flagged Variables</th><th>Observation</th></tr>"
        + "".join(findings)
        + "</table>"
        "</section>"
    )


def _section_disk_analysis(disk_result: Optional[DiskAnalysisResult]) -> str:
    if not disk_result:
        return "<section><h2>7. Disk And Encryption Analysis</h2><p>Evidence was provided as a filesystem mount; hardware block analysis was not supplied.</p></section>"
    rows = []
    for part in disk_result.partitions:
        rows.append(
            "<tr>"
            f"<td>{part.index}</td>"
            f"<td>{_esc(part.label or part.type_guid)}</td>"
            f"<td>{_esc(part.luks_version or 'None')}</td>"
            f"<td>{_esc(part.risk_label)}</td>"
            f"<td>{_esc(part.risk_note or '-')}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='5' class='empty'>No partition structure recorded.</td></tr>")
    return (
        "<section>"
        "<h2>7. Disk And Encryption Analysis</h2>"
        "<table>"
        "<tr><th>Index</th><th>Partition</th><th>Encryption</th><th>Risk</th><th>Notes</th></tr>"
        + "".join(rows)
        + "</table>"
        "</section>"
    )


def _section_mitre(risk_report: RiskReport) -> str:
    rows = []
    for entry in risk_report.mitre_coverage:
        rows.append(
            "<tr>"
            f"<td><code>{_esc(entry.technique_id)}</code></td>"
            f"<td>{_esc(entry.technique_name)}</td>"
            f"<td>{_esc(entry.tactic)}</td>"
            f"<td>{_esc(', '.join(entry.tools))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='4' class='empty'>No MITRE mappings were generated.</td></tr>")
    return (
        "<section>"
        "<h2>8. MITRE ATT&amp;CK Mapping</h2>"
        "<table>"
        "<tr><th>Technique</th><th>Description</th><th>Strategic Tactic</th><th>Evidence Correlation</th></tr>"
        + "".join(rows)
        + "</table>"
        "</section>"
    )


def _section_risk_graphs(tool_result: ToolDetectionResult, risk_report: RiskReport) -> str:
    tactic_counts = Counter(entry.tactic for entry in risk_report.mitre_coverage)
    risk_counts = Counter(item.risk_level for item in risk_report.items)
    tool_counts = Counter(tool.risk_level for tool in tool_result.detected_tools)
    timestamp_count = sum(1 for tool in tool_result.detected_tools if tool.atime or tool.mtime)
    graph_html = "".join(
        [
            _chart_box("Heuristic Risk Score", _gauge_svg(risk_report.risk_score, risk_report.overall_risk)),
            _chart_box("MITRE Tactic Frequency", _bar_chart_svg(tactic_counts, "#2563eb")),
            _chart_box("Tool Classification Mix", _donut_svg(tool_counts)),
            _chart_box(
                "Timestamp Coverage",
                _stat_block(
                    [
                        ("Tools with time evidence", str(timestamp_count)),
                        ("Tools without time evidence", str(max(len(tool_result.detected_tools) - timestamp_count, 0))),
                        ("Risk items", str(len(risk_report.items))),
                    ]
                ),
            ),
            _chart_box("Risk Item Distribution", _bar_chart_svg(risk_counts, "#ef4444")),
        ]
    )
    return (
        "<section>"
        "<h2>9. Risk Assessment And Graphical Summary</h2>"
        f"<div class='graph-grid'>{graph_html}</div>"
        "</section>"
    )


def _section_limitations(disk_result: Optional[DiskAnalysisResult]) -> str:
    items = [
        "Metadata-only analysis cannot prove execution intent without supporting telemetry.",
        "Filesystem atime may be disabled, coarse-grained, or altered by mount options.",
        "Installed timestamps depend on package-manager logs or surviving filesystem metadata.",
        "Advanced anti-forensics can suppress or manipulate timeline evidence.",
    ]
    if not disk_result:
        items.append("No block-level disk image was supplied, so deleted-partition review was not performed.")
    body = "".join(f"<li>{_esc(item)}</li>" for item in items)
    return f"<section><h2>10. Limitations</h2><ul class='clean-list'>{body}</ul></section>"


def _section_conclusion(tool_result: ToolDetectionResult, risk_report: RiskReport) -> str:
    return (
        "<section>"
        "<h2>11. Conclusion</h2>"
        f"<p>The automated forensic review identified <strong>{len(tool_result.detected_tools)}</strong> retained tool findings and assigned an overall risk of <strong>{_esc(risk_report.overall_risk)}</strong>. "
        "This report now prioritizes corroborated tools and preserves installed and last-used timestamps where evidence exists, reducing false positives from package-only detections on generic systems.</p>"
        "</section>"
    )


def _section_appendix(tool_result: ToolDetectionResult, risk_report: RiskReport) -> str:
    packages = json.dumps([tool.name for tool in tool_result.detected_tools], indent=2)
    techniques = json.dumps([entry.technique_id for entry in risk_report.mitre_coverage], indent=2)
    return (
        "<section>"
        "<h2>12. Appendix</h2>"
        "<h3>Detected Tool List</h3>"
        f"<pre>{_esc(packages)}</pre>"
        "<h3>Technique Registry</h3>"
        f"<pre>{_esc(techniques)}</pre>"
        "</section>"
    )


def _footer() -> str:
    return f"<footer>PMGP Digital Forensic Report · {_esc(_now_iso())}</footer>"


def _table_section(title: str, rows: list[tuple[str, str]]) -> str:
    body = "".join(
        f"<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>"
        for label, value in rows
    )
    return f"<section><h2>{_esc(title)}</h2><table>{body}</table></section>"


def _os_profile_dict(os_profile: OSProfile) -> dict:
    return {
        "os_type": os_profile.os_type.value,
        "confidence": os_profile.confidence,
        "indicators": list(os_profile.indicators),
        "pkg_db_type": os_profile.pkg_db_type,
        "pkg_db_path": os_profile.pkg_db_path,
        "tails_disk_confirmed": os_profile.tails_disk_confirmed,
        "filesystem_artefacts": [
            {
                "path": artefact.path,
                "type": artefact.artefact_type,
                "description": artefact.description,
                "risk_level": artefact.risk_level,
                "snippet": artefact.snippet,
            }
            for artefact in os_profile.filesystem_artefacts
        ],
    }


def _tool_dict(tool) -> dict:
    return {
        "name": tool.name,
        "risk_level": tool.risk_level,
        "matched_package": tool.matched_package,
        "description": tool.description,
        "mitre_technique": tool.mitre_technique,
        "category": tool.category,
        "detection_method": tool.detection_method,
        "mtime": tool.mtime,
        "atime": tool.atime,
        "binary_paths": list(tool.binary_paths),
        "config_paths": list(tool.config_paths),
        "aliases": list(tool.aliases),
        "evidence_sources": list(tool.evidence_sources),
        "install_time_source": tool.install_time_source,
        "removal_time": tool.removal_time,
        "removal_time_source": tool.removal_time_source,
        "last_used_source": tool.last_used_source,
        "present_on_disk": tool.present_on_disk,
        "corroborated": tool.corroborated,
    }


def _mitre_dict(entry) -> dict:
    return {
        "technique_id": entry.technique_id,
        "technique_name": entry.technique_name,
        "tactic": entry.tactic,
        "tools": list(entry.tools),
    }


def _risk_item_dict(item) -> dict:
    return {
        "source": item.source,
        "risk_level": item.risk_level,
        "title": item.title,
        "description": item.description,
        "mitre_technique": item.mitre_technique,
        "mitre_category": item.mitre_category,
        "evidence": item.evidence,
    }


def _live_analysis_dict(live_result: Optional[LiveAnalysisResult]) -> dict:
    if not live_result:
        return {}
    return {
        "is_live_system": live_result.is_live_system,
        "total_processes_scanned": live_result.total_processes_scanned,
        "suspicious_connections": len(live_result.suspicious_connections),
        "findings": [
            {
                "pid": pf.pid,
                "comm": pf.comm,
                "cmdline": pf.cmdline,
                "suspicious_vars": dict(pf.suspicious_vars),
                "attacker_ips": dict(pf.attacker_ips),
                "suspicious_paths": list(pf.suspicious_paths),
                "suspicious_maps": list(pf.suspicious_maps),
                "notes": list(pf.notes),
            }
            for pf in live_result.process_findings
        ],
    }


def _disk_analysis_dict(disk_result: Optional[DiskAnalysisResult]) -> dict:
    if not disk_result:
        return {}
    return {
        "image_path": disk_result.image_path,
        "has_gpt": disk_result.has_gpt,
        "has_mbr": disk_result.has_mbr,
        "tails_data_found": disk_result.tails_data_found,
        "notes": list(disk_result.notes),
        "partitions": [
            {
                "index": part.index,
                "label": part.label,
                "type_guid": part.type_guid,
                "luks_version": part.luks_version,
                "risk_label": part.risk_label,
                "risk_note": part.risk_note,
            }
            for part in disk_result.partitions
        ],
    }


def _timestamp_text(ts: Optional[float], fallback: str = "Unknown") -> str:
    if not ts:
        return fallback
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return fallback


def _badge(risk_level: str) -> str:
    colours = {
        "high_risk": "#dc2626",
        "dual_use": "#475569",
        "anonymization": "#1d4ed8",
    }
    label = risk_level.replace("_", " ").title()
    return f"<span class='badge' style='background:{colours.get(risk_level, '#475569')}'>{_esc(label)}</span>"


def _chart_box(title: str, body: str) -> str:
    return f"<div class='chart-box'><h3>{_esc(title)}</h3>{body}</div>"


def _gauge_svg(score: int, risk: str) -> str:
    colour = RISK_COLOURS.get(risk, "#475569")
    circumference = 251.2
    offset = circumference - (max(0, min(score, 100)) / 100.0) * circumference
    return (
        "<svg width='180' height='140' viewBox='0 0 180 140'>"
        "<circle cx='90' cy='70' r='50' fill='none' stroke='#e2e8f0' stroke-width='12'/>"
        f"<circle cx='90' cy='70' r='50' fill='none' stroke='{colour}' stroke-width='12' stroke-dasharray='{circumference}' stroke-dashoffset='{offset}' transform='rotate(-90 90 70)'/>"
        f"<text x='90' y='74' text-anchor='middle' class='gauge-score'>{score}</text>"
        f"<text x='90' y='96' text-anchor='middle' class='gauge-label'>{_esc(risk)}</text>"
        "</svg>"
    )


def _bar_chart_svg(counts: Counter, colour: str) -> str:
    if not counts:
        return "<div class='empty-graph'>No data available.</div>"
    items = list(counts.items())[:6]
    max_value = max(value for _, value in items) or 1
    bars = []
    y = 20
    for label, value in items:
        width = 180 * (value / max_value)
        bars.append(
            f"<text x='0' y='{y + 10}' class='bar-label'>{_esc(str(label))}</text>"
            f"<rect x='110' y='{y}' width='{width}' height='14' fill='{colour}' rx='4' />"
            f"<text x='{115 + width}' y='{y + 10}' class='bar-value'>{value}</text>"
        )
        y += 28
    return f"<svg width='320' height='{max(80, y)}' viewBox='0 0 320 {max(80, y)}'>{''.join(bars)}</svg>"


def _donut_svg(counts: Counter) -> str:
    total = sum(counts.values())
    if total == 0:
        return "<div class='empty-graph'>No detected tools.</div>"
    palette = {
        "high_risk": "#ef4444",
        "dual_use": "#64748b",
        "anonymization": "#2563eb",
    }
    start = 0.0
    segments = []
    legend = []
    for key, value in counts.items():
        frac = value / total
        end = start + frac
        segments.append(_donut_segment(start, end, palette.get(key, "#94a3b8")))
        legend.append(f"<div class='legend-item'><span class='legend-swatch' style='background:{palette.get(key, '#94a3b8')}'></span>{_esc(key.replace('_', ' ').title())}: {value}</div>")
        start = end
    return (
        "<div class='donut-wrap'>"
        "<svg width='180' height='180' viewBox='0 0 42 42' class='donut'>"
        "<circle cx='21' cy='21' r='15.9155' fill='transparent' stroke='#e2e8f0' stroke-width='6'></circle>"
        + "".join(segments)
        + f"<text x='21' y='21' class='donut-total'>{total}</text>"
        + "</svg>"
        + f"<div class='legend'>{''.join(legend)}</div></div>"
    )


def _donut_segment(start: float, end: float, colour: str) -> str:
    length = max((end - start) * 100, 0.01)
    offset = 25 - start * 100
    return (
        f"<circle cx='21' cy='21' r='15.9155' fill='transparent' stroke='{colour}' stroke-width='6' "
        f"stroke-dasharray='{length} {100 - length}' stroke-dashoffset='{offset}'></circle>"
    )


def _stat_block(entries: list[tuple[str, str]]) -> str:
    blocks = "".join(
        f"<div class='mini-stat'><div class='mini-label'>{_esc(label)}</div><div class='mini-value'>{_esc(value)}</div></div>"
        for label, value in entries
    )
    return f"<div class='mini-grid'>{blocks}</div>"


def _html_style() -> str:
    return """
<style>
  :root {
    --ink: #0f172a;
    --muted: #475569;
    --muted-2: #94a3b8;
    --line: #dbe4f0;
    --paper: #f8fbff;
    --card: #ffffff;
    --blue: #2563eb;
    --navy: #14213d;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Segoe UI", "Helvetica Neue", sans-serif;
    color: var(--ink);
    background:
      radial-gradient(circle at top right, rgba(37, 99, 235, 0.08), transparent 28%),
      linear-gradient(180deg, #f8fbff 0%, #eef4fb 100%);
  }
  .page {
    max-width: 1180px;
    margin: 0 auto;
    padding: 36px 24px 60px;
  }
  section, footer {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 20px;
    padding: 24px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px rgba(15, 23, 42, 0.05);
  }
  .hero {
    background: linear-gradient(135deg, #0f172a 0%, #14213d 52%, #1d4ed8 100%);
    color: #fff;
    border: none;
  }
  .hero-kicker, .hero-sub, footer, .muted, .hero-label, .gauge-label, .bar-value { color: #cbd5e1; }
  .hero-row {
    display: flex;
    justify-content: space-between;
    gap: 16px;
    align-items: flex-start;
  }
  h1, h2, h3, p { margin-top: 0; }
  h1 { font-size: 2rem; margin-bottom: 12px; }
  h2 {
    font-size: 1.15rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 18px;
    color: var(--navy);
  }
  h3 { font-size: 1rem; margin-bottom: 14px; }
  p, li, td, th { line-height: 1.6; }
  .hero-grid, .panel-grid, .graph-grid, .mini-grid {
    display: grid;
    gap: 16px;
  }
  .hero-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 24px; }
  .panel-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .graph-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .mini-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .hero-stat, .panel, .chart-box, .mini-stat {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 16px;
    padding: 16px;
  }
  .panel, .chart-box, .mini-stat { background: #fff; border-color: var(--line); }
  .hero-value { font-size: 1.35rem; font-weight: 700; color: #fff; }
  .hero-label, .mini-label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }
  .mini-value { font-size: 1.25rem; font-weight: 700; color: var(--navy); }
  .risk-pill {
    padding: 10px 16px;
    border-radius: 999px;
    font-weight: 700;
    min-width: 140px;
    text-align: center;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    overflow: hidden;
    border-radius: 14px;
  }
  th, td {
    border: 1px solid var(--line);
    padding: 12px 14px;
    vertical-align: top;
  }
  th {
    background: #eff6ff;
    color: var(--navy);
    text-align: left;
  }
  .badge {
    display: inline-block;
    color: #fff;
    border-radius: 999px;
    padding: 6px 10px;
    font-size: 0.8rem;
    font-weight: 700;
  }
  .clean-list {
    margin: 0;
    padding-left: 18px;
  }
  .empty, .empty-graph { color: var(--muted); text-align: center; padding: 18px; }
  code, pre {
    font-family: Consolas, "Courier New", monospace;
  }
  pre {
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 14px;
    padding: 16px;
    overflow-x: auto;
  }
  .gauge-score, .donut-total {
    font-size: 14px;
    font-weight: 700;
    fill: var(--navy);
    text-anchor: middle;
    dominant-baseline: middle;
  }
  .bar-label, .bar-value {
    font-size: 10px;
    font-family: "Segoe UI", sans-serif;
    fill: var(--muted);
  }
  .donut-wrap {
    display: flex;
    align-items: center;
    gap: 14px;
    justify-content: center;
    flex-wrap: wrap;
  }
  .legend-item {
    font-size: 0.88rem;
    margin-bottom: 6px;
    color: var(--muted);
  }
  .legend-swatch {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 999px;
    margin-right: 8px;
  }
  footer {
    text-align: center;
    font-size: 0.88rem;
    color: var(--muted);
  }
  @media (max-width: 860px) {
    .hero-grid, .panel-grid, .graph-grid, .mini-grid {
      grid-template-columns: 1fr;
    }
    .hero-row {
      flex-direction: column;
    }
  }
  @media print {
    body { background: #fff; }
    .page { padding: 0; }
    section, footer { box-shadow: none; break-inside: avoid; }
  }
</style>
"""


def _write(path: str, content: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _esc(value) -> str:
    return html.escape(str(value))
