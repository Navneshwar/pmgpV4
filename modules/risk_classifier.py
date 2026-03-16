"""
modules/risk_classifier.py
Aggregates findings from all PMGP modules and produces a structured
risk assessment mapped to MITRE ATT&CK tactics and techniques.

Improvements over v1:
  - Tails disk cross-signal feeds OS confidence
  - Filesystem artefacts (shell history, SSH, cron, hosts) generate RiskItems
  - Network connections from live_analyzer generate RiskItems
  - Cmdline process matches generate RiskItems
  - Kill chain inference: detects multi-stage attack patterns
  - LUKS version awareness in disk risk items
"""

from dataclasses import dataclass, field
from typing import Optional

from modules.os_profiler import OSProfile, OSType
from modules.tool_detector import ToolDetectionResult, DetectedTool
from modules.live_analyzer import LiveAnalysisResult, NetworkConnection
from modules.disk_analyzer import DiskAnalysisResult


# ── Shared colour palette (used by report_generator and app.py) ──────────────
RISK_COLOURS = {
    "CRITICAL": "#d32f2f",
    "HIGH":     "#f57c00",
    "MEDIUM":   "#fbc02d",
    "LOW":      "#388e3c",
    "INFO":     "#1565c0",
}

RISK_BG = {
    "CRITICAL": "#ffebee",
    "HIGH":     "#fff3e0",
    "MEDIUM":   "#fffde7",
    "LOW":      "#e8f5e9",
    "INFO":     "#e3f2fd",
}

# ── MITRE ATT&CK tactic ordering ─────────────────────────────────────────────
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# Kill chain patterns: (name, required_categories, risk_bump, description)
# If all required MITRE categories are present in detected tools, a kill chain
# finding is added to the report.
KILL_CHAIN_PATTERNS = [
    (
        "Recon → Exploitation chain",
        {"Reconnaissance", "Exploitation"},
        "CRITICAL",
        "Reconnaissance tools paired with exploitation frameworks – active attack chain likely",
        "T1592",
    ),
    (
        "Credential Access → Lateral Movement chain",
        {"Credential Access", "Lateral Movement"},
        "CRITICAL",
        "Credential harvesting tools combined with lateral movement capabilities",
        "T1110",
    ),
    (
        "Exploitation + Command and Control chain",
        {"Exploitation", "Command and Control"},
        "CRITICAL",
        "Exploitation tools combined with C2/anonymization – post-exploitation setup detected",
        "T1210",
    ),
    (
        "Full kill chain (Recon → Exploitation → C2)",
        {"Reconnaissance", "Exploitation", "Command and Control"},
        "CRITICAL",
        "Complete offensive kill chain detected: recon, exploitation, and C2 tools all present",
        "T1592",
    ),
    (
        "Anonymization + Offensive tooling",
        {"Command and Control", "Credential Access"},
        "HIGH",
        "Anonymization infrastructure combined with credential-access tools",
        "T1090",
    ),
]


@dataclass
class RiskItem:
    source:          str    # "tool" | "process" | "disk" | "os" | "artefact" | "network" | "killchain"
    risk_level:      str    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    title:           str
    description:     str
    mitre_technique: str = ""
    mitre_category:  str = ""
    evidence:        str = ""


@dataclass
class MitreEntry:
    technique_id:   str
    technique_name: str
    tactic:         str
    tools:          list[str] = field(default_factory=list)


@dataclass
class RiskReport:
    overall_risk:    str
    risk_score:      int
    items:           list[RiskItem]   = field(default_factory=list)
    mitre_coverage:  list[MitreEntry] = field(default_factory=list)
    summary_lines:   list[str]        = field(default_factory=list)
    kill_chains:     list[str]        = field(default_factory=list)
    time_of_attack:  str              = "Not determined"

    @property
    def items_by_level(self) -> dict[str, list[RiskItem]]:
        out: dict[str, list[RiskItem]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []
        }
        for item in self.items:
            out.setdefault(item.risk_level, []).append(item)
        return out


# ── Public entry-point ────────────────────────────────────────────────────────

def classify_risk(
    os_profile:  OSProfile,
    tool_result: ToolDetectionResult,
    live_result: Optional[LiveAnalysisResult] = None,
    disk_result: Optional[DiskAnalysisResult] = None,
) -> RiskReport:
    items:     list[RiskItem]   = []
    mitre_map: dict[str, MitreEntry] = {}

    # ── Tails cross-signal: disk confirms OS ─────────────────────────────
    if disk_result and disk_result.tails_data_found:
        if os_profile.os_type != OSType.TAILS_OS:
            # Disk found TailsData but OS profiler didn't detect Tails markers
            # (amnesic boot) – add a high-confidence indicator
            os_profile.indicators.append(
                "TailsData LUKS partition confirmed by disk analyzer "
                "(Tails amnesic system – in-memory markers absent)"
            )
            os_profile.confidence = max(os_profile.confidence, 0.85)
        else:
            os_profile.tails_disk_confirmed = True
            os_profile.confidence = min(os_profile.confidence + 0.1, 1.0)

    # ── OS profile risk ───────────────────────────────────────────────────
    items.extend(_os_risk_items(os_profile))

    # ── Tool detection risk ───────────────────────────────────────────────
    for tool in tool_result.detected_tools:
        items.append(_tool_to_risk_item(tool))
        _register_mitre(mitre_map, tool)

    # ── Filesystem artefact risk ──────────────────────────────────────────
    for artefact in os_profile.filesystem_artefacts:
        mitre_tech, mitre_cat = _artefact_mitre(artefact.artefact_type)
        items.append(RiskItem(
            source="artefact",
            risk_level=artefact.risk_level,
            title=f"Filesystem artefact: {artefact.path}",
            description=artefact.description,
            mitre_technique=mitre_tech,
            mitre_category=mitre_cat,
            evidence=f"Path: {artefact.path}"
                     + (f" | Snippet: {artefact.snippet}" if artefact.snippet else ""),
        ))

    # ── Live process risk ─────────────────────────────────────────────────
    if live_result and live_result.is_live_system:
        for pf in live_result.process_findings:
            for var, val in pf.suspicious_vars.items():
                items.append(RiskItem(
                    source="process",
                    risk_level="HIGH",
                    title=f"Suspicious env var in PID {pf.pid} ({pf.comm})",
                    description=f"{var}={val[:120]}",
                    mitre_technique="T1574.006",
                    mitre_category="Defense Evasion",
                    evidence=f"/proc/{pf.pid}/environ",
                ))
            for var, val in pf.attacker_ips.items():
                items.append(RiskItem(
                    source="process",
                    risk_level="HIGH",
                    title=f"Non-private origin IP in PID {pf.pid} ({pf.comm})",
                    description=f"{var}={val}",
                    mitre_technique="T1071",
                    mitre_category="Command and Control",
                    evidence=f"/proc/{pf.pid}/environ",
                ))
            for path in pf.suspicious_paths:
                items.append(RiskItem(
                    source="process",
                    risk_level="MEDIUM",
                    title=f"Suspicious PATH dir in PID {pf.pid} ({pf.comm})",
                    description=f"PATH includes: {path}",
                    mitre_technique="T1574",
                    mitre_category="Defense Evasion",
                    evidence=f"/proc/{pf.pid}/environ",
                ))
            for mapped_path in pf.suspicious_maps:
                items.append(RiskItem(
                    source="process",
                    risk_level="HIGH",
                    title=f"Suspicious memory-mapped file in PID {pf.pid} ({pf.comm})",
                    description=f"Mapped: {mapped_path}",
                    mitre_technique="T1574.002",
                    mitre_category="Defense Evasion",
                    evidence=f"/proc/{pf.pid}/maps",
                ))
            for note, technique, category in pf.cmdline_matches:
                items.append(RiskItem(
                    source="process",
                    risk_level="HIGH",
                    title=f"Offensive tool running: PID {pf.pid} ({pf.comm})",
                    description=note + (f" — {pf.cmdline[:100]}" if pf.cmdline else ""),
                    mitre_technique=technique,
                    mitre_category=category,
                    evidence=f"/proc/{pf.pid}/cmdline",
                ))
                _register_mitre_raw(mitre_map, technique, note, category, pf.comm)

        # ── Network connection risk ───────────────────────────────────────
        for conn in live_result.suspicious_connections:
            items.append(RiskItem(
                source="network",
                risk_level="HIGH",
                title=f"Suspicious outbound {conn.protocol.upper()} connection",
                description=(
                    f"{conn.local_addr}:{conn.local_port} → "
                    f"{conn.remote_addr}:{conn.remote_port} [{conn.state}]"
                ),
                mitre_technique="T1071",
                mitre_category="Command and Control",
                evidence=f"/proc/net/{conn.protocol}",
            ))

    # ── Disk analysis risk ────────────────────────────────────────────────
    if disk_result:
        for partition in disk_result.encrypted_partitions:
            level   = "HIGH" if partition.risk_label == "HIGH" else "MEDIUM"
            ver_tag = f" ({partition.luks_version})" if partition.luks_version else ""
            items.append(RiskItem(
                source="disk",
                risk_level=level,
                title=f"Encrypted partition: {partition.label!r}{ver_tag}",
                description=partition.risk_note,
                mitre_technique="T1486" if level == "HIGH" else "",
                mitre_category="Impact",
                evidence=f"Partition {partition.index}, LBA {partition.start_lba}",
            ))
        if disk_result.tails_data_found:
            items.append(RiskItem(
                source="disk",
                risk_level="HIGH",
                title="TailsData persistent storage partition found",
                description=(
                    "Indicates Tails OS with persistent encrypted storage. "
                    "Strongly associated with anonymized operations."
                ),
                mitre_technique="T1036",
                mitre_category="Defense Evasion",
            ))

    # ── Kill chain inference ──────────────────────────────────────────────
    present_categories = {t.category for t in tool_result.detected_tools}
    kill_chains_found: list[str] = []

    for chain_name, required, risk_level, description, technique in KILL_CHAIN_PATTERNS:
        if required.issubset(present_categories):
            items.append(RiskItem(
                source="killchain",
                risk_level=risk_level,
                title=f"Kill chain pattern: {chain_name}",
                description=description,
                mitre_technique=technique,
                mitre_category="Multiple",
                evidence="Inferred from tool combination: " + ", ".join(sorted(required)),
            ))
            kill_chains_found.append(chain_name)

    # ── Score & overall level ─────────────────────────────────────────────
    score   = _compute_score(items)
    overall = _score_to_level(score)
    summary = _build_summary(
        os_profile, tool_result, live_result, disk_result,
        score, overall, kill_chains_found,
    )

    # ── Estimated Time of Attack ──────────────────────────────────────────
    attack_time = "No attack detected"
    if items:
        import os
        from datetime import datetime, timezone
        
        timestamps = []
        if tool_result:
            for t in tool_result.detected_tools:
                if t.mtime:
                    timestamps.append(t.mtime)
            for p in tool_result.filesystem_hits + tool_result.config_hits:
                if os.path.exists(p):
                    try:
                        timestamps.append(os.path.getmtime(p))
                    except OSError:
                        pass
        
        # Fallbacks to get some reference time
        if not timestamps and os_profile and os_profile.pkg_db_path and os.path.exists(os_profile.pkg_db_path):
            try:
                timestamps.append(os.path.getmtime(os_profile.pkg_db_path))
            except OSError:
                pass
                
        if timestamps:
            earliest_ts = min(timestamps) # Oldest tool/config modification time
            attack_time = datetime.fromtimestamp(earliest_ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC (Extracted)")
        elif kill_chains_found or overall in ("CRITICAL", "HIGH"):
            attack_time = "Requires deeper timeline analysis (MACB)"
    
    return RiskReport(
        overall_risk=overall,
        risk_score=score,
        items=items,
        mitre_coverage=sorted(
            mitre_map.values(),
            key=lambda e: TACTIC_ORDER.index(e.tactic)
            if e.tactic in TACTIC_ORDER else 99,
        ),
        summary_lines=summary,
        kill_chains=kill_chains_found,
        time_of_attack=attack_time,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _os_risk_items(profile: OSProfile) -> list[RiskItem]:
    os_risk_map = {
        OSType.KALI_LINUX:      ("HIGH",  "Kali Linux – offensive security distribution detected"),
        OSType.BLACKARCH_LINUX: ("HIGH",  "BlackArch Linux – penetration testing distro detected"),
        OSType.TAILS_OS:        ("HIGH",  "Tails OS – anonymity-focused OS detected"),
        OSType.DEBIAN:          ("LOW",   "Standard Debian/Ubuntu system"),
        OSType.ARCH_LINUX:      ("LOW",   "Standard Arch Linux system"),
        OSType.UNKNOWN:         ("INFO",  "Operating system could not be determined"),
    }
    level, description = os_risk_map.get(profile.os_type, ("INFO", str(profile.os_type)))
    return [RiskItem(
        source="os",
        risk_level=level,
        title=f"OS Identified: {profile.os_type.value}",
        description=description + f" (confidence: {profile.confidence:.0%})",
        evidence="; ".join(profile.indicators),
    )]


def _tool_to_risk_item(tool: DetectedTool) -> RiskItem:
    level_map = {
        "high_risk":     "CRITICAL",
        "dual_use":      "MEDIUM",
        "anonymization": "HIGH",
    }
    method_tag = {
        "package_db": "",
        "filesystem": " [binary found outside package manager]",
        "config":     " [configuration trace found]",
        "removed_package": " [package logs show the tool was removed after installation]",
    }.get(tool.detection_method, "")

    if tool.detection_method == "removed_package":
        evidence = f"Package log evidence: {tool.matched_package}"
        if tool.removal_time_source:
            evidence += f" | Removal source: {tool.removal_time_source}"
    else:
        evidence = f"{'Package' if tool.detection_method == 'package_db' else 'Path'}: {tool.matched_package}"

    return RiskItem(
        source="tool",
        risk_level=level_map.get(tool.risk_level, "MEDIUM"),
        title=f"{tool.name} ({tool.matched_package})",
        description=tool.description + method_tag,
        mitre_technique=tool.mitre_technique.split(" ")[0] if tool.mitre_technique else "",
        mitre_category=tool.category,
        evidence=evidence,
    )


def _artefact_mitre(artefact_type: str) -> tuple[str, str]:
    return {
        "shell_history": ("T1552.003", "Credential Access"),
        "ssh_key":       ("T1021.004", "Lateral Movement"),
        "cron":          ("T1053.003", "Persistence"),
        "hosts_mod":     ("T1583.001", "Resource Development"),
        "recent_files":  ("T1074",     "Collection"),
    }.get(artefact_type, ("", ""))


def _register_mitre(mitre_map: dict, tool: DetectedTool) -> None:
    if not tool.mitre_technique:
        return
    tech_id = tool.mitre_technique.split(" ")[0]
    if tech_id not in mitre_map:
        parts = tool.mitre_technique.split(" - ", 1)
        mitre_map[tech_id] = MitreEntry(
            technique_id=tech_id,
            technique_name=parts[1] if len(parts) > 1 else tech_id,
            tactic=tool.category,
        )
    mitre_map[tech_id].tools.append(tool.name)


def _register_mitre_raw(
    mitre_map: dict,
    technique_id: str,
    name: str,
    tactic: str,
    tool_name: str,
) -> None:
    if technique_id not in mitre_map:
        mitre_map[technique_id] = MitreEntry(
            technique_id=technique_id,
            technique_name=name,
            tactic=tactic,
        )
    mitre_map[technique_id].tools.append(tool_name)


def _compute_score(items: list[RiskItem]) -> int:
    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    raw = sum(weights.get(i.risk_level, 0) for i in items)
    return min(raw, 100)


def _score_to_level(score: int) -> str:
    if score >= 60: return "CRITICAL"
    if score >= 35: return "HIGH"
    if score >= 15: return "MEDIUM"
    if score > 0:   return "LOW"
    return "INFO"


def _build_summary(
    os_profile, tool_result, live_result, disk_result,
    score, overall, kill_chains,
) -> list[str]:
    lines = [
        f"Overall Risk: {overall} (score {score}/100)",
        f"OS: {os_profile.os_type.value} (confidence {os_profile.confidence:.0%})",
        f"Packages scanned: {tool_result.total_packages_scanned}",
        f"Suspicious tools detected: {len(tool_result.detected_tools)} "
        f"({tool_result.risk_counts.get('high_risk', 0)} high-risk, "
        f"{tool_result.risk_counts.get('dual_use', 0)} dual-use, "
        f"{tool_result.risk_counts.get('anonymization', 0)} anonymization)",
    ]
    if tool_result.filesystem_hits:
        lines.append(
            f"Filesystem tool paths found (non-packaged): {len(tool_result.filesystem_hits)}"
        )
    if tool_result.config_hits:
        lines.append(f"Configuration traces found: {len(tool_result.config_hits)}")
    removed_tools = [tool for tool in tool_result.detected_tools if not tool.present_on_disk]
    if removed_tools:
        lines.append(f"Historically installed but removed tools: {len(removed_tools)}")
    if os_profile.filesystem_artefacts:
        lines.append(
            f"Filesystem artefacts: {len(os_profile.filesystem_artefacts)} "
            f"(shell history, SSH keys, cron jobs, hosts modifications)"
        )
    if live_result and live_result.is_live_system:
        lines.append(
            f"Live processes scanned: {live_result.total_processes_scanned} "
            f"({len(live_result.process_findings)} with suspicious indicators)"
        )
        if live_result.suspicious_connections:
            lines.append(
                f"Suspicious network connections: {len(live_result.suspicious_connections)}"
            )
    if disk_result and not disk_result.error_message:
        lines.append(
            f"Partitions found: {len(disk_result.partitions)} "
            f"({len(disk_result.encrypted_partitions)} encrypted)"
        )
    if kill_chains:
        lines.append(f"Kill chain patterns detected: {', '.join(kill_chains)}")
    return lines
