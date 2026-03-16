# PMGP — Passive Metadata-Graph Protocol

Advanced OS-aware forensic inspection tool. Detects offensive toolkits and
suspicious environments without executing binaries, modifying evidence, or
decrypting encrypted data.

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Project Structure

```
pmgp/
├── app.py                    # Streamlit UI
├── pipeline.py               # Top-level orchestrator
├── requirements.txt
├── data/
│   └── tool_signatures.json  # MITRE-mapped offensive tool dictionary
└── modules/
    ├── os_profiler.py        # Stage 1: Heuristic OS identification
    ├── tool_detector.py      # Stage 2: Package DB cross-reference
    ├── live_analyzer.py      # Stage 3: /proc volatile artifact extraction
    ├── disk_analyzer.py      # Stage 4: GPT/MBR + LUKS structural analysis
    ├── risk_classifier.py    # Stage 5: MITRE ATT&CK risk scoring
    └── report_generator.py   # Stage 6: JSON + HTML report output
```

## Pipeline Stages

| Stage | Module | Description |
|-------|--------|-------------|
| 1 | `os_profiler` | Identifies OS (Kali/BlackArch/Tails) from package DB paths and structural markers |
| 2 | `tool_detector` | Cross-references dpkg/pacman packages against offensive tool signatures |
| 3 | `live_analyzer` | Scans /proc for LD_PRELOAD injection, attacker IPs, suspicious PATH entries |
| 4 | `disk_analyzer` | Reads GPT/MBR tables, probes for LUKS headers, detects TailsData partitions |
| 5 | `risk_classifier` | Aggregates findings, maps to MITRE ATT&CK, computes risk score 0–100 |
| 6 | `report_generator` | Outputs structured JSON + self-contained HTML forensic report |

## Analysis Modes

- **Demo** — Simulated Kali Linux system with 15 offensive tools, process injection, and TailsData partition
- **Live System** — Analyses the actual running machine's package database and /proc
- **Custom Root Path** — Analyses a mounted disk image (e.g., `/mnt/evidence`)

## Programmatic Usage

```python
from pipeline import PipelineConfig, run_pipeline

config = PipelineConfig(
    root_path="/mnt/evidence",
    run_live_analysis=False,
    disk_image_path="/path/to/disk.img",
    save_json=True,
    save_html=True,
    output_dir="reports/",
)

result = run_pipeline(config)
print(result.risk_report.overall_risk)   # "CRITICAL"
print(result.risk_report.risk_score)     # 0–100
print(result.json_report)                # full JSON string
```

## Forensic Principles

- **Non-destructive**: Never writes to the target filesystem
- **No execution**: No binaries from the target system are ever run
- **No decryption**: Encrypted partitions are identified structurally, not opened
- **Evidence integrity**: All reads are passive; no modification of any kind
"# pmgpV2" 
"# pmgpV4" 
