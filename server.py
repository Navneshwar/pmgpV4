"""
server.py
PMGP Remote Ingestion Server
Receives a diagnostic bundle from a remote collector, extracts it into a
temporary filesystem tree, then runs the full PMGP analysis pipeline against it.
Results are written to a shared state file that the Streamlit app polls.

Run with:  python3 server.py
"""

import json
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify

sys.path.insert(0, os.path.dirname(__file__))

from modules.os_profiler import identify_os
from modules.tool_detector import correlate_tool_evidence, detect_tools
from modules.live_analyzer import analyze_live_system
from modules.risk_classifier import classify_risk
from modules.report_generator import generate_json_report, generate_html_report

app = Flask(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────
# The Streamlit app reads this file to know when a new result is ready.
STATE_FILE   = Path("remote_results/latest.json")
REPORTS_DIR  = Path("remote_results")
REPORTS_DIR.mkdir(exist_ok=True)

_processing_lock = threading.Lock()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/ingest", methods=["POST"])
def ingest():
    """Receive a diagnostic bundle and run PMGP analysis."""
    if "bundle" not in request.files:
        return jsonify({"error": "No bundle in request"}), 400

    bundle_file = request.files["bundle"]
    hostname    = request.form.get("hostname", "unknown")
    timestamp   = request.form.get("timestamp", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))

    print(f"\n[+] Bundle received from '{hostname}' at {timestamp}")

    # Save bundle temporarily
    tmp_bundle = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    bundle_file.save(tmp_bundle.name)
    tmp_bundle.close()

    # Process in background so Flask returns immediately
    thread = threading.Thread(
        target=_process_bundle,
        args=(tmp_bundle.name, hostname, timestamp),
        daemon=True,
    )
    thread.start()

    return jsonify({"status": "received", "hostname": hostname}), 200


@app.route("/status", methods=["GET"])
def status():
    """Streamlit polls this to check if a new result is ready."""
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            return jsonify(data), 200
        except Exception:
            pass
    return jsonify({"status": "waiting"}), 200


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "PMGP ingestion server running"}), 200


# ── Core processing ───────────────────────────────────────────────────────────

def _process_bundle(bundle_path: str, hostname: str, timestamp: str) -> None:
    with _processing_lock:
        extract_root = None
        try:
            print(f"[*] Extracting bundle from {hostname}…")
            extract_root = tempfile.mkdtemp(prefix="pmgp_remote_")
            _extract_bundle(bundle_path, extract_root)

            # The tarball contains one top-level directory (.diag_<pid>)
            # Find it and use it as the filesystem root for analysis
            entries = [
                e for e in os.listdir(extract_root)
                if os.path.isdir(os.path.join(extract_root, e))
            ]
            if not entries:
                print("[-] Bundle is empty or malformed")
                return

            fs_root = os.path.join(extract_root, entries[0])
            print(f"[*] Filesystem root: {fs_root}")

            # ── Reconstruct the virtual filesystem tree PMGP expects ────────
            vfs = _build_vfs(fs_root, extract_root)
            print(f"[*] Virtual filesystem ready at: {vfs}")

            # ── Run PMGP pipeline ────────────────────────────────────────────
            print("[*] Running OS profiler…")
            os_profile = identify_os(vfs)

            print("[*] Running tool detector…")
            tool_result = detect_tools(
                root_path=vfs,
                pkg_db_type=os_profile.pkg_db_type,
                pkg_db_path=os_profile.pkg_db_path,
            )

            print("[*] Running live analyzer…")
            live_result = _analyze_remote_proc(fs_root, vfs)

            tool_result = correlate_tool_evidence(
                os_profile,
                tool_result,
                live_result,
                observed_at=_parse_bundle_timestamp(timestamp),
            )

            print("[*] Running risk classifier…")
            risk_report = classify_risk(
                os_profile=os_profile,
                tool_result=tool_result,
                live_result=live_result,
            )

            print(f"[+] Analysis complete — {risk_report.overall_risk} risk, "
                  f"score {risk_report.risk_score}/100")

            # ── Save reports ─────────────────────────────────────────────────
            ts_safe  = timestamp.replace(":", "").replace("-", "")
            json_path = REPORTS_DIR / f"pmgp_{hostname}_{ts_safe}.json"
            html_path = REPORTS_DIR / f"pmgp_{hostname}_{ts_safe}.html"

            json_report = generate_json_report(
                os_profile, tool_result, risk_report, live_result,
                output_path=str(json_path),
            )
            html_report = generate_html_report(
                os_profile, tool_result, risk_report, live_result,
                output_path=str(html_path),
            )

            # ── Write state file for Streamlit to pick up ────────────────────
            state = {
                "status":       "ready",
                "hostname":     hostname,
                "timestamp":    timestamp,
                "overall_risk": risk_report.overall_risk,
                "risk_score":   risk_report.risk_score,
                "os_type":      os_profile.os_type.value,
                "confidence":   round(os_profile.confidence, 2),
                "tool_count":   len(tool_result.detected_tools),
                "kill_chains":  risk_report.kill_chains,
                "json_path":    str(json_path),
                "html_path":    str(html_path),
                "json_report":  json_report,
                "html_report":  html_report,
                "summary":      risk_report.summary_lines,
            }
            STATE_FILE.write_text(json.dumps(state, indent=2))
            print(f"[+] State file updated: {STATE_FILE}")

        except Exception as exc:
            import traceback
            print(f"[-] Processing error: {exc}")
            traceback.print_exc()
            STATE_FILE.write_text(json.dumps({
                "status":    "error",
                "hostname":  hostname,
                "timestamp": timestamp,
                "error":     str(exc),
            }))
        finally:
            # Clean up temp extraction directory
            if extract_root and os.path.isdir(extract_root):
                shutil.rmtree(extract_root, ignore_errors=True)
            os.unlink(bundle_path)


def _extract_bundle(bundle_path: str, dest: str) -> None:
    with tarfile.open(bundle_path, "r:gz") as tf:
        # Safety: strip absolute paths and prevent path traversal
        members = []
        for m in tf.getmembers():
            m.name = m.name.lstrip("/").replace("..", "__")
            members.append(m)
        tf.extractall(dest, members=members)


def _build_vfs(fs_root: str, base: str) -> str:
    """
    Reconstruct a virtual filesystem that mirrors what PMGP's modules expect.
    The collector stores files in categorized subdirs — we remap them to
    the standard Linux paths the modules look for.

    Returns path to the virtual root directory.
    """
    vfs = os.path.join(base, "vfs")
    os.makedirs(vfs, exist_ok=True)

    mappings = [
        # (source inside fs_root,          dest inside vfs)
        ("sys/os-release",                 "etc/os-release"),
        ("sys/cmdline",                    "proc/cmdline"),
        ("pkg/dpkg-status",                "var/lib/dpkg/status"),
        ("pkg/apt-sources.list",           "etc/apt/sources.list"),
        ("pkg/trusted.gpg",                "etc/apt/trusted.gpg"),
        ("conf/_etc_tor_torrc",            "etc/tor/torrc"),
        ("conf/_etc_proxychains.conf",     "etc/proxychains.conf"),
        ("conf/_etc_proxychains4.conf",    "etc/proxychains4.conf"),
        ("conf/_etc_hosts",                "etc/hosts"),
        ("conf/_etc_crontab",              "etc/crontab"),
        ("logs/dpkg.log",                  "var/log/dpkg.log"),
        ("logs/dpkg.log.1",                "var/log/dpkg.log.1"),
        ("logs/pacman.log",                "var/log/pacman.log"),
    ]

    for src_rel, dst_rel in mappings:
        src = os.path.join(fs_root, src_rel)
        dst = os.path.join(vfs, dst_rel)
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)

    # dpkg-status.d directory
    src_dir = os.path.join(fs_root, "pkg/dpkg-status.d")
    dst_dir = os.path.join(vfs, "var/lib/dpkg/status.d")
    if os.path.isdir(src_dir):
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)

    # apt sources.list.d
    src_dir = os.path.join(fs_root, "pkg/apt-sources.list.d")
    dst_dir = os.path.join(vfs, "etc/apt/sources.list.d")
    if os.path.isdir(src_dir):
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)

    # trusted.gpg.d
    src_dir = os.path.join(fs_root, "pkg/trusted.gpg.d")
    dst_dir = os.path.join(vfs, "etc/apt/trusted.gpg.d")
    if os.path.isdir(src_dir):
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)

    # pacman local db
    src_dir = os.path.join(fs_root, "pkg/pacman-local")
    dst_dir = os.path.join(vfs, "var/lib/pacman/local")
    if os.path.isdir(src_dir):
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)

    # Collector-provided path access/install metadata
    stats_src = os.path.join(fs_root, "fs/bin-stats.tsv")
    stats_dst = os.path.join(vfs, ".pmgp_path_stats.tsv")
    if os.path.isfile(stats_src):
        shutil.copy2(stats_src, stats_dst)

    # Shell histories → root home
    activity_dir = os.path.join(fs_root, "activity")
    if os.path.isdir(activity_dir):
        root_home = os.path.join(vfs, "root")
        os.makedirs(root_home, exist_ok=True)
        for fname in os.listdir(activity_dir):
            src = os.path.join(activity_dir, fname)
            # .bash_history.root → root/.bash_history
            if fname.endswith(".root"):
                base_name = "." + fname.replace(".root", "").lstrip(".")
                shutil.copy2(src, os.path.join(root_home, base_name))
            elif ".root" not in fname:
                # user history — put in /home/<user>/
                parts = fname.rsplit(".", 1)
                if len(parts) == 2:
                    hist_name, user = parts
                    user_home = os.path.join(vfs, "home", user)
                    os.makedirs(user_home, exist_ok=True)
                    shutil.copy2(src, os.path.join(user_home, "." + hist_name))

    # recently-used
    for fname in os.listdir(os.path.join(fs_root, "activity")) if os.path.isdir(
            os.path.join(fs_root, "activity")) else []:
        if "recently-used" in fname:
            if fname.endswith(".root"):
                dst = os.path.join(vfs, "root/.local/share")
                os.makedirs(dst, exist_ok=True)
                shutil.copy2(os.path.join(fs_root, "activity", fname),
                             os.path.join(dst, "recently-used.xbel"))

    # SSH artefacts
    ssh_src = os.path.join(fs_root, "ssh")
    if os.path.isdir(ssh_src):
        ssh_dst = os.path.join(vfs, "root/.ssh")
        os.makedirs(ssh_dst, exist_ok=True)
        for fname in os.listdir(ssh_src):
            src = os.path.join(ssh_src, fname)
            if os.path.isfile(src):
                base_name = fname.replace(".root", "")
                shutil.copy2(src, os.path.join(ssh_dst, base_name))

    # Cron jobs
    cron_src = os.path.join(fs_root, "conf/cron")
    if os.path.isdir(cron_src):
        for subdir in os.listdir(cron_src):
            # subdir name is mangled path e.g. _etc_cron.d
            real_path = subdir.replace("_", "/", 1).lstrip("/")
            dst_dir = os.path.join(vfs, real_path)
            os.makedirs(dst_dir, exist_ok=True)
            src_dir = os.path.join(cron_src, subdir)
            if os.path.isdir(src_dir):
                for f in os.listdir(src_dir):
                    shutil.copy2(os.path.join(src_dir, f),
                                 os.path.join(dst_dir, f))

    # Proc — build a flat /proc structure
    proc_vfs = os.path.join(vfs, "proc")
    os.makedirs(proc_vfs, exist_ok=True)
    _write_proc_version(proc_vfs)   # makes /proc/version so live_analyzer recognises it

    pid_src = os.path.join(fs_root, "proc/pids")
    if os.path.isdir(pid_src):
        for pid in os.listdir(pid_src):
            src_pid = os.path.join(pid_src, pid)
            dst_pid = os.path.join(proc_vfs, pid)
            if os.path.isdir(src_pid):
                os.makedirs(dst_pid, exist_ok=True)
                for f in ("comm", "cmdline", "environ", "maps"):
                    src_f = os.path.join(src_pid, f)
                    if os.path.isfile(src_f):
                        shutil.copy2(src_f, os.path.join(dst_pid, f))

    # Network
    net_src = os.path.join(fs_root, "net")
    if os.path.isdir(net_src):
        net_dst = os.path.join(proc_vfs, "net")
        os.makedirs(net_dst, exist_ok=True)
        for fname in ("tcp", "tcp6", "udp", "udp6"):
            src = os.path.join(net_src, fname)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(net_dst, fname))

    # Tails special paths — recreate as empty marker files
    special = os.path.join(fs_root, "fs/special-paths.txt")
    if os.path.isfile(special):
        for line in open(special).read().splitlines():
            line = line.strip().lstrip("/")
            if line:
                marker = os.path.join(vfs, line)
                os.makedirs(os.path.dirname(marker), exist_ok=True)
                open(marker, "w").close()

    return vfs


def _write_proc_version(proc_path: str) -> None:
    """Write a minimal /proc/version so live_analyzer knows this is a valid /proc."""
    version_path = os.path.join(proc_path, "version")
    if not os.path.exists(version_path):
        with open(version_path, "w") as f:
            f.write("Linux version (remote-collector)\n")


def _analyze_remote_proc(fs_root: str, vfs: str):
    """
    Run live_analyzer against the reconstructed /proc in the VFS.
    This handles remote proc data from the collector.
    """
    from modules.live_analyzer import analyze_live_system
    proc_path = os.path.join(vfs, "proc")
    if os.path.isdir(proc_path):
        return analyze_live_system(proc_path)
    return None


def _parse_bundle_timestamp(timestamp: str) -> float:
    try:
        return datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc
        ).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  PMGP Remote Ingestion Server")
    print("  Listening on 0.0.0.0:5000")
    print(f"  Results directory: {REPORTS_DIR.resolve()}")
    print("=" * 55)

    # Get and display local IP for convenience
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"\n  Share this with your collector:")
        print(f"  bash system-health-check.sh")
        print(f"  (SERVER_IP = {local_ip})")
        print(f"\n  Streamlit dashboard: streamlit run app_remote.py")
    except Exception:
        pass
    print()

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
