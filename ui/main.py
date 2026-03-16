import streamlit as st
import time as _time
import os
import sys

# Add project root to sys.path so that pipeline and modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline import PipelineConfig, run_pipeline, PipelineResult
from modules.risk_classifier import RISK_COLOURS
from ui.styles import CSS
from ui.sidebar import render_sidebar
from ui.welcome import show_welcome
from ui.demo import run_demo
from ui.remote import handle_remote_mode
from ui.results import show_results
from ui.config import _STATE_FILE

def main():
    # Initialise remote session state
    if "remote_listening" not in st.session_state:
        st.session_state.remote_listening  = False
    if "remote_wait_start" not in st.session_state:
        st.session_state.remote_wait_start = None
    if "remote_last_ts" not in st.session_state:
        st.session_state.remote_last_ts    = None

    # Inject CSS
    st.markdown(CSS, unsafe_allow_html=True)

    # Render sidebar and get inputs
    sidebar_vals = render_sidebar()
    analysis_mode = sidebar_vals["analysis_mode"]
    root_path = sidebar_vals["root_path"]
    run_live = sidebar_vals["run_live"]
    run_disk = sidebar_vals["run_disk"]
    disk_path = sidebar_vals["disk_path"]
    save_reports = sidebar_vals["save_reports"]
    output_dir = sidebar_vals["output_dir"]
    run_btn = sidebar_vals["run_btn"]

    # Title
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
        show_welcome()
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
                result = run_demo()
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
        handle_remote_mode()
        st.stop()

    result: PipelineResult = st.session_state.get("last_result")
    if result is None:
        st.stop()

    if not result.success:
        st.error("Pipeline failed:\n" + "\n".join(result.errors))
        st.stop()

    # ── Results ───────────────────────────────────────────────────────────────────
    show_results(result)