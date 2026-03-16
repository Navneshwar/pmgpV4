import streamlit as st
import os

def render_sidebar():
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

    return {
        "analysis_mode": analysis_mode,
        "root_path": root_path,
        "run_live": run_live,
        "run_disk": run_disk,
        "disk_path": disk_path,
        "save_reports": save_reports,
        "output_dir": output_dir,
        "run_btn": run_btn,
    }