"""
app.py  –  PMGP Streamlit Web Interface
Run with:  streamlit run app.py
"""

import streamlit as st
from ui.main import main

st.set_page_config(
    page_title="PMGP – Forensic Inspector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

if __name__ == "__main__":
    main()