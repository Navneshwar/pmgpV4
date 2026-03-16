import streamlit as st

def show_welcome():
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