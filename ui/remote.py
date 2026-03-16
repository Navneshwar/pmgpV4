import streamlit as st
import time as _time
import json as _json
from ui.config import _STATE_FILE, _POLL_INTERVAL, RISK_EMOJI
from modules.risk_classifier import RISK_COLOURS

def load_remote_state():
    if not _STATE_FILE.exists():
        return None
    try:
        return _json.loads(_STATE_FILE.read_text())
    except Exception:
        return None

def handle_remote_mode():
    _remote_state = load_remote_state()
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