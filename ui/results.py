import streamlit as st
import datetime
from ui.config import RISK_EMOJI, RISK_GRADIENTS
from modules.risk_classifier import RISK_COLOURS

def show_results(result):
    rr     = result.risk_report
    colour = RISK_COLOURS.get(rr.overall_risk, "#333")
    op = result.os_profile
    tr = result.tool_result
    lr = result.live_result

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