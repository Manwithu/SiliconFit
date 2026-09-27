"""SiliconFit Secure — 16-tab professional developer workflow platform.

All results come from the backend modules (Phases 1–9).
Nothing is fabricated.  No cloud AI.  No Ollama.  No Granite.
"""

import streamlit as st
from pathlib import Path

from project_scan import scan_project
from recommendations import recommend_stack
from workflow import build_workflow
from test_runner import run_tests, discover_tests
from benchmark import run_benchmark
from security import security_scan, scan_text
from debugger import debug_scan
from processor_fit import processor_fit, analyse_source, TARGETS, LANGUAGES
from dependencies import dependency_scan
from deployment import deployment_assessment
from release_gate import release_assessment
from report import build_report
from language_tools import language_from_filename, language_advisor, basic_source_stats
from public_security_db import get_all as db_get_all, search as db_search
from developer_chat import answer as chat_answer
from commit_message import generate as gen_commit, TYPES as COMMIT_TYPES
from test_scaffold import generate_test_template
from result_utils import safe_get

# ──────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SiliconFit Secure",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────────────
# THEME — dark navy / blue, card-based, no external assets
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
:root{
  --bg:#060d1a; --panel:#0d1b2e; --panel-2:#11213a; --border:#1c3252;
  --blue:#2f6fed; --blue-hover:#4c85ff; --blue-soft:#12294d;
  --text:#e6edf7; --muted:#8ea3c4; --good:#22c55e; --warn:#f5b942; --bad:#ef4444;
}
html, body, .stApp{ background:var(--bg) !important; color:var(--text); }
.block-container{ max-width:1440px; padding-top:1.4rem; padding-bottom:3rem; }

h1, h2, h3, h4 { color:var(--text) !important; letter-spacing:.2px; }
h1{ font-weight:800 !important; }
.subtitle{ color:var(--muted); font-size:1.02rem; margin-top:-8px; margin-bottom:1.2rem; }
hr { border-color:var(--border); }

section[data-testid="stSidebar"]{ background:linear-gradient(180deg,#081326,#050b16); border-right:1px solid var(--border); }
section[data-testid="stSidebar"] *{ color:var(--text) !important; }

button[data-baseweb="tab"]{ color:var(--muted) !important; font-weight:600; font-size:.84rem; }
button[data-baseweb="tab"][aria-selected="true"]{ color:var(--blue-hover) !important; border-bottom-color:var(--blue-hover) !important; }
div[data-baseweb="tab-list"]{ gap:2px; border-bottom:1px solid var(--border); flex-wrap:wrap; }

.stButton>button, .stDownloadButton>button{
  background:var(--blue); color:#ffffff; border:1px solid #3a7bff;
  border-radius:10px; padding:.5rem 1rem; font-weight:600;
  transition:background .15s ease, transform .05s ease;
}
.stButton>button:hover,.stDownloadButton>button:hover{ background:var(--blue-hover); border-color:var(--blue-hover); }
.stButton>button:active{ transform:scale(.98); }

[data-testid="stMetric"]{
  background:var(--panel); border:1px solid var(--border); border-radius:14px;
  padding:12px 15px;
}
[data-testid="stMetricLabel"]{ color:var(--muted) !important; font-size:.8rem; }
[data-testid="stMetricValue"]{ color:var(--text) !important; }

.stTextInput input,.stTextArea textarea,.stNumberInput input,
.stSelectbox div[data-baseweb="select"]>div{
  background:var(--panel-2) !important; color:var(--text) !important;
  border:1px solid var(--border) !important; border-radius:10px !important;
}

.sf-card{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:16px 18px; margin:8px 0; }
.sf-card h3,.sf-card h4{ margin-top:0; }
.sf-card code{ background:var(--panel-2); padding:2px 6px; border-radius:6px; }
.sf-muted{ color:var(--muted); }

.pill{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:.76rem; font-weight:700; letter-spacing:.3px; }
.pill-pass{ background:rgba(34,197,94,.15); color:var(--good); border:1px solid rgba(34,197,94,.4); }
.pill-warn{ background:rgba(245,185,66,.15); color:var(--warn); border:1px solid rgba(245,185,66,.4); }
.pill-block{ background:rgba(239,68,68,.15); color:var(--bad); border:1px solid rgba(239,68,68,.4); }
.pill-info{ background:var(--blue-soft); color:var(--blue-hover); border:1px solid #29416b; }

[data-testid="stDataFrame"]{ border:1px solid var(--border); border-radius:12px; overflow:hidden; }

.sf-hero{
  background:linear-gradient(135deg, var(--blue-soft), var(--panel));
  border:1px solid var(--border); border-radius:18px; padding:20px 26px; margin-bottom:16px;
}

.sf-workflow{
  display:flex; gap:8px; flex-wrap:wrap; padding:10px 0; margin-bottom:4px;
}
.sf-workflow-step{
  background:var(--blue-soft); border:1px solid #29416b; border-radius:20px;
  padding:5px 14px; font-size:.82rem; font-weight:700; color:var(--blue-hover);
}
.sf-workflow-arrow{
  color:var(--muted); line-height:2.1; font-size:1rem;
}
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def pill(status: str) -> str:
    status = (status or "").upper().strip()
    cls = {
        "PASS": "pill-pass", "READY FOR REVIEW": "pill-pass", "OK": "pill-pass",
        "WARN": "pill-warn", "REVIEW": "pill-warn", "WARNING": "pill-warn",
        "FAIL": "pill-block", "BLOCK": "pill-block", "BLOCKED": "pill-block",
        "ERROR": "pill-block", "HIGH": "pill-block",
        "MEDIUM": "pill-warn", "LOW": "pill-warn",
        "STRONG": "pill-pass", "PARTIAL": "pill-warn", "UNSUPPORTED": "pill-block",
    }.get(status, "pill-info")
    return f'<span class="pill {cls}">{status or "UNKNOWN"}</span>'


def card(html: str) -> None:
    st.markdown(f'<div class="sf-card">{html}</div>', unsafe_allow_html=True)


def workflow_banner() -> None:
    steps = ["Security", "Debug", "Fix", "Test", "Optimize", "Verify", "Release"]
    parts = []
    for i, s in enumerate(steps):
        parts.append(f'<span class="sf-workflow-step">{s}</span>')
        if i < len(steps) - 1:
            parts.append('<span class="sf-workflow-arrow">→</span>')
    st.markdown(f'<div class="sf-workflow">{"".join(parts)}</div>', unsafe_allow_html=True)


def _session_ctx() -> dict:
    """Build a context dict from cached session state for report / release gate."""
    return {
        "last_test_run": st.session_state.get("last_test_run"),
        "last_benchmark": st.session_state.get("last_benchmark"),
        "last_debug_scan": st.session_state.get("last_debug_scan"),
        "last_processor_fit": st.session_state.get("last_processor_fit"),
        "last_security_scan": st.session_state.get("last_security_scan"),
    }


# ──────────────────────────────────────────────────────────────────────────────
# HEADER
# ──────────────────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="sf-hero">'
    '<h1>🛡️ SiliconFit Secure</h1>'
    '<div class="subtitle">Deterministic developer workflow — every result is measured, scanned or explicitly marked unavailable.</div>'
    '<span class="sf-muted">Local-first · No cloud AI · No fabricated results · No Ollama · No Granite</span>'
    '</div>',
    unsafe_allow_html=True,
)

workflow_banner()

# ──────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 📁 Project")
    project_path = st.text_input("Project folder", str(Path.cwd()), key="project_path")
    if st.button("Scan project", type="primary", key="sidebar_scan"):
        try:
            st.session_state["scan"] = scan_project(Path(project_path).expanduser())
        except Exception as e:
            st.error(f"Scan failed: {e}")
    s = st.session_state.get("scan")
    if s:
        st.caption(
            f"**{s['file_count']} files** · "
            f"{', '.join(s['languages'][:4]) or 'no languages'}"
        )
    st.divider()
    st.caption("🔒 Fully local engine — no network calls, no secrets transmitted.")

p = Path(project_path).expanduser()

# ──────────────────────────────────────────────────────────────────────────────
# TABS  (16 tabs)
# ──────────────────────────────────────────────────────────────────────────────
tabs = st.tabs([
    "📊 Dashboard",          # 0
    "📂 Upload & Analyze",   # 1
    "🖥️ Processor Fit",      # 2
    "🐛 Debug & Fix",        # 3
    "🧪 Tests",              # 4
    "⚡ Benchmark",           # 5
    "🔒 Security",           # 6
    "🌐 Public Security DB", # 7
    "🤖 Bob 2.0",            # 8
    "💬 Developer Chat",     # 9
    "📖 Documentation",      # 10
    "✍️ Commit Message",     # 11
    "📦 Dependencies",       # 12
    "🚀 Deployment",         # 13
    "🚦 Release Gate",       # 14
    "📋 Report",             # 15
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 0 — DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tabs[0]:
    st.subheader("Developer Command Centre")
    st.caption("Summary of all checks run in this session. Use the sidebar to point at a project folder.")

    s = st.session_state.get("scan")
    tr = st.session_state.get("last_test_run")
    sec = st.session_state.get("last_security_scan")
    bm = st.session_state.get("last_benchmark")
    dbg = st.session_state.get("last_debug_scan")
    pf = st.session_state.get("last_processor_fit")
    rg = st.session_state.get("last_release")

    # top-row metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Files scanned", safe_get(s, "file_count", "—"))
    c2.metric("Test passed", safe_get(tr, "passed", "—"))
    c3.metric("Security HIGH", safe_get(sec, "high", "—"))
    c4.metric("Debug findings", safe_get(dbg, "count", "—"))
    c5.metric("Benchmark median", f"{safe_get(bm, 'median', 0):.3f}s" if bm and safe_get(bm, "status") == "ok" else "—")

    st.divider()

    # status row
    col_a, col_b, col_c, col_d = st.columns(4)
    with col_a:
        test_st = safe_get(tr, "execution_status", "NOT RUN")
        st.markdown(f"**Tests** &nbsp; {pill(test_st)}", unsafe_allow_html=True)
    with col_b:
        sec_st = "PASS" if sec and safe_get(sec, "high", 0) == 0 else ("BLOCK" if sec else "NOT RUN")
        st.markdown(f"**Security** &nbsp; {pill(sec_st)}", unsafe_allow_html=True)
    with col_c:
        dbg_st = "PASS" if dbg and safe_get(dbg, "high", 0) == 0 else ("WARN" if dbg else "NOT RUN")
        st.markdown(f"**Debug** &nbsp; {pill(dbg_st)}", unsafe_allow_html=True)
    with col_d:
        rg_st = safe_get(rg, "state", "NOT RUN")
        st.markdown(f"**Release Gate** &nbsp; {pill(rg_st)}", unsafe_allow_html=True)

    if s:
        card(
            f"<b>Languages:</b> {', '.join(s['languages']) or 'None'}<br>"
            f"<b>Entry points:</b> {', '.join(s['entry_points']) or 'Not detected'}<br>"
            f"<b>Project files:</b> {', '.join(s['project_files']) or 'None detected'}"
        )
    else:
        st.info("Scan a project from the sidebar to populate the dashboard.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — UPLOAD & ANALYZE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[1]:
    st.subheader("Upload & Analyze")
    st.caption(
        "Drop one or more source files for an instant language, size, security and debug snapshot. "
        "No project folder required."
    )

    uploaded = st.file_uploader(
        "Upload source file(s)",
        accept_multiple_files=True,
        type=None,
        key="upload_files",
    )
    goal = st.text_input(
        "Optional: describe the code's purpose (used by the Language Advisor)",
        placeholder="e.g. backend, embedded firmware, AI/ML, high performance",
        key="upload_goal",
    )
    target_upload = st.selectbox("Optional: target processor", ["(none)"] + TARGETS, key="upload_target")

    if uploaded:
        results = []
        for f in uploaded:
            try:
                raw = f.getvalue()
                text = raw.decode("utf-8", errors="ignore")
            except Exception as e:
                st.error(f"Could not read {f.name}: {e}")
                continue
            lang = language_from_filename(f.name)
            stats = basic_source_stats(text)
            sec = scan_text(f.name, text)
            dbg = debug_scan(f.name, text)
            tgt = None if target_upload == "(none)" else target_upload
            pf = analyse_source(f.name, text, tgt) if tgt else None
            results.append({
                "name": f.name, "language": lang, "stats": stats,
                "security": sec, "debug": dbg, "processor": pf, "text": text,
            })
        st.session_state["uploaded_results"] = results

    results = st.session_state.get("uploaded_results", [])
    if results:
        st.markdown(f"**{len(results)} file(s) analyzed**")
        for r in results:
            sec = r.get("security", {}) or {}
            dbg = r.get("debug", {}) or {}
            stats = r.get("stats", {}) or {}
            with st.expander(f"📄 {r['name']}  —  {r.get('language','Unknown')}", expanded=len(results) == 1):
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Lines", stats.get("total_lines", 0))
                m2.metric("Non-blank", stats.get("non_blank_lines", 0))
                m3.metric("TODO/FIXME", stats.get("todo_fixme_count", 0))
                m4.metric("Sec score", sec.get("score", "N/A"))
                m5.metric("Debug findings", dbg.get("count", 0))

                # Security summary
                sec_findings = sec.get("findings", [])
                if sec_findings:
                    st.markdown(
                        f"**Security** {pill('BLOCK' if sec.get('high',0)>0 else 'WARN')} "
                        f"&nbsp; {len(sec_findings)} finding(s)",
                        unsafe_allow_html=True,
                    )
                    st.dataframe(
                        [{"severity": f.get("severity"), "title": f.get("title"),
                          "line": f.get("line"), "reason": f.get("reason")}
                         for f in sec_findings],
                        use_container_width=True,
                    )
                else:
                    st.markdown(f"**Security** {pill('PASS')} &nbsp; No pattern-based findings.", unsafe_allow_html=True)

                # Debug summary
                dbg_findings = dbg.get("findings", [])
                if dbg_findings:
                    st.markdown(
                        f"**Debug** {pill('BLOCK' if dbg.get('high',0)>0 else 'WARN')} "
                        f"&nbsp; {len(dbg_findings)} finding(s)",
                        unsafe_allow_html=True,
                    )
                    with st.expander("Debug findings detail"):
                        st.dataframe(
                            [{"severity": f.get("severity"), "title": f.get("title"),
                              "line": f.get("line"), "confidence": f.get("confidence"),
                              "category": f.get("category")}
                             for f in dbg_findings],
                            use_container_width=True,
                        )
                else:
                    st.markdown(f"**Debug** {pill('PASS')} &nbsp; No heuristic debug findings.", unsafe_allow_html=True)

                # Processor analysis
                pf_res = r.get("processor")
                if pf_res:
                    obs = safe_get(pf_res, "observations", [])
                    recs = safe_get(pf_res, "recommendations", [])
                    card(
                        f"<b>Processor Analysis</b> — Target: <code>{pf_res.get('target','?')}</code><br>"
                        f"Observations: {len(obs)} · Recommendations: {len(recs)}<br>"
                        + (f"<ul>{''.join(f'<li>{o}</li>' for o in obs[:3])}</ul>" if obs else "")
                    )

                # Language advisor
                if goal.strip():
                    adv = language_advisor(goal, r.get("language", "Unknown"))
                    fit_p = "PASS" if adv.get("well_suited") else ("INFO" if adv.get("well_suited") is None else "WARN")
                    card(
                        f"<b>Language Advisor</b> {pill(fit_p)}<br>"
                        f"Goal: <code>{adv.get('goal')}</code> · Current: <code>{adv.get('current_language')}</code><br>"
                        f"{adv.get('reason','Not available')}"
                        + (f"<br>Alternatives: {', '.join(adv.get('suggested_alternatives', []))}" if adv.get("suggested_alternatives") else ""),
                        unsafe_allow_html=False,
                    )

                with st.popover("View source (first 20 000 chars)"):
                    st.code(r.get("text", "")[:20000], language=None)

        st.caption(
            "⚠️ Security and debug findings are static pattern analysis only. "
            "They are advisory — not proof that a vulnerability exists or that code is safe."
        )
    else:
        st.info("No files uploaded yet.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — PROCESSOR FIT
# ══════════════════════════════════════════════════════════════════════════════
with tabs[2]:
    st.subheader("Processor Fit Assessment")
    st.caption(
        "Static toolchain-support matrix — NOT a performance benchmark. "
        "Source: publicly documented toolchain and platform support facts."
    )

    pf_lang = st.selectbox("Language", LANGUAGES, key="pf_lang")
    pf_target = st.selectbox("Target processor", TARGETS, key="pf_target")

    if st.button("Assess fit", type="primary", key="pf_btn"):
        result = processor_fit(pf_lang, pf_target)
        st.session_state["last_processor_fit"] = result
        fit = safe_get(result, "fit", "UNKNOWN")
        st.markdown(
            f"### {pill(fit)} &nbsp; {pf_lang} on {pf_target}",
            unsafe_allow_html=True,
        )
        card(
            f"<b>Fit:</b> {fit}<br>"
            f"<b>Reason:</b> {safe_get(result, 'reason', 'No reason available.')}<br>"
            f"<b>Analysis type:</b> {safe_get(result, 'analysis_type', 'STATIC_ANALYSIS')}"
        )
        notes = safe_get(result, "notes", [])
        if notes:
            with st.expander("Advisory notes"):
                for n in notes:
                    st.write("•", n)
        st.caption(safe_get(result, "disclaimer", ""))

    st.divider()
    st.markdown("#### All-target comparison")
    if st.button("Compare all targets", key="pf_all_btn"):
        rows = []
        for t in TARGETS:
            r = processor_fit(pf_lang, t)
            rows.append({"Target": t, "Fit": r.get("fit", "?"), "Summary": r.get("reason", "")[:120]})
        st.dataframe(rows, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — DEBUG & FIX
# ══════════════════════════════════════════════════════════════════════════════
with tabs[3]:
    st.subheader("Debug & Fix Workflow")
    st.caption(
        "Static heuristic analysis. Findings are ADVISORY — not proof of bugs. "
        "No code is executed or auto-modified."
    )

    dbg_src = st.radio("Source", ["Uploaded files (from Upload & Analyze)", "Paste code"], key="dbg_src")

    dbg_result = None
    if dbg_src == "Paste code":
        dbg_fname = st.text_input("Filename (for language detection)", "code.py", key="dbg_fname")
        dbg_code = st.text_area("Paste source code", height=200, key="dbg_code")
        if st.button("Scan for bugs", type="primary", key="dbg_btn"):
            if not dbg_code.strip():
                st.warning("Paste some code first.")
            else:
                dbg_result = debug_scan(dbg_fname, dbg_code)
                st.session_state["last_debug_scan"] = dbg_result
    else:
        results = st.session_state.get("uploaded_results", [])
        if not results:
            st.info("Upload files in the **Upload & Analyze** tab first.")
        else:
            names = [r["name"] for r in results]
            sel = st.selectbox("Select file", names, key="dbg_file_sel")
            if st.button("Scan for bugs", type="primary", key="dbg_btn2"):
                chosen = next((r for r in results if r["name"] == sel), None)
                if chosen:
                    dbg_result = debug_scan(chosen["name"], chosen["text"])
                    st.session_state["last_debug_scan"] = dbg_result

    # Display cached or newly computed result
    if dbg_result is None:
        dbg_result = st.session_state.get("last_debug_scan")

    if dbg_result:
        findings = safe_get(dbg_result, "findings", [])
        high = safe_get(dbg_result, "high", 0)
        medium = safe_get(dbg_result, "medium", 0)
        low = safe_get(dbg_result, "low", 0)
        status_p = "BLOCK" if high > 0 else ("WARN" if medium > 0 else "PASS")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total findings", len(findings))
        m2.metric("HIGH", high)
        m3.metric("MEDIUM", medium)
        m4.metric("LOW", low)
        st.markdown(
            f"{pill(status_p)} &nbsp; {safe_get(dbg_result,'file','?')} "
            f"({safe_get(dbg_result,'language','?')})",
            unsafe_allow_html=True,
        )
        if findings:
            for f in findings:
                sev = f.get("severity", "?")
                conf = f.get("confidence", "?")
                with st.expander(
                    f"{pill(sev)} {f.get('title','?')} — line {f.get('line','?')} [{conf}]",
                    expanded=False,
                ):
                    st.markdown(f"**Category:** {f.get('category','?')}")
                    st.markdown(f"**Evidence:** {f.get('evidence','?')}")
                    st.markdown(f"**Explanation:** {f.get('explanation','?')}")
                    card(
                        f"<b>Advisory fix</b> (for developer review — do not apply blindly):<br>"
                        f"{f.get('proposed_fix','Not available')}<br>"
                        f"<span class='sf-muted'>Suggested regression test: {f.get('regression_test','Not provided')}</span>"
                    )
        else:
            st.success("No heuristic debug findings detected.")

        st.caption(safe_get(dbg_result, "disclaimer", ""))

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — TESTS
# ══════════════════════════════════════════════════════════════════════════════
with tabs[4]:
    st.subheader("Test Lab")
    st.caption("Runs your test suite as a subprocess and parses results. Individual PASS/FAIL/ERROR/SKIPPED per test.")

    col_discover, col_scaffold = st.columns(2)
    with col_discover:
        if st.button("Discover tests", key="discover_btn"):
            found = discover_tests(p)
            st.write(found if found else "No test_*.py files found.")
    with col_scaffold:
        if st.session_state.get("uploaded_results"):
            names = [r["name"] for r in st.session_state["uploaded_results"]]
            scaffold_sel = st.selectbox("Scaffold tests for", names, key="scaffold_sel")
            if st.button("Generate test scaffold", key="scaffold_btn"):
                chosen = next((r for r in st.session_state["uploaded_results"] if r["name"] == scaffold_sel), None)
                if chosen:
                    tmpl = generate_test_template(chosen["name"], chosen["text"])
                    st.download_button(
                        "Download scaffold",
                        tmpl.get("template", ""),
                        file_name=f"test_{Path(chosen['name']).stem}.py",
                        mime="text/x-python",
                    )
                    with st.expander("Preview scaffold"):
                        st.code(tmpl.get("template", ""), language="python")

    cmd = st.text_input("Test command", "python -m pytest -q", key="test_cmd")
    if st.button("Run tests", type="primary", key="run_tests_btn"):
        with st.spinner("Running tests…"):
            try:
                r = run_tests(p, cmd)
            except Exception as e:
                st.error(f"Test runner error: {e}")
                r = None
        if r:
            st.session_state["last_test_run"] = r
            a, b, c, d, e_ = st.columns(5)
            a.metric("Passed", r.get("passed", 0))
            b.metric("Failed", r.get("failed", 0))
            c.metric("Errors", r.get("errors", 0))
            d.metric("Skipped", r.get("skipped", 0))
            e_.metric("Time", f"{r.get('duration', 0):.2f}s")
            exec_st = r.get("execution_status", "UNKNOWN")
            st.markdown(pill(exec_st), unsafe_allow_html=True)
            tests = r.get("tests", [])
            if tests:
                st.dataframe(tests, use_container_width=True)
            if r.get("stdout"):
                with st.expander("stdout"):
                    st.code(r["stdout"][-12000:])
            if r.get("stderr"):
                with st.expander("stderr"):
                    st.code(r["stderr"][-8000:])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — BENCHMARK
# ══════════════════════════════════════════════════════════════════════════════
with tabs[5]:
    st.subheader("Benchmark Lab")
    st.caption("Measures wall-clock execution time with multiple runs. Results are real measurements, not estimates.")
    bench_cmd = st.text_input(
        "Command to benchmark",
        'python -c "sum(i*i for i in range(100000))"',
        key="bench_cmd",
    )
    bench_runs = st.number_input("Runs", min_value=3, max_value=30, value=7, step=1, key="bench_runs")
    bench_baseline = st.number_input(
        "Baseline median (seconds, 0 = no baseline)",
        min_value=0.0, value=0.0, step=0.001, format="%.4f", key="bench_baseline",
    )

    if st.button("Run benchmark", type="primary", key="bench_btn"):
        with st.spinner("Benchmarking…"):
            try:
                baseline = bench_baseline if bench_baseline > 0 else None
                r = run_benchmark(p, bench_cmd, int(bench_runs), baseline_median=baseline)
            except Exception as e:
                st.error(f"Benchmark error: {e}")
                r = None
        if r:
            st.session_state["last_benchmark"] = r
            if r.get("status") == "ok":
                a, b, c, d = st.columns(4)
                a.metric("Median", f"{r.get('median', 0):.4f}s")
                b.metric("P95", f"{r.get('p95', 0):.4f}s")
                c.metric("Min", f"{r.get('min', 0):.4f}s")
                d.metric("Max", f"{r.get('max', 0):.4f}s")
                cv = r.get("cv")
                st.markdown(
                    f"{pill('PASS')} &nbsp; "
                    f"CV: {f'{cv:.1f}%' if cv is not None else 'N/A'} &nbsp; "
                    f"Baseline: {r.get('baseline_status', 'UNAVAILABLE')}",
                    unsafe_allow_html=True,
                )
                with st.expander("Raw timing samples"):
                    st.write(r.get("samples", []))
            else:
                st.markdown(pill("BLOCK"), unsafe_allow_html=True)
                st.error(r.get("message", "Benchmark failed — check command and working directory."))

# ══════════════════════════════════════════════════════════════════════════════
# TAB 6 — SECURITY
# ══════════════════════════════════════════════════════════════════════════════
with tabs[6]:
    st.subheader("Defensive Security Sentinel")
    st.caption(
        "Static pattern scanning only. Defensive use — findings are advisory, not proof. "
        "Secret values are never displayed."
    )

    if st.button("Scan project folder", type="primary", key="sec_scan_btn"):
        with st.spinner("Scanning…"):
            try:
                r = security_scan(p)
            except Exception as e:
                st.error(f"Security scan error: {e}")
                r = None
        if r:
            st.session_state["last_security_scan"] = r
            a, b, c = st.columns(3)
            a.metric("Total findings", r.get("count", 0))
            b.metric("HIGH", r.get("high", 0))
            c.metric("Medium/Low", r.get("medium_low", 0))
            findings = r.get("findings", [])
            status = "PASS" if r.get("high", 0) == 0 and r.get("count", 0) == 0 else \
                     ("BLOCK" if r.get("high", 0) > 0 else "WARN")
            st.markdown(pill(status), unsafe_allow_html=True)
            if findings:
                # Never show the matched secret text — only show metadata
                display = [
                    {
                        "severity": f.get("severity"),
                        "title": f.get("title"),
                        "file": f.get("file"),
                        "line": f.get("line"),
                        "reason": f.get("reason"),
                        "remediation": f.get("remediation"),
                    }
                    for f in findings
                ]
                st.dataframe(display, use_container_width=True)
                with st.expander("Per-file breakdown"):
                    for fpath, count in (r.get("files_with_findings") or {}).items():
                        st.write(f"• `{fpath}`: {count} finding(s)")
            else:
                st.success("No pattern-based security findings in this project.")
        st.caption(
            "Findings are static pattern analysis. A clean result does not guarantee security. "
            "Run a professional SAST tool for production use."
        )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 7 — PUBLIC SECURITY DB
# ══════════════════════════════════════════════════════════════════════════════
with tabs[7]:
    st.subheader("Public Security Reference DB")
    st.caption(
        "Local curated vulnerability reference (CWE-mapped). "
        "Not a live CVE feed. No network access. No fabricated entries."
    )

    db_lang_filter = st.selectbox(
        "Filter by language",
        ["All"] + LANGUAGES,
        key="db_lang_filter",
    )
    db_kw = st.text_input("Keyword search (class name, CWE, description)", key="db_kw")
    db_sev = st.selectbox("Severity", ["All", "HIGH", "MEDIUM", "LOW"], key="db_sev")

    lang_arg = None if db_lang_filter == "All" else db_lang_filter
    sev_arg = None if db_sev == "All" else db_sev
    kw_arg = db_kw.strip() if db_kw.strip() else None

    entries = db_search(language=lang_arg, keyword=kw_arg, severity=sev_arg)

    st.markdown(f"**{len(entries)} entr{'y' if len(entries)==1 else 'ies'} found**")
    for e in entries:
        with st.expander(
            f"{pill(e.get('severity','?'))} [{e.get('id','?')}] {e.get('vuln_class','?')} — {e.get('cwe','?')}",
            expanded=False,
        ):
            card(
                f"<b>Class:</b> {e.get('vuln_class','?')}<br>"
                f"<b>CWE:</b> {e.get('cwe','?')} — {e.get('cwe_name','?')}<br>"
                f"<b>Languages:</b> {', '.join(e.get('languages',[]))}<br>"
                f"<b>Severity:</b> {e.get('severity','?')}<br>"
                f"<b>Description:</b> {e.get('description','?')}<br>"
                f"<b>Remediation:</b> {e.get('remediation','?')}"
            )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 8 — BOB 2.0 (Advisor / Recommendations)
# ══════════════════════════════════════════════════════════════════════════════
with tabs[8]:
    st.subheader("Bob 2.0 — Technology & Environment Advisor")
    st.caption(
        "Rule-based technology recommendations. No LLM. No cloud API. "
        "Transparent deterministic logic — every suggestion cites its reasoning."
    )

    problem = st.text_area("Describe the developer's problem or goal", key="bob_problem", height=100)
    typ = st.selectbox(
        "Application type",
        ["Web/API", "AI/ML", "Data", "Desktop", "Mobile", "CLI", "Embedded/IoT", "General"],
        key="bob_type",
    )
    priorities = st.multiselect(
        "Priorities",
        ["Fast development", "Performance", "Security", "Low cost", "Portability", "Easy maintenance", "Offline operation"],
        default=["Fast development"],
        key="bob_priorities",
    )
    target_env = st.selectbox(
        "Target environment",
        ["Windows", "Linux", "Cloud", "Docker", "Cross-platform", "Unknown"],
        key="bob_target",
    )

    if st.button("Generate recommendations", type="primary", key="bob_btn"):
        if not problem.strip():
            st.warning("Describe the problem first.")
        else:
            recs = recommend_stack(problem, typ, priorities, target_env)
            if recs:
                for r in recs:
                    card(
                        f"<h4>{r.get('name','?')}</h4>"
                        f"<b>Fit:</b> {r.get('fit','?')}<br>"
                        f"<b>Environment:</b> {r.get('environment','?')}<br>"
                        f"<b>Why:</b> {r.get('why','?')}<br>"
                        f"<b>Trade-offs:</b> {r.get('tradeoffs','?')}<br>"
                        f"<code>{r.get('command','')}</code>"
                    )
            else:
                st.info("No specific recommendations matched. Try adjusting the filters.")
            st.caption(
                "These are transparent rule-based recommendations produced from a static decision matrix. "
                "They are advisory and not generated by an LLM."
            )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 9 — DEVELOPER CHAT
# ══════════════════════════════════════════════════════════════════════════════
with tabs[9]:
    st.subheader("Developer Chat")
    st.caption(
        "Ask questions about the current session's evidence. "
        "Answers are deterministic and evidence-based — no LLM, no fabrication. "
        "Unanswerable questions return 'Insufficient project evidence.'"
    )

    question = st.text_input("Your question", placeholder="e.g. Are there security issues?", key="chat_q")
    if st.button("Ask", type="primary", key="chat_btn"):
        if not question.strip():
            st.warning("Type a question first.")
        else:
            ctx = _session_ctx()
            resp = chat_answer(question, ctx)
            ans = safe_get(resp, "answer", "No answer available.")
            src = safe_get(resp, "source", "")
            adv = safe_get(resp, "advisory", True)
            st.markdown(f"**Answer:**  {ans}")
            if src:
                st.caption(str(src))
            if adv:
                st.caption("⚠️ Advisory only — based on session evidence, not a professional audit.")

    st.divider()
    st.markdown("#### Session context summary")
    ctx = _session_ctx()
    for k, v in ctx.items():
        if v:
            st.write(f"✅ **{k}** — available")
        else:
            st.write(f"⬜ **{k}** — not yet run")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 10 — DOCUMENTATION
# ══════════════════════════════════════════════════════════════════════════════
with tabs[10]:
    st.subheader("Documentation")
    st.caption("Project documentation files and workflow guide.")

    _docs_root = Path(__file__).parent

    for doc_file in ["README.md", "bob_workflow.md", "AGENTS.md"]:
        doc_path = _docs_root / doc_file
        if doc_path.exists():
            with st.expander(f"📄 {doc_file}", expanded=doc_file == "README.md"):
                try:
                    content = doc_path.read_text(encoding="utf-8")
                    st.markdown(content)
                except Exception as e:
                    st.error(f"Could not read {doc_file}: {e}")

    st.divider()
    st.markdown("#### Workflow reference")
    steps = [
        ("Security", "Run the Security tab on your project to detect patterns before writing more code."),
        ("Debug", "Use Debug & Fix to identify reliability issues from static analysis."),
        ("Fix", "Review each advisory finding — apply only changes you understand."),
        ("Test", "Run Test Lab to verify your fixes didn't break existing coverage."),
        ("Optimize", "Use Benchmark Lab to measure real performance before and after changes."),
        ("Verify", "Check Processor Fit to confirm your language/target combination is supported."),
        ("Release", "Run Release Gate — all checks must pass before deploying."),
    ]
    for title, desc in steps:
        card(f"<b>{title}</b><br>{desc}")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 11 — COMMIT MESSAGE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[11]:
    st.subheader("Commit Message Generator")
    st.caption(
        "Generates a Conventional Commits message from your input. "
        "Never fabricates what was changed — uses only what you type."
    )

    cmt_type = st.selectbox("Change type", COMMIT_TYPES, key="cmt_type")
    cmt_scope = st.text_input("Scope (optional)", placeholder="e.g. security, benchmark, ui", key="cmt_scope")
    cmt_desc = st.text_input("Short description (required)", placeholder="e.g. add OWASP pattern checks", key="cmt_desc")
    cmt_breaking = st.checkbox("Breaking change", key="cmt_breaking")
    cmt_body = st.text_area("Body (optional)", height=80, key="cmt_body")

    if st.button("Generate message", type="primary", key="cmt_btn"):
        result = gen_commit(cmt_type, cmt_scope, cmt_desc, cmt_breaking, cmt_body)
        if result.get("error"):
            st.error(result["error"])
        else:
            st.success("Suggested commit message:")
            st.code(result["message"], language=None)
            st.caption(result.get("label", ""))
            st.download_button(
                "Copy to clipboard (download)",
                result["message"],
                file_name="commit_message.txt",
                mime="text/plain",
            )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 12 — DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════════════
with tabs[12]:
    st.subheader("Dependency Health")
    st.caption("Inspects dependency manifests in the project folder. Findings are static file analysis.")

    if st.button("Inspect dependencies", type="primary", key="dep_btn"):
        with st.spinner("Scanning…"):
            try:
                r = dependency_scan(p)
            except Exception as e:
                st.error(f"Dependency scan error: {e}")
                r = None
        if r:
            st.write(r.get("summary", "No summary available."))
            items = r.get("items", [])
            if items:
                st.dataframe(items, use_container_width=True)
            else:
                st.info("No dependency manifests found in this folder.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 13 — DEPLOYMENT
# ══════════════════════════════════════════════════════════════════════════════
with tabs[13]:
    st.subheader("Deployment Readiness")
    st.caption("Checks for common deployment artefacts: Dockerfile, CI config, env files, etc.")

    if st.button("Assess deployment readiness", type="primary", key="dep_assess_btn"):
        with st.spinner("Assessing…"):
            try:
                r = deployment_assessment(p)
            except Exception as e:
                st.error(f"Deployment assessment error: {e}")
                r = None
        if r:
            for x in r.get("checks", []):
                card(
                    f"{pill(x.get('status','WARN'))} &nbsp; <b>{x.get('name','Check')}</b><br>"
                    f"{x.get('detail','')}"
                )
            suggested = r.get("suggested_path", "")
            if suggested:
                st.info(f"**Suggested path:** {suggested}")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 14 — RELEASE GATE
# ══════════════════════════════════════════════════════════════════════════════
with tabs[14]:
    st.subheader("Release Gate")
    st.caption(
        "Aggregates evidence from all checks. READY FOR REVIEW requires: "
        "zero security HIGH findings, debug HIGH findings resolved, tests passing, deployment artefacts present."
    )

    if st.button("Run release gate", type="primary", key="rg_btn"):
        with st.spinner("Evaluating…"):
            try:
                r = release_assessment(p, _session_ctx())
            except Exception as e:
                st.error(f"Release gate error: {e}")
                r = None
        if r:
            st.session_state["last_release"] = r
            state = r.get("state", "UNKNOWN")
            st.markdown(f"### {pill(state)}", unsafe_allow_html=True)
            reasons = r.get("reasons", [])
            if reasons:
                for reason in reasons:
                    st.write("•", reason)
            evidence = r.get("evidence", [])
            if evidence:
                with st.expander("Evidence table", expanded=True):
                    st.dataframe(evidence, use_container_width=True)
            st.caption(r.get("disclaimer", ""))

# ══════════════════════════════════════════════════════════════════════════════
# TAB 15 — REPORT
# ══════════════════════════════════════════════════════════════════════════════
with tabs[15]:
    st.subheader("Engineering Report")
    st.caption(
        "Generates a Markdown report from all available evidence. "
        "Missing checks are clearly marked NOT RUN — nothing is fabricated."
    )

    if st.button("Generate report", type="primary", key="report_btn"):
        with st.spinner("Building report…"):
            try:
                report_text = build_report(p, _session_ctx())
            except Exception as e:
                st.error(f"Report generation error: {e}")
                report_text = None
        if report_text:
            st.download_button(
                "⬇️ Download report (.md)",
                report_text,
                file_name="siliconfit_report.md",
                mime="text/markdown",
            )
            with st.expander("Report preview", expanded=True):
                st.markdown(report_text)
