"""Deterministic rule-based developer chat - Phase 8B.

Answers developer questions from available SiliconFit session/project evidence.
No Ollama, Granite, OpenAI, or external LLM APIs.
Never fabricates evidence.
Unanswered questions return "Insufficient project evidence."
Every answer includes a source badge.
"""

from result_utils import safe_get


# ---------------------------------------------------------------------------
# Rule definitions
# Each rule: (trigger_keywords, answer_builder_fn)
# ---------------------------------------------------------------------------

def _source(label):
    return f"[Source: {label}]"


def _answer(text, source):
    return {"answer": text, "source": source, "advisory": True}


def _no_evidence(topic):
    return {
        "answer": f"Insufficient project evidence for: {topic}. Run the relevant check first.",
        "source": _source("Not available"),
        "advisory": True,
    }


# ---------------------------------------------------------------------------
# Evidence extractors
# ---------------------------------------------------------------------------

def _security_answer(context):
    sec = context.get("last_security_scan")
    if not sec:
        return _no_evidence("security findings")
    high = safe_get(sec, "high", 0)
    count = safe_get(sec, "count", 0)
    ml = safe_get(sec, "medium_low", 0)
    if count == 0:
        text = "No pattern-based security findings detected. This is not a security guarantee."
    else:
        text = (f"{count} security finding(s): {high} HIGH, {ml} MEDIUM/LOW. "
                "Review findings in the Security tab before releasing.")
    return _answer(text, _source("Last security scan"))


def _test_answer(context):
    tr = context.get("last_test_run")
    if not tr:
        return _no_evidence("test results")
    passed = safe_get(tr, "passed", 0)
    failed = safe_get(tr, "failed", 0)
    errors = safe_get(tr, "errors", 0)
    status = safe_get(tr, "execution_status", "UNKNOWN")
    text = (f"Test run status: {status}. "
            f"{passed} passed, {failed} failed, {errors} error(s). "
            f"{safe_get(tr, 'summary_line', '')}")
    return _answer(text.strip(), _source("Last test run"))


def _benchmark_answer(context):
    bm = context.get("last_benchmark")
    if not bm:
        return _no_evidence("benchmark results")
    if safe_get(bm, "status") != "ok":
        return _answer(
            f"Last benchmark failed: {safe_get(bm, 'message', 'unknown error')}",
            _source("Last benchmark"),
        )
    med = safe_get(bm, "median", 0)
    cv = safe_get(bm, "cv")
    bs = safe_get(bm, "baseline_status", "UNAVAILABLE")
    cv_str = f" CV={cv:.1f}%" if cv is not None else ""
    text = (f"Benchmark: median {med:.4f}s{cv_str}. "
            f"Baseline comparison: {bs}. "
            "All values are MEASURED wall-clock timings.")
    return _answer(text, _source("Last benchmark run"))


def _debug_answer(context):
    dbg = context.get("last_debug_scan")
    if not dbg:
        return _no_evidence("debug findings")
    count = safe_get(dbg, "count", 0)
    high = safe_get(dbg, "high", 0)
    if count == 0:
        text = "No debug/reliability findings detected in the last scan."
    else:
        text = (f"{count} debug finding(s): {high} HIGH severity. "
                "Review findings in the Debug & Fix tab.")
    return _answer(text, _source("Last debug scan"))


def _release_answer(context):
    rg = context.get("last_release_gate")
    if not rg:
        return _no_evidence("release gate status")
    state = safe_get(rg, "state", "UNKNOWN")
    reasons = safe_get(rg, "reasons", [])
    reasons_str = "; ".join(reasons[:3]) if reasons else "No reasons recorded."
    text = f"Release gate state: {state}. {reasons_str}"
    return _answer(text, _source("Last release gate assessment"))


def _processor_answer(context):
    pf = context.get("last_processor_fit")
    if not pf:
        return _no_evidence("processor fit analysis")
    fit = safe_get(pf, "fit", "UNKNOWN")
    lang = safe_get(pf, "language", "?")
    target = safe_get(pf, "target", "?")
    reason = safe_get(pf, "reason", "No reason available.")
    text = f"{lang} on {target}: {fit}. {reason} (Advisory - static matrix only.)"
    return _answer(text, _source("Last processor fit analysis"))


def _priority_answer(context):
    """What should I fix first?"""
    sec = context.get("last_security_scan")
    dbg = context.get("last_debug_scan")
    tr  = context.get("last_test_run")

    items = []
    if sec and safe_get(sec, "high", 0) > 0:
        items.append(f"1. Fix {safe_get(sec,'high',0)} HIGH security finding(s) — these block release.")
    if tr and safe_get(tr, "failed", 0) > 0:
        items.append(f"2. Fix {safe_get(tr,'failed',0)} failing test(s) — failed tests block release.")
    if dbg and safe_get(dbg, "high", 0) > 0:
        items.append(f"3. Review {safe_get(dbg,'high',0)} HIGH debug finding(s).")
    if sec and safe_get(sec, "medium_low", 0) > 0:
        items.append(f"4. Review {safe_get(sec,'medium_low',0)} MEDIUM/LOW security finding(s).")

    if not items:
        if not any([sec, dbg, tr]):
            return _no_evidence("priority analysis")
        items = ["No immediate blockers detected. Run all checks to confirm."]

    return _answer("\n".join(items), _source("Aggregated evidence"))


def _optimization_answer(context):
    bm = context.get("last_benchmark")
    if not bm or safe_get(bm, "status") != "ok":
        return _answer(
            "No verified benchmark measurements available. "
            "Run the Benchmark Lab and compare before/after to verify any optimization.",
            _source("Benchmark not run"),
        )
    bs = safe_get(bm, "baseline_status", "UNAVAILABLE")
    if bs == "UNAVAILABLE":
        return _answer(
            "Benchmark ran but no baseline was provided. "
            "Set a baseline median to measure whether an optimization helped.",
            _source("Last benchmark"),
        )
    delta = safe_get(bm, "baseline_delta_pct")
    delta_str = f"{delta:+.1f}%" if delta is not None else "unknown"
    text = (f"Optimization result vs baseline: {delta_str} ({bs}). "
            "This is a MEASURED wall-clock comparison, not a hypothesis.")
    return _answer(text, _source("Last benchmark with baseline"))


# ---------------------------------------------------------------------------
# Rule dispatch table
# ---------------------------------------------------------------------------

_RULES = [
    (["security", "vulnerabilit", "finding", "high finding", "scan result"],  _security_answer),
    (["test", "pass", "fail", "broke", "regression"],                          _test_answer),
    (["benchmark", "performance", "fast", "slow", "speed", "latency"],        _benchmark_answer),
    (["debug", "bug", "reliability", "crash", "defect"],                      _debug_answer),
    (["release", "blocked", "block", "gate", "ready"],                        _release_answer),
    (["processor", "hardware", "arm", "x86", "esp32", "riscv", "target"],    _processor_answer),
    (["fix first", "priority", "what should", "where to start"],              _priority_answer),
    (["optim", "speedup", "improvement", "faster", "verified optim"],         _optimization_answer),
]

# FAQ answers shown when no project is loaded
_FAQ = {
    "what is siliconfit": (
        "SiliconFit Secure is a deterministic developer workflow platform. "
        "It scans source code for security issues, debug problems, and processor fit, "
        "then aggregates evidence into a release gate. No AI fabrication — all results are measured or explicitly marked unavailable."
    ),
    "how do i run tests": (
        "Go to the Tests tab. Enter your test command (default: python -m pytest -v) and click Run. "
        "Results are parsed from the runner output."
    ),
    "how do i scan for security issues": (
        "Go to the Defensive Security tab and click 'Run security scan'. "
        "You can also upload individual files in the Upload & Analyze tab for immediate scanning."
    ),
    "what languages are supported": (
        "Python, C, C++, Rust, Go, Java, JavaScript, TypeScript, and Custom. "
        "Security scanning, debug analysis, and processor fit are all language-aware."
    ),
    "how do i generate a report": (
        "Go to the Engineering Report tab and click 'Generate report'. "
        "You can download it as a Markdown file."
    ),
    "how do i release": (
        "Run all checks (security scan, tests, debug scan, benchmark), then go to the Release Gate tab. "
        "The gate aggregates all available evidence and shows PASS/REVIEW/BLOCKED."
    ),
}


def answer(question, context=None):
    """Return an answer to the developer's question.

    context: dict of last_security_scan, last_test_run, last_benchmark,
             last_debug_scan, last_release_gate, last_processor_fit.

    Never raises. Never fabricates. Returns advisory text only.
    """
    context = context or {}
    q = (question or "").strip().lower()

    if not q:
        return _answer("Please ask a question.", _source("None"))

    # Check FAQ first (no context required)
    for faq_key, faq_text in _FAQ.items():
        if faq_key in q or all(w in q for w in faq_key.split()):
            return _answer(faq_text, _source("SiliconFit FAQ"))

    # Match against rule triggers
    for triggers, fn in _RULES:
        if any(t in q for t in triggers):
            return fn(context)

    # No match
    return {
        "answer": (
            "I don't have a rule for that question yet. "
            "Run the relevant SiliconFit check and ask about the results. "
            "Available topics: security findings, test results, benchmark, debug findings, "
            "release gate, processor fit, what to fix first."
        ),
        "source": _source("No matching rule"),
        "advisory": True,
    }
