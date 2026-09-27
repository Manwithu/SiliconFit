"""Evidence-based release gate - Phase 7.

Combines evidence from security, tests, debug findings, benchmark,
processor fit, dependencies, deployment, and documentation.

Rules:
- FAILED tests → BLOCKED
- HIGH security finding → BLOCKED
- MEDIUM security finding → REVIEW
- Missing evidence → REVIEW or NOT_RUN (never silently PASS)
- All checks PASS → READY FOR REVIEW
- READY FOR REVIEW does not mean the software is completely secure.
"""

from pathlib import Path
from test_runner import discover_tests, _execution_status


# ---------------------------------------------------------------------------
# Individual evidence check helpers
# ---------------------------------------------------------------------------

def _check(name, status, detail, note=""):
    """Build a single evidence-check row."""
    return {"check": name, "status": status, "detail": detail, "note": note}


def _test_check(context):
    """Derive a test evidence check from session context."""
    last_run = context.get("last_test_run")
    if not last_run:
        discovered = context.get("discovered_tests", [])
        if discovered:
            return _check(
                "Tests",
                "NOT_RUN",
                f"{len(discovered)} test file(s) discovered but not executed.",
                "Run the Test Lab to obtain a PASS/FAIL result.",
            )
        return _check("Tests", "NOT_RUN", "No test run recorded.", "Run tests before releasing.")

    status = _execution_status(last_run)
    passed = last_run.get("passed", 0)
    failed = last_run.get("failed", 0)
    errors = last_run.get("errors", 0)
    detail = f"{passed} passed, {failed} failed, {errors} error(s). {last_run.get('summary_line','')}"

    if status == "PASS":
        gate_status = "PASS"
    elif status in ("FAIL", "ERROR"):
        gate_status = "BLOCK"
    else:
        gate_status = "UNKNOWN"

    return _check("Tests", gate_status, detail.strip(),
                  "Test results are from the last recorded run.")


def _security_check(context):
    """Derive a security evidence check from session context."""
    last_sec = context.get("last_security_scan")
    if not last_sec:
        return _check("Security", "NOT_RUN", "No security scan recorded.",
                      "Run the Defensive Security scanner before releasing.")
    high  = last_sec.get("high", 0)
    count = last_sec.get("count", 0)
    ml    = last_sec.get("medium_low", 0)
    detail = f"{count} finding(s): {high} HIGH, {ml} MEDIUM/LOW."

    if high > 0:
        gate_status = "BLOCK"
    elif ml > 0:
        gate_status = "REVIEW"
    else:
        gate_status = "PASS"

    return _check("Security", gate_status, detail,
                  "Static pattern scan only — absence of findings is not a security guarantee.")


def _debug_check(context):
    """Derive a debug evidence check from session context."""
    last_debug = context.get("last_debug_scan")
    if not last_debug:
        return _check("Debug findings", "NOT_RUN", "No debug scan recorded.",
                      "Run Debug & Fix to surface reliability issues.")
    high   = last_debug.get("high", 0)
    medium = last_debug.get("medium", 0)
    count  = last_debug.get("count", 0)
    detail = f"{count} finding(s): {high} HIGH, {medium} MEDIUM."

    if high > 0:
        gate_status = "REVIEW"
    elif medium > 0:
        gate_status = "REVIEW"
    else:
        gate_status = "PASS"

    return _check("Debug findings", gate_status, detail,
                  "Static heuristic findings — POTENTIAL findings require developer review.")


def _benchmark_check(context):
    """Derive a benchmark evidence check from session context."""
    last_bench = context.get("last_benchmark")
    if not last_bench:
        return _check("Benchmark", "NOT_RUN", "No benchmark recorded.",
                      "Run Benchmark Lab if performance requirements exist.")
    status = last_bench.get("status", "unknown")
    if status == "ok":
        med = last_bench.get("median", 0)
        bs  = last_bench.get("baseline_status", "UNAVAILABLE")
        detail = f"Median {med:.4f}s. Baseline comparison: {bs}."
        gate_status = "PASS" if bs in ("PASS", "UNAVAILABLE") else "REVIEW"
    else:
        detail = last_bench.get("message", "Benchmark failed.")
        gate_status = "REVIEW"

    return _check("Benchmark", gate_status, detail, "MEASURED wall-clock time only.")


def _processor_check(context):
    """Derive a processor-fit evidence check from session context."""
    last_pf = context.get("last_processor_fit")
    if not last_pf:
        return _check("Processor fit", "NOT_RUN", "No processor fit analysis recorded.",
                      "Run Processor Fit if hardware compatibility is a requirement.")
    fit = last_pf.get("fit", "UNKNOWN")
    target = last_pf.get("target", "Unknown")
    gate_status = {"STRONG": "PASS", "PARTIAL": "REVIEW",
                   "UNSUPPORTED": "BLOCK", "UNKNOWN": "NOT_RUN"}.get(fit, "NOT_RUN")
    return _check("Processor fit", gate_status,
                  f"{last_pf.get('language','?')} on {target}: {fit}.",
                  "Static advisory matrix — not a verified hardware result.")


def _dependency_check(root):
    """Check presence of dependency manifests."""
    try:
        from dependencies import dependency_scan
        result = dependency_scan(root)
        items  = result.get("items", [])
        errors = [i for i in items if "ERROR" in i.get("status", "")]
        if items:
            gate_status = "REVIEW" if errors else "PASS"
            detail = f"{len(items)} manifest(s) found."
        else:
            gate_status = "REVIEW"
            detail = "No dependency manifests found."
    except Exception:
        gate_status = "NOT_RUN"
        detail = "Dependency scan unavailable."
    return _check("Dependencies", gate_status, detail,
                  "Dependency scan does not check for known vulnerabilities.")


def _deployment_check(root):
    """Check deployment readiness."""
    try:
        from deployment import deployment_assessment
        result  = deployment_assessment(root)
        checks  = result.get("checks", [])
        warns   = [c for c in checks if c.get("status") == "WARN"]
        passes  = [c for c in checks if c.get("status") == "PASS"]
        gate_status = "PASS" if not warns else "REVIEW"
        detail  = f"{len(passes)} check(s) passed, {len(warns)} warning(s)."
    except Exception:
        gate_status = "NOT_RUN"
        detail = "Deployment assessment unavailable."
    return _check("Deployment readiness", gate_status, detail)


def _documentation_check(root):
    """Check presence of README."""
    readme = (Path(root) / "README.md").exists() if root else False
    return _check(
        "Documentation",
        "PASS" if readme else "WARN",
        "README.md present." if readme else "README.md missing.",
        "Tests discovered does not mean tests have been run or passed.",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def release_assessment(root, context=None):
    """Return a release gate assessment combining evidence from all sources.

    Args:
        root:    Project folder path.
        context: Optional dict with cached results from other modules.
                 Keys: last_test_run, last_security_scan, last_debug_scan,
                       last_benchmark, last_processor_fit, discovered_tests.
                 Missing keys → NOT_RUN (never silently PASS).
    """
    root = Path(root) if root else Path(".")
    context = context or {}

    if not root.exists():
        return {
            "state": "BLOCKED",
            "reasons": ["Project folder does not exist."],
            "evidence": [],
        }

    evidence = []
    blockers  = []
    reviews   = []
    not_run   = []

    # --- Run all checks ---
    checks = [
        _test_check(context),
        _security_check(context),
        _debug_check(context),
        _benchmark_check(context),
        _processor_check(context),
        _dependency_check(root),
        _deployment_check(root),
        _documentation_check(root),
    ]

    for c in checks:
        evidence.append(c)
        st = c.get("status", "UNKNOWN")
        if st == "BLOCK":
            blockers.append(f"{c['check']}: {c['detail']}")
        elif st in ("REVIEW", "WARN", "UNKNOWN"):
            reviews.append(f"{c['check']}: {c['detail']}")
        elif st == "NOT_RUN":
            not_run.append(c["check"])

    # --- Derive overall state ---
    if blockers:
        state = "BLOCKED"
        reasons = blockers + ([f"Not run: {', '.join(not_run)}"] if not_run else [])
    elif reviews:
        state = "REVIEW"
        reasons = reviews + ([f"Not run: {', '.join(not_run)}"] if not_run else [])
    elif not_run:
        state = "REVIEW"
        reasons = [f"Evidence not collected for: {', '.join(not_run)}."]
    else:
        state = "READY FOR REVIEW"
        reasons = [
            "No blockers detected by available checks.",
            "READY FOR REVIEW does not mean the software is completely secure or production-ready.",
        ]

    return {
        "state": state,
        "reasons": reasons,
        "evidence": evidence,
        "disclaimer": (
            "Release Gate is evidence-based but not exhaustive. "
            "Human review is required before any production deployment."
        ),
    }
