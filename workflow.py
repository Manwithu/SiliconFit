"""Bob 2.0 workflow step builder - Phase 9.

Architecture:
  BOB 2.0         = Orchestrator (guides the session)
  SILICONFIT      = Deterministic evidence engine
  DEVELOPER       = Final decision maker

The application never pretends Bob has executed an operation it has not.
Workflow step states: NOT_RUN / RUNNING / PASS / FAIL / REVIEW / BLOCKED
"""

from result_utils import safe_get

# Workflow step definitions: (title, action, evidence_description, context_key)
# context_key: the session-state key that provides evidence for this step.
_STEPS = [
    (
        "Plan — Define acceptance criteria",
        "Turn the project goal into observable requirements and success conditions.",
        "Developer requirements document.",
        None,
    ),
    (
        "Explore — Select technology and environment",
        "Confirm language, runtime, framework, dependencies, OS and deployment target.",
        "Advisor + environment inspection.",
        None,
    ),
    (
        "Security Explorer — Security scan",
        "Run the Defensive Security scanner on all source files.",
        "Security scanner findings.",
        "last_security_scan",
    ),
    (
        "Bug Hunter — Debug & Fix analysis",
        "Run the Debug & Fix scanner to surface reliability issues.",
        "Debug scan findings.",
        "last_debug_scan",
    ),
    (
        "Hardware Analyst — Processor fit",
        "Confirm language and target processor compatibility.",
        "Processor fit matrix + source heuristic analysis.",
        "last_processor_fit",
    ),
    (
        "Implementation — Incremental development",
        "Make small, verifiable changes. Commit each logical unit.",
        "Changed files / Git diff when available.",
        None,
    ),
    (
        "Test Designer — Test Lab",
        "Execute supported tests and inspect individual PASS/FAIL/ERROR/SKIPPED results.",
        "Test runner output — actual execution required.",
        "last_test_run",
    ),
    (
        "Benchmark — Measure performance",
        "Measure the actual workload and compare with a baseline when available.",
        "Repeatable wall-clock measurements (MEASURED label required).",
        "last_benchmark",
    ),
    (
        "Behavior Verification — Validate results",
        "Review all evidence: security, debug, test, benchmark, processor fit.",
        "Aggregated evidence from all checks.",
        None,
    ),
    (
        "Release Gate — Human approval",
        "Resolve blockers or explicitly accept remaining risks before release.",
        "Release Gate evidence table.",
        "last_release_gate",
    ),
]


def _step_evidence_status(context_key, context):
    """Derive the evidence status for a workflow step from session context."""
    if context_key is None:
        return "NOT_RUN"

    data = context.get(context_key)
    if not data:
        return "NOT_RUN"

    # Test run
    if context_key == "last_test_run":
        es = safe_get(data, "execution_status", "UNKNOWN")
        return {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "FAIL"}.get(es, "UNKNOWN")

    # Security scan
    if context_key == "last_security_scan":
        high = safe_get(data, "high", 0)
        ml   = safe_get(data, "medium_low", 0)
        if high > 0: return "BLOCKED"
        if ml  > 0: return "REVIEW"
        return "PASS"

    # Debug scan
    if context_key == "last_debug_scan":
        high   = safe_get(data, "high", 0)
        medium = safe_get(data, "medium", 0)
        if high > 0 or medium > 0: return "REVIEW"
        return "PASS"

    # Benchmark
    if context_key == "last_benchmark":
        status = safe_get(data, "status")
        if status == "ok":   return "PASS"
        if status == "failed": return "FAIL"
        return "UNKNOWN"

    # Processor fit
    if context_key == "last_processor_fit":
        fit = safe_get(data, "fit", "UNKNOWN")
        return {"STRONG": "PASS", "PARTIAL": "REVIEW",
                "UNSUPPORTED": "BLOCKED", "UNKNOWN": "NOT_RUN"}.get(fit, "NOT_RUN")

    # Release gate
    if context_key == "last_release_gate":
        state = safe_get(data, "state", "UNKNOWN")
        return {
            "READY FOR REVIEW": "PASS",
            "REVIEW": "REVIEW",
            "BLOCKED": "BLOCKED",
        }.get(state, "UNKNOWN")

    return "UNKNOWN"


def build_workflow(goal, root, context=None):
    """Return the Bob 2.0 workflow steps with live evidence status.

    Args:
        goal:    Developer's project goal string.
        root:    Project folder path (unused structurally but kept for API compatibility).
        context: Optional dict of session-state evidence from other modules.

    Returns a list of step dicts. evidence_status is always one of:
        NOT_RUN / PASS / FAIL / REVIEW / BLOCKED / UNKNOWN
    Never claims a step has passed if evidence is absent.
    """
    goal = goal or "Unnamed project"
    context = context or {}

    steps = []
    for i, (title, action, evidence_desc, ctx_key) in enumerate(_STEPS, 1):
        ev_status = _step_evidence_status(ctx_key, context)
        steps.append({
            "step": i,
            "title": title,
            "action": action.replace("{goal}", goal) if "{goal}" in action else action,
            "evidence": evidence_desc,
            "evidence_status": ev_status,
            "context_key": ctx_key,
        })

    return steps
