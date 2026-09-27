from pathlib import Path
from project_scan import scan_project
from security import security_scan
from dependencies import dependency_scan
from deployment import deployment_assessment
from release_gate import release_assessment
from result_utils import safe_get


def build_report(root, context=None):
    """Build a Markdown engineering report from available evidence.

    context: optional dict of cached session results (last_test_run,
             last_benchmark, last_debug_scan, last_processor_fit).
    Missing evidence is explicitly marked as NOT RUN.
    """
    context = context or {}
    s   = scan_project(root)
    sec = security_scan(root)
    dep = dependency_scan(root)
    de  = deployment_assessment(root)
    g   = release_assessment(root, context)

    languages = safe_get(s, "languages", [])
    reasons   = safe_get(g, "reasons", [])

    lines = [
        "# SiliconFit Secure Engineering Report",
        "",
        f"Project: `{root}`",
        "",
        "## Project",
        f"- Files: {safe_get(s, 'file_count', 0)}",
        f"- Languages: {', '.join(languages) if languages else 'None'}",
        f"- Test files: {safe_get(s, 'test_file_count', 0)}",
        f"- Dependency manifests: {safe_get(s, 'dependency_file_count', 0)}",
        "",
        "## Security",
        f"- Findings: {safe_get(sec, 'count', 0)}",
        f"- High: {safe_get(sec, 'high', 0)}",
        f"- Medium/Low: {safe_get(sec, 'medium_low', 0)}",
        f"- Note: {safe_get(sec, 'score_label', 'Static analysis only.')}",
        "",
    ]

    # --- Test results ---
    tr = context.get("last_test_run")
    lines.append("## Tests")
    if tr:
        lines += [
            f"- Status: {safe_get(tr, 'execution_status', 'UNKNOWN')}",
            f"- Passed: {safe_get(tr, 'passed', 0)}",
            f"- Failed: {safe_get(tr, 'failed', 0)}",
            f"- Errors: {safe_get(tr, 'errors', 0)}",
            f"- Skipped: {safe_get(tr, 'skipped', 0)}",
            f"- Duration: {safe_get(tr, 'duration', 0):.2f}s",
        ]
    else:
        lines.append("- Status: NOT RUN")
    lines.append("")

    # --- Debug findings ---
    dbg = context.get("last_debug_scan")
    lines.append("## Debug Findings")
    if dbg:
        lines += [
            f"- Total: {safe_get(dbg, 'count', 0)}",
            f"- High: {safe_get(dbg, 'high', 0)}",
            f"- Medium: {safe_get(dbg, 'medium', 0)}",
            f"- Low: {safe_get(dbg, 'low', 0)}",
            "- Note: Static heuristic analysis only.",
        ]
    else:
        lines.append("- Status: NOT RUN")
    lines.append("")

    # --- Benchmark ---
    bm = context.get("last_benchmark")
    lines.append("## Benchmark")
    if bm and safe_get(bm, "status") == "ok":
        cv = safe_get(bm, "cv")
        cv_str = f"{cv:.1f}%" if cv is not None else "N/A"
        lines += [
            f"- Evidence: MEASURED",
            f"- Median: {safe_get(bm, 'median', 0):.4f}s",
            f"- P95: {safe_get(bm, 'p95', 0):.4f}s",
            f"- CV: {cv_str}",
            f"- Baseline comparison: {safe_get(bm, 'baseline_status', 'UNAVAILABLE')}",
        ]
    elif bm:
        lines.append(f"- Status: FAILED — {safe_get(bm, 'message', 'unknown error')}")
    else:
        lines.append("- Status: NOT RUN")
    lines.append("")

    # --- Processor fit ---
    pf = context.get("last_processor_fit")
    lines.append("## Processor Fit")
    if pf:
        lines += [
            f"- Language: {safe_get(pf, 'language', 'Unknown')}",
            f"- Target: {safe_get(pf, 'target', 'Unknown')}",
            f"- Fit: {safe_get(pf, 'fit', 'UNKNOWN')}",
            f"- Advisory: {safe_get(pf, 'reason', 'No reason available.')}",
        ]
    else:
        lines.append("- Status: NOT RUN")
    lines.append("")

    lines += [
        "## Dependencies",
        safe_get(dep, "summary", "Dependency scan result unavailable."),
        "",
        "## Deployment",
        safe_get(de, "suggested_path", "Deployment assessment unavailable."),
        "",
        "## Release Gate",
        f"State: **{safe_get(g, 'state', 'UNKNOWN')}**",
    ] + [f"- {x}" for x in reasons] + [
        "",
        f"*{safe_get(g, 'disclaimer', '')}*",
    ]

    return "\n".join(lines)
