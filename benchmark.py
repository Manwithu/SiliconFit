import subprocess, time, statistics, math


def run_benchmark(root, command, runs=7, baseline_median=None):
    """Run *command* in *root* for *runs* iterations and collect wall-clock timings.

    Args:
        root:             Working directory for the subprocess.
        command:          Shell command string to benchmark.
        runs:             Number of iterations (1–30).
        baseline_median:  Optional prior median (seconds) for delta comparison.

    Returns a dict.  status is "ok" or "failed".
    All values are MEASURED from actual subprocess execution.
    No values are fabricated.
    """
    vals = []
    errs = []
    for _ in range(max(1, min(int(runs), 30))):
        s = time.perf_counter()
        try:
            p = subprocess.run(
                command, cwd=root, shell=True, text=True,
                capture_output=True, timeout=120,
            )
            t = time.perf_counter() - s
            if p.returncode == 0:
                vals.append(t)
            else:
                errs.append((p.stderr or p.stdout or "Command failed")[-1000:])
        except Exception as e:
            errs.append(str(e))

    if not vals:
        return {
            "status": "failed",
            "evidence": "NOT_RUN",
            "message": errs[-1] if errs else "No measurements collected",
            "runs": runs,
            "errors": errs,
        }

    vals.sort()
    n = len(vals)
    med = statistics.median(vals)

    # p95: index at ceil(0.95 * n) - 1, clamped to [0, n-1].
    p95_idx = max(0, min(n - 1, math.ceil(0.95 * n) - 1))
    p95 = vals[p95_idx]

    # Coefficient of variation (stddev / mean * 100) — requires n >= 2.
    if n >= 2:
        mean = sum(vals) / n
        stddev = statistics.stdev(vals)
        cv = (stddev / mean * 100) if mean > 0 else 0.0
    else:
        stddev = None
        cv = None

    # Outliers: runs > median * 3 (heuristic — flagged for awareness, not excluded).
    outliers = [v for v in vals if v > med * 3] if med > 0 else []

    # Baseline delta: only computed when a real baseline is supplied.
    if baseline_median is not None and baseline_median > 0:
        delta_pct = ((med - baseline_median) / baseline_median) * 100
        if delta_pct <= 0:
            baseline_status = "PASS"        # faster or equal
        elif delta_pct <= 10:
            baseline_status = "WARN"        # within 10 % slower
        else:
            baseline_status = "BLOCK"       # more than 10 % slower
    else:
        delta_pct = None
        baseline_status = "UNAVAILABLE"

    return {
        "status": "ok",
        "evidence": "MEASURED",
        "runs": n,
        "median": med,
        "min": vals[0],
        "max": vals[-1],
        "p95": p95,
        "stddev": stddev,
        "cv": cv,
        "outliers": outliers,
        "samples": vals,
        "errors": errs,
        "baseline_median": baseline_median,
        "baseline_delta_pct": delta_pct,
        "baseline_status": baseline_status,
    }
