import subprocess, time, re
from pathlib import Path


def discover_tests(root):
    root = Path(root)
    return [
        str(x.relative_to(root))
        for x in root.rglob("test_*.py")
        if not any(p in x.parts for p in {".venv", "venv", "node_modules"})
    ]


def _parse_summary_line(text):
    """Extract passed/failed/error counts from pytest summary lines.

    Handles both verbose-mode per-test lines and the compact summary line
    emitted by both -q and -v modes, e.g.:
      '3 passed, 1 failed, 2 errors in 0.45s'
    Returns (passed, failed, errors, summary_line_str).
    """
    passed = failed = errors = 0
    summary_line = ""
    # Look for pytest's final summary line: "N passed" / "N failed" / "N error(s)"
    for line in reversed(text.splitlines()):
        line_s = line.strip()
        if re.search(r"\d+\s+passed|\d+\s+failed|\d+\s+error", line_s):
            summary_line = line_s
            m_p = re.search(r"(\d+)\s+passed", line_s)
            m_f = re.search(r"(\d+)\s+failed", line_s)
            m_e = re.search(r"(\d+)\s+error", line_s)
            if m_p:
                passed = int(m_p.group(1))
            if m_f:
                failed = int(m_f.group(1))
            if m_e:
                errors = int(m_e.group(1))
            break
    return passed, failed, errors, summary_line


def _parse(text):
    """Parse per-test result lines from pytest verbose output.

    Returns a list of row dicts.  Falls back to the summary line when no
    per-test lines are found (e.g. when pytest -q is used).
    """
    rows = []
    for line in text.splitlines():
        m = re.match(
            r"(.+?)\s+(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)(?:\s+\[.*\])?$",
            line.strip(),
        )
        if m:
            rows.append({"test": m.group(1).strip(), "status": m.group(2), "details": ""})
    return rows


def _parse_skipped(text):
    """Extract skipped count from pytest summary line."""
    skipped = 0
    for line in reversed(text.splitlines()):
        m = re.search(r"(\d+)\s+skipped", line)
        if m:
            skipped = int(m.group(1))
            break
    return skipped


def _execution_status(result):
    """Return a single status string for the last test run.

    Distinguishes PASS / FAIL / ERROR / NOT_RUN / UNKNOWN.
    Never conflates NOT_RUN with PASS.
    """
    if not result:
        return "NOT_RUN"
    rc = result.get("returncode")
    if rc is None:
        return "NOT_RUN"
    if rc == 0 and result.get("passed", 0) > 0:
        return "PASS"
    if rc != 0 and result.get("failed", 0) > 0:
        return "FAIL"
    if result.get("errors", 0) > 0:
        return "ERROR"
    if rc == 0:
        return "PASS"
    return "UNKNOWN"


def run_tests(root, command):
    start = time.perf_counter()
    try:
        p = subprocess.run(
            command, cwd=root, shell=True, text=True,
            capture_output=True, timeout=300,
        )
        dur = time.perf_counter() - start
        combined = (p.stdout or "") + "\n" + (p.stderr or "")
        rows = _parse(combined)

        # Derive counts from per-test rows when available.
        if rows:
            passed = sum(x["status"] in ("PASSED", "XPASS") for x in rows)
            failed = sum(x["status"] == "FAILED" for x in rows)
            errors = sum(x["status"] == "ERROR" for x in rows)
            skipped = sum(x["status"] in ("SKIPPED", "XFAIL") for x in rows)
            _, _, _, summary_line = _parse_summary_line(combined)
        else:
            # No per-test lines — parse the summary line for accurate counts.
            passed, failed, errors, summary_line = _parse_summary_line(combined)
            skipped = _parse_skipped(combined)
            if passed or failed or errors or skipped:
                # Build a single summary row from parsed counts.
                status = "PASS" if p.returncode == 0 else "FAIL"
                detail = summary_line or "See raw output for details."
                rows = [{"test": "Test runner summary", "status": status, "details": detail}]
            else:
                # Completely unparseable output — fall back to return code.
                status = "PASS" if p.returncode == 0 else "FAIL"
                rows = [{"test": "Test runner summary", "status": status,
                         "details": "See raw output for runner-specific details."}]
                passed = int(p.returncode == 0)
                failed = int(p.returncode != 0)

        result = {
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "duration": dur,
            "tests": rows,
            "summary_line": summary_line,
            "stdout": p.stdout or "",
            "stderr": p.stderr or "",
            "returncode": p.returncode,
        }
        result["execution_status"] = _execution_status(result)
        return result
    except subprocess.TimeoutExpired:
        return {
            "passed": 0, "failed": 0, "errors": 1, "skipped": 0, "duration": 300,
            "tests": [{"test": "Test command timeout", "status": "ERROR",
                        "details": "Exceeded 300 seconds."}],
            "summary_line": "", "execution_status": "ERROR",
            "stdout": "", "stderr": "Timeout", "returncode": -1,
        }
    except Exception as e:
        return {
            "passed": 0, "failed": 0, "errors": 1, "skipped": 0,
            "duration": time.perf_counter() - start,
            "tests": [{"test": "Test runner execution", "status": "ERROR", "details": str(e)}],
            "summary_line": "", "execution_status": "ERROR",
            "stdout": "", "stderr": str(e), "returncode": -1,
        }
