"""Shared result-handling utilities.

All helpers are pure functions with no side effects.
They must never raise — safe defaults are always returned.
"""

_VALID_STATUSES = {"PASS", "FAIL", "ERROR", "WARN", "SKIP", "UNKNOWN", "NOT_RUN"}


def safe_get(d, key, default=None):
    """Return d[key] when d is a dict and key exists, otherwise default.

    Never raises regardless of the type of d or key.
    """
    try:
        return d[key]
    except Exception:
        return default


def normalise_status(raw):
    """Map any raw status string to one of the canonical SiliconFit statuses.

    Canonical set: PASS, FAIL, ERROR, WARN, SKIP, UNKNOWN, NOT_RUN
    Unknown inputs map to UNKNOWN rather than raising.
    """
    if not isinstance(raw, str):
        return "UNKNOWN"
    upper = raw.strip().upper()
    _aliases = {
        "PASSED": "PASS",
        "OK": "PASS",
        "READY FOR REVIEW": "PASS",
        "FAILED": "FAIL",
        "BLOCKED": "FAIL",
        "BLOCK": "FAIL",
        "SKIPPED": "SKIP",
        "XFAIL": "SKIP",
        "XPASS": "PASS",
        "WARNING": "WARN",
        "REVIEW": "WARN",
        "NOT RUN": "NOT_RUN",
        "NOTRUN": "NOT_RUN",
    }
    if upper in _VALID_STATUSES:
        return upper
    return _aliases.get(upper, "UNKNOWN")


def clamp(val, lo, hi):
    """Return val clamped to [lo, hi].

    Works for int and float.  Returns lo if val is None or non-numeric.
    """
    try:
        v = float(val)
        return type(val)(max(float(lo), min(float(hi), v)))
    except Exception:
        return lo
