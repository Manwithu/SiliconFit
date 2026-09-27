"""Test scaffold generator — Phase 5.

Generates minimal pytest-style test stubs for Python source files by
detecting top-level function names using regex (no AST required).

For C/C++ files, generates a comment-based checklist instead.
All output is advisory and must be reviewed before use.
Never auto-writes files.
"""

import re
from pathlib import Path

_PYTHON_FUNC = re.compile(r"^def\s+([a-zA-Z_]\w*)\s*\(", re.MULTILINE)
_C_FUNC      = re.compile(r"^\w[\w\s\*]+\s+([a-zA-Z_]\w*)\s*\([^;{]*\)\s*\{", re.MULTILINE)

_PY_EXTS  = {".py", ".pyw"}
_C_EXTS   = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}


def _language(filename):
    ext = Path(str(filename or "")).suffix.lower()
    if ext in _PY_EXTS:   return "Python"
    if ext in _C_EXTS:    return "C/C++"
    return "Unknown"


def generate_test_template(filename, text, language=None):
    """Return an advisory test stub for the given source file.

    Never raises.  Never auto-saves or modifies files.
    """
    text = text or ""
    filename_str = str(filename or "unknown")
    lang = language or _language(filename_str)

    if lang == "Python":
        return _python_template(filename_str, text)
    if lang in ("C", "C++", "C/C++"):
        return _c_template(filename_str, text)
    return {
        "template": f"# No test scaffold available for language: {lang}\n",
        "functions_found": [],
        "language": lang,
        "advisory": True,
    }


def _python_template(filename, text):
    names = _PYTHON_FUNC.findall(text)
    # Exclude private/dunder names from scaffold
    public = [n for n in names if not n.startswith("_")]
    module_stem = Path(filename).stem.replace("-", "_")

    lines = [
        f"# Auto-generated test scaffold for {filename}",
        f"# Advisory only — review and complete before running.",
        f"import sys, pytest",
        f"# sys.path.insert(0, '<path to module>')",
        f"# from {module_stem} import ...",
        "",
    ]
    if not public:
        lines.append("# No public functions detected — add tests manually.")
    else:
        for fn in public:
            lines += [
                f"def test_{fn}_basic():",
                f'    """Verify basic behaviour of {fn}()."""',
                f"    # Arrange",
                f"    # Act",
                f"    # result = {fn}(...)",
                f"    # Assert",
                f"    pass",
                "",
            ]
        lines += [
            "# Branch-coverage hint:",
            f"# This file has {len(names)} function(s). Consider at least one test",
            "# per branch (if/else/for/while/try) to achieve meaningful coverage.",
        ]

    return {
        "template": "\n".join(lines),
        "functions_found": public,
        "language": "Python",
        "advisory": True,
    }


def _c_template(filename, text):
    # Simple heuristic: match function definitions
    names = list({m.group(1) for m in _C_FUNC.finditer(text)})
    lines = [
        f"/* Test checklist for {filename} */",
        "/* Advisory only — implement using your chosen C test framework (Unity, Check, CTest). */",
        "",
    ]
    if not names:
        lines.append("/* No function signatures detected — add test cases manually. */")
    else:
        for fn in sorted(names):
            lines += [
                f"/* void test_{fn}_basic(void) {{",
                f"     /* Arrange */",
                f"     /* Act: call {fn}(...) */",
                f"     /* Assert: verify expected output */",
                f"  }} */",
                "",
            ]
    return {
        "template": "\n".join(lines),
        "functions_found": sorted(names),
        "language": "C/C++",
        "advisory": True,
    }


def branch_coverage_hint(text):
    """Return a count of branch keywords as a heuristic coverage estimate.

    Not an actual coverage measurement — labelled as advisory.
    """
    text = text or ""
    keywords = ["if", "else", "elif", "for", "while", "switch", "match", "case", "try", "except", "catch"]
    counts = {kw: len(re.findall(r"\b" + kw + r"\b", text)) for kw in keywords}
    total = sum(counts.values())
    return {
        "branch_keyword_counts": counts,
        "total_branch_keywords": total,
        "hint": (
            f"Detected {total} branch keyword(s). "
            "Consider at least one test per branch path for meaningful coverage. "
            "This is a heuristic count, not an actual coverage measurement."
        ),
        "advisory": True,
    }
