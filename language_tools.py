"""Language detection and advisory helpers. No compilers required."""

EXT_MAP = {
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++",
    ".py": "Python", ".pyw": "Python",
    ".rs": "Rust",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript", ".mjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".cs": "C#",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".rb": "Ruby",
    ".php": "PHP",
}

GOAL_ADVICE = {
    "ai/ml": {
        "suits": ["Python"],
        "alternatives": ["C++ (performance-critical inner loops)", "Rust (safe high-performance tooling)"],
        "reason": "Python has the deepest ML ecosystem (numpy, pytorch, scikit-learn) and fastest iteration speed.",
    },
    "embedded firmware": {
        "suits": ["C", "C++", "Rust"],
        "alternatives": ["MicroPython (only for non-critical prototyping)"],
        "reason": "Embedded targets need predictable memory layout and no garbage collector.",
    },
    "systems programming": {
        "suits": ["C", "C++", "Rust", "Go"],
        "alternatives": [],
        "reason": "Systems code benefits from manual or ownership-based memory control and small runtimes.",
    },
    "backend": {
        "suits": ["Go", "Java", "Python", "TypeScript", "C#"],
        "alternatives": [],
        "reason": "Mature web frameworks, concurrency primitives and deployment tooling exist across all of these.",
    },
    "full stack": {
        "suits": ["TypeScript", "JavaScript", "Python"],
        "alternatives": [],
        "reason": "Shared language across frontend and backend reduces context switching.",
    },
    "cybersecurity": {
        "suits": ["Python", "C", "Rust", "Go"],
        "alternatives": [],
        "reason": "Python for tooling/scripting speed; C/Rust/Go where low-level or high-performance analysis is needed.",
    },
    "high performance": {
        "suits": ["C", "C++", "Rust"],
        "alternatives": ["Go (simpler concurrency, moderate performance)"],
        "reason": "Compiled languages without a heavy managed runtime give the most predictable throughput and latency.",
    },
    "data science": {
        "suits": ["Python"],
        "alternatives": ["R (statistics-heavy workflows)"],
        "reason": "Pandas/numpy/notebook ecosystem is unmatched for exploratory data work.",
    },
    "mobile": {
        "suits": ["Kotlin", "Swift"],
        "alternatives": ["TypeScript (React Native)", "Dart (Flutter)"],
        "reason": "Native toolchains give the best platform integration; cross-platform frameworks trade that for reach.",
    },
    "robotics": {
        "suits": ["C++", "Python"],
        "alternatives": ["Rust (emerging, safer real-time control)"],
        "reason": "C++ for real-time control loops; Python for orchestration, perception glue and prototyping.",
    },
}


def language_from_filename(filename):
    """Return the detected language name, or 'Unknown' for unrecognized extensions."""
    filename = str(filename or "")
    for ext, name in EXT_MAP.items():
        if filename.lower().endswith(ext):
            return name
    return "Unknown"


def language_advisor(goal, current_language):
    """Advisory-only comparison of current language against a stated goal.

    Never forces a migration; always returns a dict with safe defaults.
    """
    goal_key = (goal or "").strip().lower()
    current_language = current_language or "Unknown"
    entry = None
    for key, value in GOAL_ADVICE.items():
        if key in goal_key or goal_key in key:
            entry = value
            break
    if entry is None:
        return {
            "goal": goal or "Not specified",
            "current_language": current_language,
            "well_suited": None,
            "suggested_alternatives": [],
            "reason": "No advisory rule matched this goal yet. Treat the current language choice as acceptable "
                      "unless you have a specific, measured reason to change it.",
            "note": "Advisory",
        }
    well_suited = current_language in entry.get("suits", [])
    return {
        "goal": goal or "Not specified",
        "current_language": current_language,
        "well_suited": well_suited,
        "suggested_alternatives": [l for l in entry.get("suits", []) if l != current_language] + entry.get("alternatives", []),
        "reason": entry.get("reason", "Not available"),
        "note": "Advisory — not a forced migration.",
    }


def basic_source_stats(text):
    """Safe, dependency-free statistics about a source text blob."""
    text = text or ""
    lines = text.splitlines()
    non_blank = [l for l in lines if l.strip()]
    comment_like = [l for l in non_blank if l.strip().startswith(("#", "//", "/*", "*"))]
    todo_count = sum(1 for l in lines if "TODO" in l or "FIXME" in l)
    return {
        "total_lines": len(lines),
        "non_blank_lines": len(non_blank),
        "comment_like_lines": len(comment_like),
        "todo_fixme_count": todo_count,
        "char_count": len(text),
    }
