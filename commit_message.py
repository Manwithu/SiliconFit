"""Conventional Commits message generator - Phase 8D.

Generates a commit message from developer-supplied metadata.
Never claims a commit was created. Advisory output only.
"""


TYPES = ["feat", "fix", "docs", "test", "refactor", "chore", "perf", "ci", "style", "revert"]


def generate(change_type, scope, description, breaking=False, body=""):
    """Return a Conventional Commits formatted message string.

    Never fabricates what was changed. Uses only what the developer typed.
    Returns a dict with 'message' and 'advisory' fields.
    """
    change_type = (change_type or "chore").strip().lower()
    if change_type not in TYPES:
        change_type = "chore"

    description = (description or "").strip()
    if not description:
        return {
            "message": "",
            "error": "Description is required to generate a commit message.",
            "advisory": True,
        }

    scope_part = f"({scope.strip()})" if scope and scope.strip() else ""
    breaking_marker = "!" if breaking else ""
    header = f"{change_type}{scope_part}{breaking_marker}: {description}"

    lines = [header]
    if body and body.strip():
        lines.append("")
        lines.append(body.strip())
    if breaking:
        lines.append("")
        lines.append("BREAKING CHANGE: " + (body.strip() or description))

    return {
        "message": "\n".join(lines),
        "type": change_type,
        "scope": scope.strip() if scope else "",
        "description": description,
        "breaking": breaking,
        "advisory": True,
        "label": "Suggested commit message — review before committing.",
    }
