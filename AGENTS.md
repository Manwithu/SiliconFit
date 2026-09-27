# SiliconFit Secure — IBM Bob Context

SiliconFit is an evidence engine, not a chatbot.

## Core rules

- Never fabricate test results, benchmark values, security findings, compatibility claims or deployment success.
- Use `.get()` / `safe_get()` / safe defaults for ALL optional dictionary fields.
- Distinguish PASS, FAIL, ERROR, SKIPPED, NOT_RUN, WARN, REVIEW, BLOCKED, and UNKNOWN.
- Never conflate NOT_RUN with PASS.
- Do not claim security from absence of scanner matches.
- Do not claim performance improvements without actual before/after measurements.
- Keep the core product independent of Ollama and Granite.
- Security functionality is defensive only.
- Secret values detected in source are never displayed in the UI — show [REDACTED] if needed.
- All advisory outputs carry `advisory: True` in their return dict.
- After any change run `python -m pytest -v`.

## Module responsibilities

| Module | Responsibility |
|--------|---------------|
| `security.py` | Multi-language static security scanner |
| `debugger.py` | Static heuristic debug/reliability analysis |
| `processor_fit.py` | Language × target fit matrix + source heuristics |
| `benchmark.py` | Subprocess wall-clock benchmark (MEASURED only) |
| `test_runner.py` | Test execution + result parsing |
| `test_scaffold.py` | Advisory test stub generator |
| `release_gate.py` | Evidence-based release gate |
| `workflow.py` | Bob 2.0 workflow with live evidence status |
| `public_security_db.py` | Local curated CWE reference |
| `developer_chat.py` | Rule-based Q&A from session evidence |
| `commit_message.py` | Conventional Commits generator |
| `result_utils.py` | `safe_get`, `normalise_status`, `clamp` |
| `report.py` | Downloadable Markdown engineering report |

## Evidence labels

- `MEASURED` — actual subprocess execution result
- `NOT_RUN` — check was not executed in this session
- `UNAVAILABLE` — tool or baseline not present
- `STATIC_ANALYSIS` — regex/heuristic pattern scan, no code execution
- `ADVISORY` — recommendation that must be verified before acting on it

## Bob 2.0 workflow

Plan → Explore → Security Explorer → Bug Hunter → Hardware Analyst →
Implementation → Test Designer → Benchmark → Behavior Verification → Release Gate → Human Approval
