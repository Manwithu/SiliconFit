# SiliconFit Secure — Hackathon Implementation Plan

## Top-Level Overview

**Goal:** Evolve the existing SiliconFit Secure codebase into a polished,
hackathon-ready developer workflow platform.

**Core workflow:** Security → Debug → Fix → Test → Optimize → Verify → Release

**Architecture:**
- BOB 2.0 = Orchestrator (guides the session)
- SILICONFIT = Deterministic evidence engine (measures, scans, runs)
- DEVELOPER = Final decision maker

**Approach:** Extend and harden existing modules. Add missing modules.
Never fabricate evidence. Keep fully local (no Ollama, no Granite, no cloud AI API).

**Supported languages:** C, C++, Python, Rust, Go, Java, JavaScript, TypeScript, Custom

**Processor targets:** Generic x86-64, Intel x86-64, AMD x86-64, ARM64, RISC-V 64, ESP32-class MCU

**Non-goals:** LLM integration, cloud APIs, automatic code rewriting, fabricated security findings.

---

## Phase 1 — Reliability and Result Normalization

**Status:** [ ] pending

### Intent
Harden every existing module so that `None`, empty, missing-key, and
malformed-result scenarios never crash the application.
Bring `report.py` in line with the `.get()` policy mandated by `AGENTS.md`.
Fix the `pytest -q` parsing gap so Test Lab shows real per-test results.
Document the canonical return shapes for every module.

### Existing files to modify
- `siliconfit/report.py` — replace bare bracket indexing with `.get()` + safe defaults
- `siliconfit/test_runner.py` — add `-v` flag to the default command OR add a
  secondary parse pass that reads the pytest summary line (`N passed, M failed`)
  so the fallback row reflects accurate counts
- `siliconfit/benchmark.py` — correct p95 calculation for small sample sizes
  (use `statistics.quantiles` when available, or an index-safe formula for n < 20)
- `siliconfit/release_gate.py` — add a `note` field to evidence rows clarifying
  that "tests discovered" does not mean "tests passed"

### New files required
- `siliconfit/result_utils.py` — shared helpers:
  - `safe_get(d, key, default)` wrapper
  - `normalise_status(raw)` → one of PASS / FAIL / ERROR / WARN / SKIP / UNKNOWN
  - `clamp(val, lo, hi)` for numeric results

### Features to implement
- All module return dicts gain a `_schema_version` field (integer, starts at 1)
  so callers can detect incompatible changes
- `test_runner._parse()` gains a summary-line fallback: parse
  `(\d+) passed` / `(\d+) failed` / `(\d+) error` from the pytest summary
  when zero per-test rows are found
- `benchmark.run_benchmark()` p95 formula: sort vals, index at
  `max(0, int(ceil(0.95 * n)) - 1)` to be statistically correct for n >= 1

### Tests to add/update
- `tests/test_analyzers.py`: add assertion that `run_benchmark` p95 <= max
- `tests/test_report.py`: add assertion that `build_report` on missing folder
  still contains all expected section headings (no KeyError)
- New `tests/test_result_utils.py`: unit tests for `safe_get`, `normalise_status`,
  `clamp`

### Dependencies
None — stdlib only.

### Acceptance criteria
- `python -m pytest -q` passes with zero failures and zero errors
- `build_report` on a missing folder returns a string without raising
- Uploading a file with `None` content in `scan_text` returns count=0, score=100
- `run_benchmark` with 2 samples returns p95 >= median

### Potential risks
- Changing the default test command from `-q` to `-v` changes stdout volume;
  cap displayed output at 12 000 chars (already done in `app.py`)

---

## Phase 2 — Security Expansion

**Status:** [ ] pending

### Intent
Extend the security scanner to cover C, C++, Rust, Go, Java, JavaScript,
and TypeScript source files.
Add patterns for the most common, unambiguous, high-signal vulnerabilities
in each language.
Ensure the scanner never reports a false security guarantee.

### Existing files to modify
- `siliconfit/security.py` — extend `PAT` list and `security_scan()` to operate
  on all supported extensions, not just `.py`

### New files required
- None — all changes contained within `security.py`

### Features to implement
**New per-language pattern groups (all severity-labelled):**

C / C++:
- HIGH: `strcpy(`, `gets(`, `sprintf(` without `n` variant — unsafe buffer ops
- HIGH: hard-coded string literal that looks like a secret
  (reuse existing regex, apply to `.c`, `.cpp`, `.h`, `.hpp`)
- MEDIUM: `system(` — shell command boundary
- MEDIUM: `malloc` result used without NULL check (heuristic)

Rust:
- MEDIUM: `unsafe {` block — flag for manual review
- LOW: `.unwrap()` call — may panic in production

Go:
- MEDIUM: `exec.Command(` — shell boundary
- LOW: blank identifier error discard `_, err` followed immediately by use of result
  (heuristic, line-level)

Java:
- HIGH: `Runtime.getRuntime().exec(` — shell boundary
- HIGH: hard-coded secret regex (same pattern)
- MEDIUM: `ObjectInputStream` — unsafe deserialization

JavaScript / TypeScript:
- HIGH: `eval(` — arbitrary code execution
- HIGH: hard-coded secret regex
- MEDIUM: `child_process` usage
- LOW: `console.log(password` / `console.log(secret` — secret leakage via log

**Scanner changes:**
- `security_scan(root)` receives an optional `extensions` parameter defaulting
  to all supported extensions; iterates all matching files
- `scan_text(filename, text)` selects the pattern set by inspecting the
  file extension so it never applies Python patterns to C files
- Both functions continue to return the same dict shape; add `language` field
  to each finding row

**Hard rule:** The summary never says "no vulnerabilities found"; it says
"no pattern-based findings detected — this is not a security guarantee."

### Tests to add/update
- `tests/test_security.py`:
  - `test_scan_text_c_hardcoded_key` — `strcpy` + hard-coded key in `.c` source
  - `test_scan_text_rust_unsafe_block`
  - `test_scan_text_js_eval`
  - `test_scan_text_java_exec`
  - `test_security_scan_c_file_detected` — point scanner at `sample_projects/`
    and assert `security_demo.c` findings are returned
  - `test_no_false_guarantee` — empty file of any extension returns score=100
    and no findings, but `score_label` still contains "not a security guarantee"

### Dependencies
None — stdlib `re` only.

### Acceptance criteria
- `security_demo.c` produces at least 2 HIGH findings when scanned
- `buggy_memory.c` produces at least 1 MEDIUM finding
- `sample_project.py` with no secrets produces 0 HIGH findings
- All new test cases pass

### Potential risks
- Overly broad C patterns (e.g. `strcpy` in comments) may produce false positives;
  patterns must use word boundaries or context anchors where possible
- Do not scan `.c` files for Python-specific patterns (`subprocess`, `pickle`)

---

## Phase 3 — Processor Fit and Hardware-Aware Analysis

**Status:** [ ] pending

### Intent
Add a new `processor_fit.py` module that maps source language + algorithm
characteristics to processor targets.
Provide evidence-based (not fabricated) fit scores using a static
knowledge matrix.
All processor specifications must come from documented public facts,
not from runtime detection or fabricated values.

### Existing files to modify
- `siliconfit/app.py` — add "Processor Fit" tab between Upload & Analyze and Advisor

### New files required
- `siliconfit/processor_fit.py` — new module

### Features to implement

**Processor target definitions (static, documented):**

| Target | Key characteristics |
|---|---|
| Generic x86-64 | Ubiquitous; SIMD via SSE2/AVX; OS-dependent ABI |
| Intel x86-64 | AVX-512 on server SKUs; P/E core topology on client |
| AMD x86-64 | Zen architecture; strong AVX2; competitive SIMD |
| ARM64 | NEON SIMD; low power; Apple Silicon, AWS Graviton, mobile |
| RISC-V 64 | Open ISA; no guaranteed SIMD extensions; toolchain maturity varies |
| ESP32-class MCU | Xtensa LX6/LX7 or RISC-V; ~240 MHz; ~520 KB SRAM; no OS |

**Language × Target fit matrix (advisory, labelled as such):**

- C: strong fit for all targets; only language supporting all six
- C++: strong fit for x86-64, ARM64; limited for ESP32 (no exceptions, no RTTI)
- Rust: strong fit for x86-64, ARM64, RISC-V; growing ESP32 support
- Python: strong fit for x86-64; not suitable for bare-metal MCU targets
- Go: strong fit for x86-64, ARM64; no ESP32/RISC-V support
- Java: x86-64, ARM64 only; JVM not available on bare-metal
- JavaScript/TypeScript: x86-64 (Node/browser); not suitable for bare-metal

**`processor_fit(language, target)` returns:**
```
{
  "language": str,
  "target": str,
  "fit": "STRONG" | "PARTIAL" | "UNSUPPORTED" | "UNKNOWN",
  "reason": str,       # documented fact, not fabricated
  "notes": [str],      # advisory notes
  "advisory": True     # always True — never a guarantee
}
```

**UI (new tab "Processor Fit"):**
- Language selector (all supported languages + Custom)
- Target selector (all 6 targets)
- "Assess fit" button
- Shows fit pill, reason, advisory notes
- Disclaimer: "This is a static advisory matrix, not a measurement.
  Profile your actual workload on your actual hardware."

### Tests to add/update
- New `tests/test_processor_fit.py`:
  - `test_c_fits_all_targets` — C returns STRONG for all 6 targets
  - `test_python_unsupported_on_esp32`
  - `test_java_unsupported_on_riscv`
  - `test_unknown_language_returns_unknown`
  - `test_advisory_flag_always_true`
  - `test_all_targets_have_reason_text`

### Dependencies
None — static knowledge table, stdlib only.

### Acceptance criteria
- All 6 targets × all 8 languages produce a non-empty `reason`
- `advisory` is `True` in every response
- No runtime system calls or `platform` module queries
- All new tests pass

### Potential risks
- The matrix must not claim performance benchmarks; it can only state
  "toolchain supported" / "partially supported" / "not supported"

---

## Phase 4 — Debug & Fix Workflow

**Status:** [ ] pending

### Intent
Add a `debugger.py` module that performs static heuristic analysis of
uploaded source code to surface common bug categories without executing code.
The workflow maps to: scan → categorize findings → propose fix pattern.
No code is auto-modified; all suggestions are advisory.

### Existing files to modify
- `siliconfit/app.py` — add "Debug & Fix" tab

### New files required
- `siliconfit/debugger.py` — new module

### Features to implement

**Bug categories detected by static heuristic (per language):**

Python:
- Mutable default argument (`def f(x=[])`)
- `except:` without exception type (already in security; surface here as bug too)
- Shadowing a builtin name (`list = ...`, `id = ...`, `type = ...`)
- Missing `return` in function that has `return value` on some branches (heuristic)

C / C++:
- `malloc` without free (heuristic: malloc call with no corresponding free in same scope)
- Signed/unsigned comparison warning pattern (`int` vs `unsigned int`)
- `printf` format string with `%s` and no obvious null check

Rust:
- `.unwrap()` on a Result/Option (surface as potential panic, not a security issue)
- `todo!()` / `unimplemented!()` in non-test code

Go:
- Error return ignored (`:=` assignment where last return is `error`, never checked)
- `defer` inside a loop (performance / correctness issue)

JavaScript / TypeScript:
- `== null` instead of `=== null` (loose equality)
- `var` usage (prefer `let`/`const`)

**`debug_scan(filename, text)` returns:**
```
{
  "findings": [
    {
      "category": str,
      "severity": "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "line": int,
      "description": str,
      "fix_pattern": str,   # advisory text, never auto-applied
      "advisory": True
    }
  ],
  "count": int,
  "language": str
}
```

**UI tab "Debug & Fix":**
- Uses already-uploaded files from session state OR a fresh upload
- Per-file expandable findings list with severity pills
- "Fix pattern" shown as advisory text alongside each finding
- Disclaimer: "These are static heuristic findings. Verify before applying any change."

### Tests to add/update
- New `tests/test_debugger.py`:
  - `test_mutable_default_argument_detected`
  - `test_malloc_without_free_detected`
  - `test_unwrap_in_rust_detected`
  - `test_empty_input_returns_zero_findings`
  - `test_none_input_does_not_crash`
  - `test_advisory_always_true`
  - `test_fix_pattern_is_string`

### Dependencies
None — stdlib `re` only.

### Acceptance criteria
- `buggy_memory.c` produces at least 1 finding
- `sample_project.py` produces 0 HIGH findings
- `debug_scan(None, None)` returns `{"findings": [], "count": 0, ...}` without raising
- All new tests pass

### Potential risks
- Mutable-default and missing-return heuristics are line-level approximations;
  they will false-positive on some valid patterns — clearly label findings as
  ADVISORY and low-confidence

---

## Phase 5 — Testing and Behavior Verification Improvements

**Status:** [ ] pending

### Intent
Make Test Lab actually useful: show individual test names and
PASS/FAIL/ERROR/SKIPPED status by default.
Add a test template generator so developers can scaffold tests for
uploaded source files.
Add mutation-style completeness hints (not actual mutation testing —
no code execution required).

### Existing files to modify
- `siliconfit/test_runner.py`:
  - Change default command from `pytest -q` to `pytest -v` so per-test
    lines are emitted and `_parse()` works correctly
  - `_parse()`: also capture the summary line `N passed, M failed in Xs`
    as a final summary row (type = "summary")
  - `run_tests()` return dict: add `"summary_line": str` field
- `siliconfit/app.py` (Test Lab tab):
  - Update default command to `python -m pytest -v`
  - Show summary_line beneath the dataframe

### New files required
- `siliconfit/test_scaffold.py` — test template generator

### Features to implement

**`test_scaffold.generate_test_template(filename, text, language)` returns:**
```
{
  "template": str,   # source code of a minimal test file
  "functions_found": [str],
  "language": str,
  "advisory": True
}
```
- Detects top-level function names from the source using regex (not AST,
  to keep it dependency-free)
- Generates a pytest-style test stub for each detected function
- For C/C++: generates a comment-based test checklist (no pytest for C)
- Template is shown in a `st.code` block with a download button; never auto-saved

**Mutation completeness hints (advisory only):**
- Count branch keywords (`if`, `else`, `for`, `while`, `switch`, `match`)
  in the source
- Display as: "This file has N branch points. Consider at least one test
  per branch to achieve meaningful coverage."
- No actual coverage measurement — clearly labelled as a heuristic estimate

### Tests to add/update
- `tests/test_analyzers.py`: update benchmark test to use `-v` flag
- New `tests/test_test_scaffold.py`:
  - `test_generates_template_for_python`
  - `test_finds_function_names`
  - `test_empty_source_returns_empty_template`
  - `test_c_source_generates_checklist`
  - `test_advisory_flag_true`

### Dependencies
None.

### Acceptance criteria
- Running `pytest -v` on the test suite produces per-test rows in the UI
- `generate_test_template("fib.py", fibonacci_source, "Python")` returns
  a template containing `test_fibonacci`
- All new tests pass

### Potential risks
- Function-name regex for Python (`def \w+`) is simple and will match
  nested functions; acceptable for a template generator

---

## Phase 6 — Benchmark Improvements

**Status:** [ ] pending

### Intent
Make Benchmark Lab more informative: show a spark-line of per-run times,
report outlier runs, add a baseline comparison feature, and ensure p95
is statistically correct for all sample sizes.

### Existing files to modify
- `siliconfit/benchmark.py`:
  - Fix p95 formula (already planned in Phase 1; confirm done)
  - Add `"outliers": [float]` field: runs > median × 3 are flagged
  - Add `"cv": float` coefficient of variation (stddev / mean × 100)
    as a stability metric
  - Add `"baseline_delta_pct": float | None` when a `baseline_median`
    argument is passed (default None)
- `siliconfit/app.py` (Benchmark tab):
  - Show per-run samples as a `st.line_chart`
  - Show CV as a metric ("Lower is more stable")
  - Add optional baseline input (float, seconds) and show delta pill:
    PASS if new median <= baseline, WARN if within 10 %, BLOCK if > 10 % slower
  - Show outlier count if any runs were flagged

### New files required
None.

### Tests to add/update
- `tests/test_analyzers.py`:
  - `test_benchmark_cv_is_float`
  - `test_benchmark_outliers_empty_for_stable_command`
  - `test_benchmark_p95_gte_median`
  - `test_benchmark_baseline_delta_none_when_no_baseline`

### Dependencies
None — `statistics.stdev` is stdlib.

### Acceptance criteria
- `run_benchmark` returns `cv`, `outliers`, `baseline_delta_pct` in all cases
- p95 >= median for all sample sizes >= 1
- `st.line_chart` renders without error when samples list is non-empty
- All new tests pass

### Potential risks
- `statistics.stdev` raises `StatisticsError` for n < 2; guard with
  `cv = None` when `len(vals) < 2`

---

## Phase 7 — Release Gate Integration

**Status:** [ ] pending

### Intent
Extend `release_gate.py` to incorporate evidence from security, tests,
benchmarks, and deployment readiness — not just file discovery.
The gate must clearly distinguish between "check passed", "check WARN",
"check not run", and "check BLOCKED".
It must never claim READY FOR REVIEW if evidence is missing.

### Existing files to modify
- `siliconfit/release_gate.py`:
  - Accept optional `context` dict parameter carrying cached results
    from other modules (security scan, test run, benchmark, deployment)
  - Add checks:
    - Security: HIGH findings count > 0 → BLOCKED
    - Tests: last test run returncode != 0 → BLOCKED; not run → WARN
    - Benchmark: no evidence → WARN; failed → WARN
    - Deployment: all deployment checks PASS → PASS; any WARN → WARN
  - Each check emits status = one of PASS / WARN / BLOCKED / NOT_RUN
  - State logic: any BLOCKED → "BLOCKED"; any WARN → "REVIEW"; all PASS → "READY FOR REVIEW"
- `siliconfit/app.py` (Release Gate tab):
  - Pass `st.session_state` context (last scan, last test run, last security
    scan, last benchmark) into `release_assessment`
  - Show each evidence row with a pill

### New files required
None.

### Tests to add/update
- `tests/test_analyzers.py`:
  - `test_release_gate_blocked_by_high_security_findings`
  - `test_release_gate_warn_when_tests_not_run`
  - `test_release_gate_ready_when_all_pass`
  - `test_release_gate_not_run_vs_pass_distinct`

### Dependencies
None.

### Acceptance criteria
- A project with HIGH security findings is BLOCKED regardless of other checks
- A project with no test run recorded shows NOT_RUN for the test check
- A project with all checks PASS is READY FOR REVIEW
- All new tests pass

### Potential risks
- Session state may be missing on first page load; `context` must default
  to an empty dict and all sub-checks must treat missing evidence as NOT_RUN

---

## Phase 8 — Professional Streamlit UI and Missing Tabs

**Status:** [ ] pending

### Intent
Add the tabs that are missing from the current 11-tab layout.
Polish the existing tabs to match the defined final tab list.
No visual regressions on existing functionality.

**Target tab list (15 tabs):**
1. Dashboard (rename Overview; add summary cards for all pending checks)
2. Upload & Analyze (existing, minor enhancements)
3. Language Detection (promote language_tools; standalone language scan tab)
4. Processor Fit (new, from Phase 3)
5. Debug & Fix (new, from Phase 4)
6. Tests (rename Test Lab)
7. Benchmark (existing, enhanced in Phase 6)
8. Defensive Security (rename Security)
9. Public Security DB (new — curated static reference, NOT live CVE lookup)
10. Bob 2.0 Workflow (new — render bob_workflow.md steps interactively)
11. Developer Chat (new — structured Q&A backed by rule-based logic, no LLM)
12. Documentation (new — render README.md + AGENTS.md inline; download links)
13. Commit Message (new — rule-based conventional commit generator)
14. Engineering Report (rename Report)
15. Release Gate (existing, enhanced in Phase 7)

### Existing files to modify
- `siliconfit/app.py` — full tab restructure; add new tabs; rename existing

### New files required
- `siliconfit/public_security_db.py` — static reference module
- `siliconfit/commit_message.py` — conventional commit generator
- `siliconfit/developer_chat.py` — rule-based Q&A engine

### Features to implement

**Tab 1 – Dashboard:**
- Summary metric cards: files scanned, security findings, tests passed/failed,
  benchmark median, release gate state
- All sourced from `st.session_state`; shows "Not run" when evidence absent
- "Run all checks" button: calls scan, security, dependency, deployment in sequence

**Tab 3 – Language Detection (standalone):**
- Upload or enter filename + paste source
- Calls `language_from_filename` + `basic_source_stats`
- Shows language pill, stats table, and Language Advisor if goal entered

**Tab 9 – Public Security DB:**
- Static, curated list of well-known vulnerability classes per language
  (e.g. buffer overflow in C, SQL injection in Python/Java, prototype pollution in JS)
- Source: `public_security_db.py` — entirely static, no network calls
- Searchable by language and keyword
- Prominent disclaimer: "This is a static educational reference.
  It is not a CVE database and does not reflect your specific codebase."

**Tab 10 – Bob 2.0 Workflow:**
- Read and render `bob_workflow.md` steps
- Add interactive checkboxes so developer can tick off completed steps
- Show current step highlighted

**Tab 11 – Developer Chat:**
- Text input: developer asks a question about the project
- `developer_chat.answer(question, context)` matches question to a rule set
  and returns a structured answer
- Rules cover: "what tests failed?", "what are the security findings?",
  "what is the release state?", "how do I run benchmarks?", etc.
- Every answer shows a source badge: "From: test runner output" /
  "From: security scan" / "Advisory" / "Not available"
- No LLM; no fabrication; unanswered questions return "I don't have evidence
  for that yet. Run the relevant check first."

**Tab 13 – Commit Message:**
- Inputs: change type (feat/fix/docs/test/refactor/chore), scope (optional),
  description, breaking change flag
- `commit_message.generate(type, scope, description, breaking)` returns
  a Conventional Commits formatted string
- One-click copy button (`st.code` block)
- Never fabricates what was changed; uses only what the developer typed

**Tab 14 – Engineering Report:**
- Existing functionality preserved
- Add sections for: processor fit (if run), debug findings (if run),
  test results (if run)

### Tests to add/update
- New `tests/test_public_security_db.py`:
  - `test_c_has_buffer_overflow_entry`
  - `test_python_has_injection_entry`
  - `test_all_languages_have_entries`
- New `tests/test_commit_message.py`:
  - `test_feat_generates_correct_prefix`
  - `test_breaking_change_flag`
  - `test_scope_included_when_provided`
  - `test_empty_description_returns_error_not_crash`
- New `tests/test_developer_chat.py`:
  - `test_unknown_question_returns_not_available`
  - `test_security_question_with_no_context`
  - `test_answer_includes_source_badge`

### Dependencies
None.

### Acceptance criteria
- All 15 tabs render without error in Streamlit
- Dashboard shows "Not run" for checks that have not been executed
- Public Security DB search returns results for all 8 supported languages
- Commit message generator produces valid Conventional Commits format
- Developer Chat never returns a fabricated answer
- All new tests pass

### Potential risks
- Tab count increase may affect Streamlit tab rendering width;
  use short tab labels and test on a 1280px-wide viewport
- `st.session_state` key collisions between tabs; prefix all keys
  with tab name (e.g. `"bench_cmd"`, `"sec_last_result"`)

---

## Phase 9 — Bob 2.0 Workflow Integration and Documentation

**Status:** [ ] pending

### Intent
Wire the Bob 2.0 workflow steps to actual evidence from the platform.
Each step in the workflow should link to a tab and show its current
evidence status.
Update all documentation to reflect the final feature set.

### Existing files to modify
- `siliconfit/workflow.py` — add an optional `evidence` field to each
  step dict, populated from `context` (session state) when available
- `siliconfit/report.py` — add sections for processor fit, debug findings,
  test detail, benchmark CV
- `siliconfit/AGENTS.md` — update to reflect new modules and rules
- `siliconfit/README.md` — update feature list, tab names, usage instructions

### New files required
None (documentation updates only plus `workflow.py` enhancement).

### Features to implement
- `build_workflow(goal, root, context)`:
  - `context` is an optional dict from `st.session_state`
  - Each step dict gains `"evidence_status": "PASS" | "WARN" | "NOT_RUN"`
    based on available context
  - Step 4 (Tests): evidence_status derived from last test run returncode
  - Step 5 (Security): evidence_status derived from last security scan high count
  - Step 6 (Benchmark): evidence_status derived from last benchmark status
  - Step 8 (Release): evidence_status derived from last release gate state
- Bob 2.0 Workflow tab (Phase 8, Tab 10):
  - Render steps with their live evidence_status pills
  - Steps with NOT_RUN show a "Run now →" link to the relevant tab

### Tests to add/update
- `tests/test_analyzers.py`:
  - `test_build_workflow_returns_eight_steps`
  - `test_build_workflow_evidence_not_run_when_no_context`
  - `test_build_workflow_pass_when_tests_passed`

### Dependencies
None.

### Acceptance criteria
- `build_workflow` with empty context returns 8 steps, all evidence_status = NOT_RUN
- `build_workflow` with test context returncode=0 returns step 4 as PASS
- README accurately describes all 15 tabs
- All new tests pass

### Potential risks
- Context dict keys must match exactly what `app.py` writes to session state;
  document the key schema in a comment block in `app.py`

---

## Phase 10 — Final Testing, Regression Testing and Hackathon Demo Preparation

**Status:** [ ] pending

### Intent
Run the full test suite, fix any regressions, add integration-level
smoke tests, and prepare demo materials.
Verify the complete 15-tab UI starts cleanly and all tabs render
without crashing on an empty session.

### Existing files to modify
- All `tests/test_*.py` files — review for completeness
- `siliconfit/app.py` — final UI polish, consistent pill usage, no raw
  `st.error` for expected empty states

### New files required
- `siliconfit/tests/test_integration.py` — smoke tests that exercise
  the full pipeline on `sample_projects/`

### Features to implement

**Integration smoke tests (no UI, pure Python):**
- Full pipeline on `sample_project.py`: scan → language → debug → security → report
- Full pipeline on `security_demo.c`: scan → security (expect HIGH findings) → report
- Full pipeline on `buggy_memory.c`: scan → debug → security → report
- Release gate on a pristine copy of the repo root: expect READY FOR REVIEW
  (after all checks pass)

**Demo checklist (documented, not code):**
- Start app: `streamlit run app.py`
- Upload `security_demo.c` → show HIGH security findings
- Upload `buggy_memory.c` → show debug findings
- Upload `sample_project.py` → show clean result
- Run benchmark on `python -c "sum(i*i for i in range(100000))"`
- Run release gate → show evidence table
- Generate report → download

**Final validation:**
- `python -m pytest -v` passes with zero failures, zero errors
- `streamlit run app.py --server.headless true` starts without ImportError
- No module performs a network call
- No module fabricates results

### Tests to add/update
- `tests/test_integration.py`:
  - `test_full_pipeline_clean_python_file`
  - `test_full_pipeline_security_demo_c`
  - `test_full_pipeline_buggy_memory_c`
  - `test_report_contains_all_sections`
  - `test_no_module_calls_network` (assert `socket` not imported by any module)

### Dependencies
None.

### Acceptance criteria
- `python -m pytest -v` passes entirely
- Zero new warnings in Streamlit startup
- All 15 tabs visible and non-crashing with an empty project folder
- `security_demo.c` produces HIGH findings in the security tab
- Engineering report contains all 8 expected sections
- No fabricated evidence in any output

### Potential risks
- Integration tests that call `run_benchmark` execute real subprocesses;
  gate them behind a `RUN_INTEGRATION=1` environment variable to keep
  the default `pytest -q` run fast

---

## Cross-Phase Constraints (apply to all phases)

1. Every function that returns a dict must use `.get()` or `safe_get()` at all call sites.
2. No module may call a network endpoint. Verified in Phase 10.
3. All advisory outputs must include `"advisory": True` in their return dict
   AND a visible disclaimer in the UI.
4. Secret values detected in source code are NEVER rendered in the UI;
   show `[REDACTED]` in the finding row.
5. `python -m pytest -q` must pass after every phase before the next begins.
6. Tab key names in `app.py` are unique and prefixed with the tab short name.
7. The `_schema_version` field introduced in Phase 1 is incremented when
   a module's return shape changes in a breaking way.
