# SiliconFit Secure

|**Security -- Debug -- Fix -- Test -- Optimize -- Verify -- Release**|

A deterministic developer workflow platform that turns a problem into evidence:
technology choice, workflow plan, security scan, debug analysis, processor-fit assessment,
benchmark measurements, deployment checklist, and release gate.

## Architecture

```
BOB 2.0          = Orchestrator (guides the session)
SILICONFIT       = Deterministic evidence engine
DEVELOPER        = Final decision maker
```

## Features

| Tab | Feature |
|-----|---------|
| Dashboard | Project status, all check summaries |
| Upload & Analyze | Multi-file upload, language detection, security + debug snapshot |
| Processor Fit | Language × target compatibility matrix + source heuristics |
| Debug & Fix | Static heuristic bug/reliability analysis |
| Tests | Test discovery, execution, PASS/FAIL/ERROR/SKIPPED parsing |
| Benchmark | Wall-clock timing, CV, outliers, baseline comparison |
| Defensive Security | Multi-language static security scanner |
| Public Security DB | Local curated CWE reference (not a live CVE database) |
| Bob 2.0 Workflow | Evidence-driven workflow with live step status |
| Developer Chat | Rule-based Q&A from session evidence |
| Documentation | Inline README + AGENTS.md |
| Commit Message | Conventional Commits generator |
| Dependencies | Dependency manifest health |
| Deployment | Deployment readiness checklist |
| Release Gate | Evidence-based gate (security + tests + debug + benchmark) |
| Engineering Report | Downloadable Markdown report |

## Supported Languages

C · C++ · Python · Rust · Go · Java · JavaScript · TypeScript · Custom

## Processor Targets

Generic x86-64 · Intel x86-64 · AMD x86-64 · ARM64 · RISC-V 64 · ESP32-class MCU

## Installation

Fully local — `streamlit` + `pytest` only. No cloud AI API, no API key.

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pytest -v
streamlit run app.py
```

## Running tests without internet access

```bash
python -c "import sys; sys.path.insert(0,'siliconfit'); sys.path.insert(0,'siliconfit/tests'); import pytest; pytest.main(['-v','siliconfit/tests'])"
```

## Key constraints

- Never fabricate test results, benchmark values, security findings, or processor specs.
- All advisory outputs are labelled `advisory: True`.
- No Ollama, Granite, or cloud AI APIs.
- Secret values detected in source are never displayed.
- PASS ≠ secure; READY FOR REVIEW ≠ production-ready.

See `AGENTS.md` and `bob_workflow.md` for IBM Bob 2.0 usage.
