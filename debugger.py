"""Static heuristic debug analysis — Debug & Fix Workflow.

Identifies likely bugs and reliability issues across supported languages
by applying deterministic regex patterns to source code.

Rules:
- Never auto-modifies source code.
- All proposed fixes are advisory text for developer review.
- Findings are labelled CONFIRMED (deterministic evidence) or POTENTIAL (heuristic).
- Never claims a heuristic detection proves a bug exists.
- No Ollama, Granite, or cloud API calls.
- Never raises on None, empty, or malformed input.
- Reuses result_utils for safe dict access.
"""

import re
from pathlib import Path
from result_utils import safe_get  # noqa: F401 — available for callers

# ---------------------------------------------------------------------------
# Extension → language family (mirrors security.py groupings)
# ---------------------------------------------------------------------------

_PY_EXTS   = {".py", ".pyw"}
_C_EXTS    = {".c", ".h"}
_CPP_EXTS  = {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
_RUST_EXTS = {".rs"}
_GO_EXTS   = {".go"}
_JAVA_EXTS = {".java"}
_JS_EXTS   = {".js", ".mjs", ".jsx", ".json"}
_TS_EXTS   = {".ts", ".tsx"}

_ALL_SUPPORTED = _PY_EXTS | _C_EXTS | _CPP_EXTS | _RUST_EXTS | _GO_EXTS | _JAVA_EXTS | _JS_EXTS | _TS_EXTS


def _language_for_ext(ext):
    ext = (ext or "").lower()
    if ext in _PY_EXTS:   return "Python"
    if ext in _C_EXTS:    return "C"
    if ext in _CPP_EXTS:  return "C++"
    if ext in _RUST_EXTS: return "Rust"
    if ext in _GO_EXTS:   return "Go"
    if ext in _JAVA_EXTS: return "Java"
    if ext in _JS_EXTS:   return "JavaScript"
    if ext in _TS_EXTS:   return "TypeScript"
    return "Unknown"


# ---------------------------------------------------------------------------
# Pattern table format:
#
#   (
#     lang_set,          set of language names this pattern applies to, or {"ALL"}
#     severity,          "HIGH" | "MEDIUM" | "LOW"
#     title,             short human-readable title
#     pattern,           compiled-regex or raw string
#     confidence,        "CONFIRMED" | "POTENTIAL"
#     category,          one of the 13 bug categories
#     evidence_fmt,      format string; {match} is the raw match text (first 80 chars)
#     explanation,       why this is a problem
#     proposed_fix,      advisory fix description for developer review
#     regression_test,   what test to add
#   )
# ---------------------------------------------------------------------------

_PATTERNS = [

    # -----------------------------------------------------------------------
    # Python — None / null handling
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "Attribute access on potentially-None value",
        r"(\w+)\s*=\s*(?:None|re\.search|re\.match|re\.fullmatch|dict\.get|\.get\s*\()"
        r"[^\n]*\n[^\n]*\1\.",
        "POTENTIAL",
        "None/null handling",
        "Variable assigned from a nullable source, then immediately attribute-accessed.",
        "The variable may be None if the operation did not match/find a value.",
        "Check `if var is not None:` before accessing attributes or calling methods on the result.",
        "Test the code path where the nullable expression returns None.",
    ),
    (
        {"Python"},
        "MEDIUM",
        "dict.get() result used without None check",
        r"(\w+)\s*=\s*\w+\.get\s*\([^\)]+\)\s*\n[^\n]*\1\s*\[",
        "POTENTIAL",
        "Missing dictionary key",
        "Result of dict.get() (which can return None) used with subscript access on the next line.",
        "dict.get() returns None when the key is absent; subscript on None raises TypeError.",
        "Provide a default in .get(key, default) or guard with `if var is not None:`.",
        "Test the code path where the key is absent.",
    ),

    # -----------------------------------------------------------------------
    # Python — missing dictionary keys (direct bracket access on possibly-absent key)
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "Direct dictionary subscript on function return value",
        r'(?:result|data|response|resp|r|ret|out|output)\s*=\s*\w+\s*\([^\n]*\)\s*\n[^\n]*(?:result|data|response|resp|r|ret|out|output)\s*\[',
        "POTENTIAL",
        "Missing dictionary key",
        "Function return value subscripted directly without checking for key existence or None.",
        "If the function returns None or a dict without the expected key, a KeyError or TypeError will be raised.",
        "Use .get() with a default, or check `if key in result` before subscripting.",
        "Test the code path where the function returns None or a dict missing the key.",
    ),

    # -----------------------------------------------------------------------
    # Python — division by zero
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "HIGH",
        "Division by variable without zero check",
        r"/\s*(\w+)\b(?!\s*=)",
        "POTENTIAL",
        "Division by zero",
        "Division by a variable with no visible guard against zero on the preceding lines.",
        "If the denominator is zero a ZeroDivisionError is raised at runtime.",
        "Add an explicit check: `if denominator != 0:` before dividing, or use a safe-divide helper.",
        "Test with denominator = 0 and assert the expected behaviour (error or default value).",
    ),

    # -----------------------------------------------------------------------
    # Python — index / length errors
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "List/sequence indexed at position [0] without empty check",
        r"(\w+)\s*\[\s*0\s*\]",
        "POTENTIAL",
        "Index/length error",
        "Direct access to index 0 of a sequence without a prior length or emptiness check.",
        "If the sequence is empty, an IndexError is raised.",
        "Guard with `if var:` or `if len(var) > 0:` before accessing index 0.",
        "Test with an empty list/string as input.",
    ),
    (
        {"Python"},
        "MEDIUM",
        "list[-1] access without empty check",
        r"(\w+)\s*\[\s*-\s*1\s*\]",
        "POTENTIAL",
        "Index/length error",
        "Access to the last element via [-1] without a prior emptiness check.",
        "If the sequence is empty, an IndexError is raised.",
        "Guard with `if var:` before accessing [-1].",
        "Test with an empty list as input.",
    ),

    # -----------------------------------------------------------------------
    # Python — unsafe resource handling
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "File opened without context manager",
        r"\bopen\s*\([^\)]+\)(?!\s*as\b)(?!\s*\))",
        "POTENTIAL",
        "Unsafe resource handling",
        "File opened without a 'with' statement — file handle may not be closed on error.",
        "If an exception is raised before close(), the file descriptor leaks.",
        "Use `with open(...) as f:` to guarantee the file is closed on all code paths.",
        "Test that the file is closed even when the body raises an exception.",
    ),
    (
        {"Python"},
        "MEDIUM",
        "subprocess.Popen not closed or used in context manager",
        r"\bsubprocess\.Popen\s*\([^\n]*\)(?!\s*(?:as|__enter__))",
        "POTENTIAL",
        "Unsafe resource handling",
        "subprocess.Popen created without a 'with' statement or explicit .communicate()/.wait().",
        "The child process may become a zombie if .wait() or .communicate() is never called.",
        "Use `with subprocess.Popen(...) as p:` or call p.wait()/p.communicate() explicitly.",
        "Test that the child process is reaped even when the parent raises an exception.",
    ),

    # -----------------------------------------------------------------------
    # Python — exception handling problems
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "HIGH",
        "Bare except clause",
        r"^\s*except\s*:\s*$",
        "CONFIRMED",
        "Exception handling problem",
        "Bare `except:` clause — catches all exceptions including KeyboardInterrupt and SystemExit.",
        "Silently swallowing all exceptions hides bugs and prevents clean shutdown.",
        "Replace with `except Exception as e:` and log or re-raise the exception.",
        "Verify the handler does not swallow KeyboardInterrupt.",
    ),
    (
        {"Python"},
        "MEDIUM",
        "Exception caught and silently passed",
        r"except\s+(?:\w+(?:\s*,\s*\w+)*)?\s*(?:as\s+\w+)?\s*:\s*\n\s*pass\s*$",
        "CONFIRMED",
        "Exception handling problem",
        "Exception caught and immediately passed — error silently discarded.",
        "Silent exception swallowing hides failures and makes debugging extremely difficult.",
        "At minimum log the exception: `logger.exception('Context message')` or re-raise.",
        "Add a test that verifies the error is observable (logged or propagated).",
    ),

    # -----------------------------------------------------------------------
    # Python — subprocess / toolchain failure handling
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "subprocess.run returncode not checked",
        r"\bsubprocess\.run\s*\([^\n]*\)\s*(?!\s*\.\s*(?:check_returncode|returncode))",
        "POTENTIAL",
        "Subprocess/toolchain failure handling",
        "subprocess.run() result not checked for returncode != 0.",
        "A failed subprocess is silently ignored; the program continues with potentially invalid state.",
        "Check `result.returncode != 0` or pass `check=True` to raise on non-zero exit.",
        "Test with a command that exits with code 1 and verify the failure is handled.",
    ),

    # -----------------------------------------------------------------------
    # Python — potential infinite loops
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "while True without apparent break or return",
        r"while\s+True\s*:\s*\n(?:(?!\s*(?:break|return|raise|sys\.exit))[^\n]*\n){1,20}",
        "POTENTIAL",
        "Potential infinite loop",
        "while True loop with no visible break, return, raise, or sys.exit within the first ~20 lines.",
        "If the exit condition is never reached, the loop runs indefinitely.",
        "Ensure every code path through the loop body reaches a break, return, or raise.",
        "Test that the loop terminates for all expected inputs including edge cases.",
    ),

    # -----------------------------------------------------------------------
    # Python — unreachable / suspicious logic
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "LOW",
        "Code after return statement",
        r"\breturn\b[^\n]*\n(\s+)[^\s#\n][^\n]*\n\1",
        "POTENTIAL",
        "Unreachable or suspicious logic",
        "Statement(s) appear to follow a return at the same indentation level.",
        "Code after a return is unreachable and indicates a logic error.",
        "Remove the unreachable code or adjust the return placement.",
        "Verify with a coverage tool that the unreachable lines are never executed.",
    ),
    (
        {"Python"},
        "LOW",
        "Comparison to True/False with == instead of is",
        r"\b==\s*(?:True|False)\b|\b(?:True|False)\s*==\b",
        "POTENTIAL",
        "Unreachable or suspicious logic",
        "Boolean compared with == rather than 'is' or a direct truthiness check.",
        "Comparing with == is technically correct but is considered a code smell in Python; "
        "it can also be incorrect for objects that override __eq__.",
        "Use `if var:` / `if not var:` or `if var is True:` for identity checks.",
        "Verify the comparison produces the expected result for all relevant types.",
    ),

    # -----------------------------------------------------------------------
    # Python — malformed input handling
    # -----------------------------------------------------------------------
    (
        {"Python"},
        "MEDIUM",
        "int()/float() conversion without try/except",
        r"\b(?:int|float)\s*\(\s*(?![\d\"'])\w+",
        "POTENTIAL",
        "Malformed input handling",
        "int() or float() called on a variable that may contain non-numeric user input without error handling.",
        "If the input cannot be converted, a ValueError is raised.",
        "Wrap in try/except ValueError or validate input with str.isdigit() / a regex before converting.",
        "Test with non-numeric strings, empty strings, and None.",
    ),
    (
        {"Python"},
        "MEDIUM",
        "json.loads() without exception handling",
        r"\bjson\.loads\s*\([^\n]*\)(?!\s*#)",
        "POTENTIAL",
        "Malformed input handling",
        "json.loads() called without visible try/except around it.",
        "Malformed JSON input raises json.JSONDecodeError.",
        "Wrap in `try: ... except json.JSONDecodeError as e:` and handle or propagate the error.",
        "Test with invalid JSON strings: empty string, truncated JSON, non-JSON text.",
    ),

    # -----------------------------------------------------------------------
    # C / C++ — None/null handling
    # -----------------------------------------------------------------------
    (
        {"C", "C++"},
        "HIGH",
        "Pointer dereference without NULL check",
        r"\*\s*(\w+)(?!\s*=)[^\n;]*;(?![^\n]*if\s*\(\s*\1\s*(?:!=|==)\s*NULL)",
        "POTENTIAL",
        "None/null handling",
        "Pointer dereferenced without a prior NULL check on the same line or in the preceding lines.",
        "Dereferencing a NULL pointer causes undefined behaviour (typically SIGSEGV).",
        "Always check `if (ptr != NULL)` before dereferencing. Use assert() in debug builds.",
        "Test with NULL as the pointer argument and verify the NULL path is handled.",
    ),
    (
        {"C", "C++"},
        "HIGH",
        "malloc() result not checked for NULL",
        r"\bint\s*\*\s*\w+\s*=\s*malloc\s*\([^;]+\)\s*;(?!\s*\n[^\n]*if\s*\([^\)]*==\s*NULL)",
        "POTENTIAL",
        "None/null handling",
        "malloc() return value stored but not immediately checked for NULL.",
        "malloc() returns NULL on allocation failure; using the result without checking causes undefined behaviour.",
        "Check `if (ptr == NULL) { /* handle error */ }` immediately after every malloc() call.",
        "Test with allocation size larger than available memory (use mock or ulimit) to exercise the NULL path.",
    ),

    # -----------------------------------------------------------------------
    # C / C++ — index / length errors
    # -----------------------------------------------------------------------
    (
        {"C", "C++"},
        "HIGH",
        "Off-by-one in loop boundary (i <= n with array of size n)",
        r"for\s*\([^;]*;\s*\w+\s*<=\s*(\w+)\s*;[^\)]*\)[^\{]*\{[^\}]*\[\s*\w+\s*\]",
        "POTENTIAL",
        "Index/length error",
        "Loop iterates with `<= n` and accesses an array — likely off-by-one, writing past the array end.",
        "An array of size n has valid indices 0..n-1. Using `i <= n` writes to index n which is out of bounds.",
        "Change `i <= n` to `i < n` and verify the loop intent.",
        "Run under AddressSanitizer (-fsanitize=address) to detect the out-of-bounds access.",
    ),

    # -----------------------------------------------------------------------
    # C / C++ — unsafe resource handling
    # -----------------------------------------------------------------------
    (
        {"C", "C++"},
        "MEDIUM",
        "fopen() result not checked for NULL",
        r'\bfopen\s*\([^;]+\)\s*;(?!\s*\n[^\n]*if\s*\([^\)]*==\s*NULL)',
        "POTENTIAL",
        "Unsafe resource handling",
        "fopen() return value not immediately checked for NULL.",
        "fopen() returns NULL if the file cannot be opened; using the result without checking causes undefined behaviour.",
        "Check `if (fp == NULL) { perror(\"fopen\"); return -1; }` after every fopen() call.",
        "Test with a path that does not exist and verify the NULL path is handled.",
    ),
    (
        {"C", "C++"},
        "MEDIUM",
        "Memory allocated but no corresponding free() visible",
        r"\b(malloc|calloc|realloc)\s*\([^;]+\)\s*;",
        "POTENTIAL",
        "Unsafe resource handling",
        "Heap allocation detected. No corresponding free() visible in the immediate scope.",
        "Failure to free allocated memory causes heap leaks; on long-running processes or MCUs this is critical.",
        "Ensure every allocation path has a matching free() including all error exits.",
        "Run under Valgrind or AddressSanitizer to detect leaked allocations.",
    ),

    # -----------------------------------------------------------------------
    # C / C++ — exception / error handling
    # -----------------------------------------------------------------------
    (
        {"C", "C++"},
        "MEDIUM",
        "Return value of standard library call ignored",
        r"\b(printf|fprintf|fwrite|fread|fclose|rename|remove|mkdir)\s*\([^;]+\)\s*;",
        "POTENTIAL",
        "Exception handling problem",
        "Return value of a standard library function discarded without error checking.",
        "Standard library I/O functions return error indicators; ignoring them hides I/O failures.",
        "Check return values: `if (fclose(fp) != 0) { perror(\"fclose\"); }`",
        "Test on a read-only filesystem or with a closed file descriptor to exercise error paths.",
    ),

    # -----------------------------------------------------------------------
    # C / C++ — potential infinite loops
    # -----------------------------------------------------------------------
    (
        {"C", "C++"},
        "MEDIUM",
        "while(1) or for(;;) without visible break",
        r"\b(while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{(?:[^}](?!break))*?\}",
        "POTENTIAL",
        "Potential infinite loop",
        "Infinite loop construct without an obvious break statement in the body.",
        "If the exit condition is never met the loop runs indefinitely.",
        "Ensure every iteration path through the loop body reaches a break, return, or exit().",
        "Code review: trace all exit paths from the loop body.",
    ),

    # -----------------------------------------------------------------------
    # C / C++ — memory management
    # -----------------------------------------------------------------------
    (
        {"C", "C++"},
        "HIGH",
        "Use of freed memory (double-free or use-after-free pattern)",
        r"\bfree\s*\(\s*(\w+)\s*\)\s*;[^\n]*\n(?:[^\n]*\n){0,5}[^\n]*\b\1\b",
        "POTENTIAL",
        "Memory management issue",
        "Variable used after it has been passed to free(), suggesting potential use-after-free.",
        "Accessing memory after free() is undefined behaviour and a security vulnerability.",
        "Set the pointer to NULL immediately after free(): `free(ptr); ptr = NULL;` "
        "and check for NULL before any subsequent use.",
        "Run under AddressSanitizer (-fsanitize=address) to detect use-after-free at runtime.",
    ),

    # -----------------------------------------------------------------------
    # Rust — None / null handling
    # -----------------------------------------------------------------------
    (
        {"Rust"},
        "MEDIUM",
        "unwrap() on Option/Result — potential panic",
        r"\.unwrap\s*\(\s*\)",
        "CONFIRMED",
        "None/null handling",
        ".unwrap() call — panics if the value is None or Err.",
        "In production code .unwrap() will panic on None/Err, causing uncontrolled process termination.",
        "Replace with .expect(\"descriptive message\") in non-test code, or handle with match/if let/? operator.",
        "Test the code path that produces None/Err and verify the error is handled gracefully.",
    ),
    (
        {"Rust"},
        "LOW",
        "expect() used without descriptive message",
        r'\.expect\s*\(\s*""\s*\)',
        "POTENTIAL",
        "Exception handling problem",
        ".expect(\"\") called with an empty message — unhelpful panic message if it fires.",
        "An empty message makes the panic impossible to diagnose without source code.",
        "Provide a meaningful message: `.expect(\"Failed to open config file\")`.",
        "Verify the message is meaningful for every expect() call.",
    ),

    # -----------------------------------------------------------------------
    # Rust — index / length errors
    # -----------------------------------------------------------------------
    (
        {"Rust"},
        "MEDIUM",
        "Direct slice index without bounds check",
        r"(\w+)\s*\[\s*\d+\s*\](?!\s*=)",
        "POTENTIAL",
        "Index/length error",
        "Slice/array indexed with a literal integer without a visible bounds check.",
        "If the index exceeds the slice length, Rust panics with 'index out of bounds'.",
        "Use .get(index) which returns Option<T>, or verify the slice is large enough before indexing.",
        "Test with a slice shorter than the literal index.",
    ),

    # -----------------------------------------------------------------------
    # Rust — exception / subprocess handling
    # -----------------------------------------------------------------------
    (
        {"Rust"},
        "MEDIUM",
        "Command::output() or status() result unwrapped without error handling",
        r"Command::(?:output|status)\s*\(\s*\)\.unwrap",
        "POTENTIAL",
        "Subprocess/toolchain failure handling",
        "Process output/status unwrapped directly — panics if the process fails to spawn.",
        "If the executable is missing or cannot be executed, .unwrap() panics.",
        "Use `match cmd.output() { Ok(o) => ..., Err(e) => eprintln!(\"Failed: {}\", e) }`.",
        "Test with a command that does not exist and verify the error path.",
    ),

    # -----------------------------------------------------------------------
    # Go — error handling
    # -----------------------------------------------------------------------
    (
        {"Go"},
        "HIGH",
        "Error return value discarded with blank identifier",
        r"_\s*(?:,\s*_\s*)?=\s*\w+\s*\(",
        "POTENTIAL",
        "Exception handling problem",
        "Function return value(s) discarded entirely with '_'.",
        "Discarding all return values including errors means failures are silently ignored.",
        "Always handle error returns: `result, err := f(); if err != nil { ... }`.",
        "Test the error path and verify the caller handles or propagates the error.",
    ),
    (
        {"Go"},
        "MEDIUM",
        "nil pointer dereference risk — method called on possibly-nil interface",
        r"var\s+\w+\s+\w+(?:Interface|Reader|Writer|Closer|Handler)\b[^\n]*\n(?:[^\n]*\n){0,5}[^\n]*\.\w+\s*\(",
        "POTENTIAL",
        "None/null handling",
        "Interface variable declared without initialisation, then a method called on it.",
        "Calling a method on a nil interface value panics at runtime.",
        "Initialise the interface variable before use, or check `if v != nil` before calling methods.",
        "Test with a nil interface value and verify the nil case is handled.",
    ),
    (
        {"Go"},
        "MEDIUM",
        "http.Get / http.Post without response body close",
        r"\bhttp\.(?:Get|Post|Do)\s*\([^\n]*\)(?:[^\n]*\n){0,5}(?![^\n]*resp\.Body\.Close)",
        "POTENTIAL",
        "Unsafe resource handling",
        "HTTP response body not closed within the visible scope.",
        "Failure to close the response body leaks a TCP connection from the http.Client pool.",
        "Use `defer resp.Body.Close()` immediately after checking the error from http.Get/Post.",
        "Verify with a long-running test that connection count does not grow unboundedly.",
    ),

    # -----------------------------------------------------------------------
    # Java — null handling
    # -----------------------------------------------------------------------
    (
        {"Java"},
        "HIGH",
        "NullPointerException risk — method called on possibly-null reference",
        r"(\w+)\s*=\s*\w+\s*\([^\n]*\)\s*;\s*\n[^\n]*\1\s*\.\s*\w+\s*\(",
        "POTENTIAL",
        "None/null handling",
        "Method return value stored then immediately used without null check.",
        "If the method returns null a NullPointerException is thrown.",
        "Check `if (var != null)` before calling methods on the result, or use Optional<T>.",
        "Test the code path where the method returns null.",
    ),

    # -----------------------------------------------------------------------
    # Java — exception handling
    # -----------------------------------------------------------------------
    (
        {"Java"},
        "HIGH",
        "Empty catch block — exception silently swallowed",
        r"catch\s*\([^\)]+\)\s*\{\s*\}",
        "CONFIRMED",
        "Exception handling problem",
        "Empty catch block — exception is caught and silently discarded.",
        "Silent exception swallowing hides failures; the program continues in an unknown state.",
        "At minimum log the exception: `logger.error(\"Context\", e);` or re-throw as a runtime exception.",
        "Add a test that verifies the exception is observable (logged or propagated).",
    ),
    (
        {"Java"},
        "MEDIUM",
        "Resource not closed in finally / not using try-with-resources",
        r"\b(InputStream|OutputStream|Connection|Statement|ResultSet|BufferedReader)\b\s+\w+\s*=\s*new\s+[^\n]+\n(?:(?!try\s*\()[^\n]*\n){0,10}",
        "POTENTIAL",
        "Unsafe resource handling",
        "Java resource allocated without visible try-with-resources or finally block.",
        "Failure to close I/O resources leaks file descriptors or database connections.",
        "Use try-with-resources: `try (InputStream is = ...) { ... }` to guarantee close().",
        "Verify no resource leak with a leak-detection library (Netty's ResourceLeakDetector or similar).",
    ),

    # -----------------------------------------------------------------------
    # JavaScript / TypeScript — null / undefined handling
    # -----------------------------------------------------------------------
    (
        {"JavaScript", "TypeScript"},
        "MEDIUM",
        "Property access on possibly-undefined variable",
        r"(\w+)\s*=\s*(?:document\.(?:getElementById|querySelector)|req\.(?:body|query|params)|JSON\.parse)\s*\([^\n]*\)[^\n]*\n[^\n]*\1\.",
        "POTENTIAL",
        "None/null handling",
        "Variable assigned from a DOM query or parsed input, then property accessed without null check.",
        "document.getElementById returns null when the element is not found; accessing .property raises TypeError.",
        "Use optional chaining: `var?.property` or check `if (var !== null && var !== undefined)`.",
        "Test with a DOM that does not contain the queried element, or with null/undefined input.",
    ),
    (
        {"JavaScript", "TypeScript"},
        "MEDIUM",
        "JSON.parse() without try/catch",
        r"\bJSON\.parse\s*\([^\n]*\)(?!\s*\/\/)",
        "POTENTIAL",
        "Malformed input handling",
        "JSON.parse() called without visible try/catch.",
        "Malformed JSON input throws a SyntaxError.",
        "Wrap in try/catch: `try { data = JSON.parse(raw); } catch (e) { /* handle */ }`.",
        "Test with invalid JSON: empty string, truncated JSON, plain text.",
    ),
    (
        {"JavaScript", "TypeScript"},
        "MEDIUM",
        "Promise not caught — unhandled rejection risk",
        r"(?:fetch|axios\.get|axios\.post|\w+\.then\s*\([^\)]+\))(?![^\n]*\.catch)",
        "POTENTIAL",
        "Exception handling problem",
        "Promise chain without a visible .catch() handler.",
        "An unhandled promise rejection may silently fail or crash the Node.js process.",
        "Append `.catch(err => { /* handle */ })` to every promise chain, "
        "or use async/await with try/catch.",
        "Test the code path where the promise rejects and verify the rejection is handled.",
    ),

    # -----------------------------------------------------------------------
    # All languages — potential infinite loops (generic)
    # -----------------------------------------------------------------------
    (
        {"ALL"},
        "LOW",
        "TODO / FIXME comment near loop or error handling",
        r"(?:TODO|FIXME)\s*[:\-]?\s*.{10,}",
        "POTENTIAL",
        "Unreachable or suspicious logic",
        "TODO or FIXME comment found — indicates known incomplete or deferred logic.",
        "Known incomplete logic may indicate missing error handling, placeholder values, or deferred fixes.",
        "Review each TODO/FIXME and either implement the missing logic or document the accepted risk.",
        "Audit TODO/FIXME items before release and ensure none are in critical code paths.",
    ),
]


def _patterns_for_language(language):
    """Return patterns applicable to the given language name."""
    result = []
    for entry in _PATTERNS:
        lang_set = entry[0]
        if "ALL" in lang_set or language in lang_set:
            result.append(entry)
    return result


def _make_finding(severity, title, filename, line, confidence, category,
                  evidence, explanation, proposed_fix, regression_test):
    return {
        "severity": severity,
        "title": title,
        "file": filename or "uploaded_file",
        "line": line,
        "confidence": confidence,
        "category": category,
        "evidence": evidence,
        "explanation": explanation,
        "proposed_fix": proposed_fix,
        "regression_test": regression_test,
        "advisory": True,
        "disclaimer": (
            "This is a static heuristic finding. "
            "CONFIRMED means deterministic evidence (e.g. exact syntax). "
            "POTENTIAL means a pattern that often indicates a bug but is not guaranteed. "
            "Verify before applying any proposed fix."
        ),
    }


def debug_scan(filename, text):
    """Scan a single source file for debug/reliability findings.

    Returns a dict with 'findings', counts, and metadata.
    Never raises.  Never auto-modifies source code.
    """
    text = text or ""
    filename_str = str(filename or "uploaded_file")
    ext = Path(filename_str).suffix.lower()
    language = _language_for_ext(ext)

    if not text.strip():
        return _empty_result(filename_str, language)

    patterns = _patterns_for_language(language)
    if not patterns:
        return _empty_result(filename_str, language)

    findings = []

    for (lang_set, severity, title, pattern, confidence, category,
         evidence_fmt, explanation, proposed_fix, regression_test) in patterns:
        try:
            for m in re.finditer(pattern, text, re.MULTILINE):
                line = text.count("\n", 0, m.start()) + 1
                match_text = m.group(0)[:80].replace("\n", " ")
                evidence = f"Matched: `{match_text}`"
                findings.append(_make_finding(
                    severity, title, filename_str, line, confidence, category,
                    evidence, explanation, proposed_fix, regression_test,
                ))
        except Exception:
            # A malformed pattern must never crash the scanner.
            continue

    high   = sum(f["severity"] == "HIGH"   for f in findings)
    medium = sum(f["severity"] == "MEDIUM" for f in findings)
    low    = sum(f["severity"] == "LOW"    for f in findings)
    confirmed  = sum(f["confidence"] == "CONFIRMED"  for f in findings)
    potential  = sum(f["confidence"] == "POTENTIAL"  for f in findings)

    return {
        "file": filename_str,
        "language": language,
        "findings": findings,
        "count": len(findings),
        "high": high,
        "medium": medium,
        "low": low,
        "confirmed": confirmed,
        "potential": potential,
        "advisory": True,
        "disclaimer": (
            "All findings are static heuristic results. "
            "No code was executed. "
            "Proposed fixes are advisory only — review and test before applying. "
            "No source code was modified."
        ),
    }


def debug_scan_text(filename, text):
    """Alias for debug_scan — matches scan_text naming convention."""
    return debug_scan(filename, text)


def _empty_result(filename_str, language):
    return {
        "file": filename_str,
        "language": language,
        "findings": [],
        "count": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "confirmed": 0,
        "potential": 0,
        "advisory": True,
        "disclaimer": (
            "All findings are static heuristic results. "
            "No code was executed. "
            "Proposed fixes are advisory only — review and test before applying. "
            "No source code was modified."
        ),
    }
