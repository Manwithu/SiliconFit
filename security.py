"""Defensive security scanner — static pattern analysis only.

Supported languages: Python, C, C++, Rust, Go, Java, JavaScript, TypeScript.

Rules:
- Never display matched secret values.
- Never claim a clean scan means code is secure.
- All findings are advisory; no finding is proof of exploitability.
- Patterns are deterministic regex; no AI, no network, no fabrication.
"""

from pathlib import Path
import re

# ---------------------------------------------------------------------------
# Pattern table format:
#   (severity, title, regex_pattern, reason, remediation, regression_test)
#
# Severity: "HIGH" | "MEDIUM" | "LOW"
# ---------------------------------------------------------------------------

# Extensions grouped by language family for pattern dispatch.
_PY_EXTS   = {".py", ".pyw"}
_C_EXTS    = {".c", ".h"}
_CPP_EXTS  = {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
_RUST_EXTS = {".rs"}
_GO_EXTS   = {".go"}
_JAVA_EXTS = {".java"}
_JS_EXTS   = {".js", ".mjs", ".jsx"}
_TS_EXTS   = {".ts", ".tsx"}

_C_ALL_EXTS = _C_EXTS | _CPP_EXTS   # patterns shared between C and C++

# All extensions the scanner will process.
_JSON_EXTS = {".json"}
ALL_EXTENSIONS = _PY_EXTS | _C_EXTS | _CPP_EXTS | _RUST_EXTS | _GO_EXTS | _JAVA_EXTS | _JS_EXTS | _TS_EXTS | _JSON_EXTS


# ---------------------------------------------------------------------------
# Python patterns  (original 5 rules preserved; extended with new ones)
# ---------------------------------------------------------------------------
_PAT_PYTHON = [
    (
        "HIGH",
        "Potential hard-coded secret/token",
        r"(?i)(api[_-]?key|secret|password|token|private[_-]?key|passwd|auth[_-]?token)\s*=\s*[\"'][^\"']{8,}[\"']",
        "A credential or secret appears to be hard-coded in source code.",
        "Move secrets to environment variables or a secrets manager. Never commit credentials to source control.",
        "assert scan_text('demo.py', 'api_key = \"abcdefgh12345678\"')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Shell command boundary uses user-controlled source",
        r"(?i)(os\.system|subprocess\.(run|Popen|call|check_output|check_call))\s*\([^\n]*(input\(|request\.|argv|sys\.stdin)",
        "A shell command is constructed from user-controlled input, risking command injection.",
        "Use subprocess with a list of arguments (not shell=True) and never pass untrusted input directly.",
        "assert scan_text('a.py', 'os.system(input())')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Potential PEM private key material",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE KEY",
        "A PEM private key header was found embedded in source code.",
        "Remove private key material from source. Store keys outside the repository using a secrets manager.",
        "assert scan_text('k.py', '-----BEGIN PRIVATE KEY')[\"high\"] >= 1",
    ),
    (
        "MEDIUM",
        "Weak randomness API",
        r"\brandom\.(random|randint|randrange|choice|choices|shuffle)\s*\(",
        "The 'random' module is not cryptographically secure and must not be used for security-sensitive values.",
        "Use 'secrets' module or 'os.urandom' for tokens, passwords, and cryptographic keys.",
        "assert scan_text('r.py', 'random.randint(0,9)')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Unsafe deserialization (pickle)",
        r"\bpickle\.loads?\s*\(",
        "pickle.load/loads can execute arbitrary code when deserialising untrusted data.",
        "Avoid pickle for untrusted data. Use JSON or a schema-validated format instead.",
        "assert scan_text('p.py', 'pickle.loads(data)')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Unsafe deserialization (marshal/shelve/yaml.load)",
        r"\b(marshal\.loads?\s*\(|shelve\.open\s*\(|yaml\.load\s*\([^\n]*(?!Loader\s*=\s*yaml\.SafeLoader))",
        "marshal, shelve, and yaml.load without SafeLoader can execute arbitrary code.",
        "Use yaml.safe_load() instead of yaml.load(). Avoid marshal/shelve for untrusted input.",
        "assert scan_text('y.py', 'yaml.load(data)')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Use of eval() or exec()",
        r"\b(eval|exec)\s*\([^\n]*(input\(|request\.|argv|open\(|read\()",
        "eval/exec with user-controlled input can execute arbitrary code.",
        "Avoid eval/exec entirely. If dynamic dispatch is needed, use a safe allowlist-based approach.",
        "assert scan_text('e.py', 'eval(input())')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "SQL query string concatenation",
        r"(?i)(execute|cursor\.execute)\s*\([^\n]*(\"[^\"]*\"\s*\+|f\"|%\s*\(|\.format\s*\()",
        "String-concatenated or f-string SQL queries are vulnerable to SQL injection.",
        "Use parameterised queries (cursor.execute(sql, params)) and never embed user input in SQL strings.",
        "assert scan_text('db.py', 'cursor.execute(\"SELECT * FROM users WHERE id=\" + uid)')[\"medium_low\"] >= 1",
    ),
    (
        "LOW",
        "Bare exception handler",
        r"except\s*:\s*$",
        "A bare 'except:' silently swallows all exceptions including KeyboardInterrupt and SystemExit.",
        "Catch specific exception types. Log or re-raise unexpected exceptions.",
        "assert scan_text('x.py', 'except:\\n    pass')[\"count\"] >= 1",
    ),
    (
        "LOW",
        "Hardcoded IP address",
        r"(?<!\d)(\d{1,3}\.){3}\d{1,3}(?!\d)",
        "A literal IP address may represent a hard-coded server endpoint that is difficult to rotate.",
        "Use configuration files or environment variables for network addresses.",
        "assert scan_text('h.py', 'HOST = \"192.168.1.1\"')[\"count\"] >= 1",
    ),
    (
        "LOW",
        "Debug/verbose flag left enabled",
        r"(?i)\b(DEBUG|VERBOSE)\s*=\s*True\b",
        "DEBUG=True in production code may expose stack traces and internal state.",
        "Set DEBUG=False in production. Use environment variables to control debug mode.",
        "assert scan_text('s.py', 'DEBUG = True')[\"count\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# C / C++ patterns
# ---------------------------------------------------------------------------
_PAT_C = [
    (
        "HIGH",
        "Potential hard-coded secret/token (C/C++)",
        # Single pattern with optional [] for array declarations.
        r'(?i)(api[_-]?key|secret|password|token|private[_-]?key|passwd)\s*(?:\[[^\]]*\])?\s*=\s*"[^"]{8,}"'
        r'|"sk_live_[A-Za-z0-9]{8,}"'
        r'|"sk_test_[A-Za-z0-9]{8,}"',
        "A credential or secret appears to be hard-coded in source code.",
        "Move secrets to environment variables or a secure configuration store. Never commit credentials to source.",
        "assert scan_text('demo.c', 'char api_key[] = \"sk_live_abc12345\";')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Potential PEM private key material",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE KEY",
        "A PEM private key header was found embedded in source code.",
        "Remove private key material from source. Store keys outside the repository.",
        "assert scan_text('k.c', '-----BEGIN PRIVATE KEY')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Unsafe string copy: strcpy()",
        r"\bstrcpy\s*\(",
        "strcpy() does not check destination buffer size and can cause a stack/heap buffer overflow.",
        "Replace with strlcpy() or strncpy() with explicit size. Validate that source length < destination capacity.",
        "assert scan_text('s.c', 'strcpy(buf, input);')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Unsafe line input: gets()",
        r"\bgets\s*\(",
        "gets() reads an unbounded line from stdin and will always overflow a fixed buffer.",
        "Replace with fgets(buf, sizeof(buf), stdin) to enforce a maximum read length.",
        "assert scan_text('g.c', 'gets(buffer);')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Shell command execution: system()",
        r"\bsystem\s*\(",
        "system() passes a string to the shell, creating a command injection surface when the argument is not fully controlled.",
        "Prefer execvp/execve with a fixed argv array. Never pass user-controlled strings to system().",
        "assert scan_text('s.c', 'system(cmd);')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Shell command execution: popen()",
        r"\bpopen\s*\(",
        "popen() passes a command string to a shell, which is vulnerable to injection if the string includes user input.",
        "Build the argument list as an array and use posix_spawn or execvp instead of popen.",
        "assert scan_text('p.c', 'popen(cmd, \"r\");')[\"high\"] >= 1",
    ),
    (
        "MEDIUM",
        "Unsafe string formatting: sprintf()",
        r"\bsprintf\s*\(",
        "sprintf() does not limit output length and can overflow the destination buffer.",
        "Replace with snprintf() and always check the return value against the destination buffer size.",
        "assert scan_text('f.c', 'sprintf(buf, fmt, arg);')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Unsafe string formatting: vsprintf()",
        r"\bvsprintf\s*\(",
        "vsprintf() does not limit output length and can overflow the destination buffer.",
        "Replace with vsnprintf() and verify the returned length.",
        "assert scan_text('f.c', 'vsprintf(buf, fmt, ap);')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Unsafe memory allocation: malloc() without NULL check",
        # Allow nested parentheses (e.g. sizeof(int)) by matching up to the statement semicolon.
        r"\bmalloc\s*\([^;]+\);",
        "malloc() returns NULL on allocation failure. Using the result without a NULL check causes undefined behaviour.",
        "Always check that malloc() did not return NULL before using the pointer.",
        "assert scan_text('m.c', 'int *p = malloc(n * sizeof(int));')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Format-string risk: printf with variable first argument",
        r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]",
        "Passing a variable as the printf format string enables format-string injection attacks.",
        "Always use a literal format string: printf(\"%s\", user_input) instead of printf(user_input).",
        "assert scan_text('f.c', 'printf(user_buf);')[\"medium_low\"] >= 1",
    ),
    (
        "LOW",
        "Unbounded string length check: strlen() on unvalidated input",
        r"\bstrlen\s*\(",
        "strlen() on a non-null-terminated buffer leads to out-of-bounds reads.",
        "Ensure all strings passed to strlen() are null-terminated and originate from controlled sources.",
        "assert scan_text('l.c', 'n = strlen(input);')[\"count\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# Rust patterns
# ---------------------------------------------------------------------------
_PAT_RUST = [
    (
        "HIGH",
        "Potential hard-coded secret/token (Rust)",
        r'(?i)(api[_-]?key|secret|password|token|private[_-]?key|passwd)\s*[:=]\s*"[^"]{8,}"'
        r'|"sk_live_[A-Za-z0-9]{8,}"'
        r'|"sk_test_[A-Za-z0-9]{8,}"',
        "A credential or secret appears to be hard-coded in source code.",
        "Use environment variables (std::env::var) or the 'secrecy' crate. Never hard-code credentials.",
        "assert scan_text('demo.rs', 'let api_key = \"abcdefgh12345678\";')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Potential PEM private key material",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE KEY",
        "A PEM private key header was found embedded in source code.",
        "Remove private key material from source. Store keys outside the repository.",
        "assert scan_text('k.rs', '-----BEGIN PRIVATE KEY')[\"high\"] >= 1",
    ),
    (
        "MEDIUM",
        "Unsafe block",
        r"\bunsafe\s*\{",
        "An 'unsafe' block bypasses Rust's memory-safety guarantees. All unsafe code requires manual review.",
        "Minimise unsafe blocks. Document the safety invariants with a SAFETY comment and consider safe wrappers.",
        "assert scan_text('u.rs', 'unsafe { *ptr = 1; }')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Shell command execution (Rust std::process::Command with shell)",
        r'Command::new\s*\(\s*"(sh|bash|cmd|powershell)"',
        "Spawning a shell via std::process::Command is a command injection surface if arguments are user-controlled.",
        "Invoke the binary directly with explicit argument lists instead of spawning a shell.",
        "assert scan_text('c.rs', 'Command::new(\"sh\")')[\"medium_low\"] >= 1",
    ),
    (
        "LOW",
        "Potential panic from unwrap()",
        r"\.unwrap\s*\(\s*\)",
        ".unwrap() panics on None/Err in production code, causing uncontrolled process termination.",
        "Replace .unwrap() with .expect(\"context\") in non-test code, or handle the error with match/if let.",
        "assert scan_text('u.rs', 'let v = result.unwrap();')[\"count\"] >= 1",
    ),
    (
        "LOW",
        "Unhandled todo!/unimplemented! macro",
        r"\b(todo!|unimplemented!)\s*\(",
        "todo!() and unimplemented!() panic unconditionally and must not reach production code paths.",
        "Replace with proper implementations or return a Result/Option before shipping.",
        "assert scan_text('t.rs', 'todo!()')[\"count\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# Go patterns
# ---------------------------------------------------------------------------
_PAT_GO = [
    (
        "HIGH",
        "Potential hard-coded secret/token (Go)",
        r'(?i)(apiKey|api_key|secret|password|token|privateKey|private_key|passwd)\s*[:=]+\s*"[^"]{8,}"'
        r'|"sk_live_[A-Za-z0-9]{8,}"'
        r'|"sk_test_[A-Za-z0-9]{8,}"',
        "A credential or secret appears to be hard-coded in source code.",
        "Use os.Getenv() or a secrets manager. Never hard-code credentials in Go source.",
        "assert scan_text('demo.go', 'apiKey := \"abcdefgh12345678\"')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Potential PEM private key material",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE KEY",
        "A PEM private key header was found embedded in source code.",
        "Remove private key material from source. Store keys outside the repository.",
        "assert scan_text('k.go', '-----BEGIN PRIVATE KEY')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Shell command execution via exec.Command with shell",
        r'exec\.Command\s*\(\s*"(sh|bash|/bin/sh|/bin/bash|cmd|powershell)"',
        "Invoking a shell through exec.Command creates a command injection surface when arguments include user input.",
        "Invoke the target binary directly with explicit arguments instead of spawning a shell.",
        "assert scan_text('c.go', 'exec.Command(\"sh\", \"-c\", userInput)')[\"high\"] >= 1",
    ),
    (
        "MEDIUM",
        "Weak randomness: math/rand",
        r'\brand\.(Intn|Int|Float64|Perm|Seed)\s*\(',
        "math/rand is not cryptographically secure and must not be used for security-sensitive values.",
        "Use crypto/rand for tokens, keys, and security-sensitive random values.",
        "assert scan_text('r.go', 'rand.Intn(100)')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "SQL query string concatenation (Go)",
        r'(?i)(db\.(Query|QueryRow|Exec)\s*\([^\n]*(\"[^\"]*\"\s*\+|\bfmt\.Sprintf\b))',
        "String-concatenated SQL is vulnerable to SQL injection.",
        "Use parameterised queries with ? or $N placeholders and never embed user data in query strings.",
        "assert scan_text('db.go', 'db.Query(\"SELECT * FROM t WHERE id=\" + id)')[\"medium_low\"] >= 1",
    ),
    (
        "LOW",
        "Ignored error return value",
        r"_\s*,\s*err\s*:?=",
        "Assigning the error return value to the blank identifier silently discards failures.",
        "Always check returned errors. Log or propagate them rather than discarding with '_'.",
        "assert scan_text('e.go', '_, err := os.Open(f)')[\"count\"] >= 1",
    ),
    (
        "LOW",
        "TLS InsecureSkipVerify set to true",
        r"InsecureSkipVerify\s*:\s*true",
        "Setting InsecureSkipVerify to true disables TLS certificate validation, enabling MITM attacks.",
        "Never set InsecureSkipVerify=true in production. Use a correctly configured tls.Config with a trusted CA pool.",
        "assert scan_text('t.go', 'InsecureSkipVerify: true')[\"count\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# Java patterns
# ---------------------------------------------------------------------------
_PAT_JAVA = [
    (
        "HIGH",
        "Potential hard-coded secret/token (Java)",
        r'(?i)(apiKey|api_key|secret|password|token|privateKey|private_key|passwd)\s*=\s*"[^"]{8,}"'
        r'|"sk_live_[A-Za-z0-9]{8,}"'
        r'|"sk_test_[A-Za-z0-9]{8,}"',
        "A credential or secret appears to be hard-coded in source code.",
        "Use environment variables, System.getenv(), or a secrets manager. Never hard-code credentials.",
        "assert scan_text('demo.java', 'String password = \"abcdefgh12345\";')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Potential PEM private key material",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE KEY",
        "A PEM private key header was found embedded in source code.",
        "Remove private key material from source. Store keys outside the repository.",
        "assert scan_text('k.java', '-----BEGIN PRIVATE KEY')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Shell command execution: Runtime.exec()",
        r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
        "Runtime.exec() with user-controlled strings is vulnerable to command injection.",
        "Use ProcessBuilder with an explicit argument list instead of passing a concatenated command string.",
        "assert scan_text('r.java', 'Runtime.getRuntime().exec(cmd)')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Unsafe deserialization: ObjectInputStream",
        r"\bnew\s+ObjectInputStream\s*\(",
        "Java's ObjectInputStream deserializes arbitrary class hierarchies and can execute arbitrary code.",
        "Avoid Java serialization for untrusted data. Use JSON/Protobuf with schema validation instead.",
        "assert scan_text('d.java', 'new ObjectInputStream(inputStream)')[\"high\"] >= 1",
    ),
    (
        "MEDIUM",
        "SQL query string concatenation (Java)",
        r'(?i)(Statement|PreparedStatement)\s+\w+\s*=.+\n?.*(createStatement|prepareStatement)\s*\(\s*"[^"]+"\s*\+',
        "Concatenated SQL queries are vulnerable to SQL injection.",
        "Use PreparedStatement with ? placeholders and pass parameters via setString/setInt.",
        "assert scan_text('db.java', 'stmt = conn.createStatement(); stmt.execute(\"SELECT * FROM t WHERE id=\" + id)')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "Weak randomness: java.util.Random",
        r"\bnew\s+Random\s*\(\s*\)",
        "java.util.Random is not cryptographically secure.",
        "Use java.security.SecureRandom for security-sensitive random values.",
        "assert scan_text('r.java', 'Random r = new Random();')[\"medium_low\"] >= 1",
    ),
    (
        "LOW",
        "printStackTrace() leaks internal details",
        r"\.printStackTrace\s*\(\s*\)",
        "printStackTrace() logs internal stack frames to stderr, which may leak sensitive path or class information.",
        "Use a structured logger (SLF4J, Logback) instead of printStackTrace().",
        "assert scan_text('e.java', 'e.printStackTrace()')[\"count\"] >= 1",
    ),
    (
        "LOW",
        "TLS hostname verification disabled",
        r"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER\s*\)",
        "Disabling hostname verification allows MITM attacks.",
        "Use a hostname verifier that validates the server certificate against the expected hostname.",
        "assert scan_text('t.java', 'ALLOW_ALL_HOSTNAME_VERIFIER')[\"count\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# JavaScript patterns
# ---------------------------------------------------------------------------
_PAT_JS = [
    (
        "HIGH",
        "Potential hard-coded secret/token (JavaScript)",
        r'(?i)(apiKey|api_key|secret|password|token|privateKey|private_key|passwd)\s*[:=]\s*["\'][^"\']{8,}["\']'
        r'|["\']sk_live_[A-Za-z0-9]{8,}["\']'
        r'|["\']sk_test_[A-Za-z0-9]{8,}["\']',
        "A credential or secret appears to be hard-coded in source code.",
        "Use environment variables (process.env) and a .env file excluded from version control.",
        "assert scan_text('demo.js', 'const apiKey = \"abcdefgh12345678\";')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Potential PEM private key material",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE KEY",
        "A PEM private key header was found embedded in source code.",
        "Remove private key material from source. Store keys outside the repository.",
        "assert scan_text('k.js', '-----BEGIN PRIVATE KEY')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Use of eval()",
        r"\beval\s*\(",
        "eval() executes arbitrary JavaScript, enabling code injection if the argument is user-controlled.",
        "Avoid eval() entirely. Use JSON.parse() for data and explicit function calls for dispatch.",
        "assert scan_text('e.js', 'eval(userInput)')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Use of new Function()",
        r"\bnew\s+Function\s*\(",
        "new Function() is equivalent to eval() and executes arbitrary code.",
        "Replace with explicit function definitions. Never pass user input to new Function().",
        "assert scan_text('f.js', 'new Function(userCode)()')[\"high\"] >= 1",
    ),
    (
        "HIGH",
        "Child process execution with shell: true",
        r"(?i)(child_process|exec|spawn|execSync|spawnSync)\s*[.(]",
        "child_process functions with user-controlled strings can execute arbitrary shell commands.",
        "Use spawn() with an explicit argument array and avoid shell: true. Validate all input.",
        "assert scan_text('c.js', 'exec(userInput)')[\"high\"] >= 1",
    ),
    (
        "MEDIUM",
        "Prototype pollution risk: assignment to __proto__",
        r"__proto__\s*\[|__proto__\s*=",
        "Assigning to __proto__ can corrupt the prototype chain for all objects (prototype pollution).",
        "Use Object.create(null) for safe property maps and validate that user-supplied keys are not '__proto__'.",
        "assert scan_text('pp.js', 'obj.__proto__ = evil')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "innerHTML assignment (XSS risk)",
        r"\.innerHTML\s*=",
        "Assigning user-controlled content to innerHTML executes embedded scripts (XSS).",
        "Use textContent for plain text. Sanitise HTML with DOMPurify before assigning to innerHTML.",
        "assert scan_text('x.js', 'el.innerHTML = userInput')[\"medium_low\"] >= 1",
    ),
    (
        "MEDIUM",
        "document.write() (XSS risk)",
        r"\bdocument\.write\s*\(",
        "document.write() with user-controlled input enables script injection.",
        "Avoid document.write(). Build DOM elements programmatically instead.",
        "assert scan_text('w.js', 'document.write(userInput)')[\"medium_low\"] >= 1",
    ),
    (
        "LOW",
        "Secret potentially logged to console",
        r"(?i)console\.(log|info|debug|warn)\s*\([^\n]*(password|secret|token|api[_-]?key)",
        "Logging credential-related values to the console may expose secrets in log aggregation systems.",
        "Never log credentials. Redact sensitive fields before logging.",
        "assert scan_text('l.js', 'console.log(password)')[\"count\"] >= 1",
    ),
    (
        "LOW",
        "Suspicious dependency version constraint (any/wildcard)",
        r'"[^"]+"\s*:\s*"\*"',
        "A wildcard (*) dependency version pins no minimum, allowing any future version including breaking or malicious ones.",
        "Pin to a specific version or a narrow range (e.g. ^1.2.3) in package.json.",
        "assert scan_text('p.json', '\"lodash\": \"*\"')[\"count\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# TypeScript patterns  (superset of JS patterns + TS-specific additions)
# ---------------------------------------------------------------------------
_PAT_TS = _PAT_JS + [
    (
        "MEDIUM",
        "Type assertion bypassing null check (as any)",
        r"\bas\s+any\b",
        "Casting to 'any' disables TypeScript's type system and can conceal null/undefined dereferences.",
        "Use proper type guards or unknown instead of any. Narrow types explicitly.",
        "assert scan_text('a.ts', 'const x = (value as any).secret')[\"medium_low\"] >= 1",
    ),
]

# ---------------------------------------------------------------------------
# Extension → pattern-list mapping
# ---------------------------------------------------------------------------
def _patterns_for_extension(ext):
    ext = (ext or "").lower()
    if ext in _PY_EXTS:
        return _PAT_PYTHON
    if ext in _C_EXTS:
        return _PAT_C
    if ext in _CPP_EXTS:
        return _PAT_C  # C++ uses the same C pattern set
    if ext in _RUST_EXTS:
        return _PAT_RUST
    if ext in _GO_EXTS:
        return _PAT_GO
    if ext in _JAVA_EXTS:
        return _PAT_JAVA
    if ext in _JS_EXTS:
        return _PAT_JS
    if ext in _TS_EXTS:
        return _PAT_TS
    # package.json and similar JSON manifests use the JS wildcard-dependency rule.
    if ext == ".json":
        return _PAT_JS
    return []


# ---------------------------------------------------------------------------
# Internal: build a single finding row from a regex match.
# The matched text is intentionally NOT included to prevent secret exposure.
# ---------------------------------------------------------------------------
def _make_finding(sev, title, reason, remediation, regression_test, filename, text, match_start):
    return {
        "severity": sev,
        "title": title,
        # Legacy alias kept for backward compatibility with existing UI code.
        "finding": title,
        "file": filename or "uploaded_file",
        "line": text.count("\n", 0, match_start) + 1,
        "reason": reason,
        "remediation": remediation,
        "regression_test": regression_test,
        # Matched value is deliberately withheld to avoid surfacing secrets.
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_text(filename, text):
    """Scan a single in-memory source blob.

    Language is inferred from the file extension in *filename*.
    Never raises.  Returns the same dict shape regardless of language.
    Secret values are never included in findings.
    """
    text = text or ""
    filename_str = str(filename or "uploaded_file")
    ext = Path(filename_str).suffix.lower() if filename_str else ""
    patterns = _patterns_for_extension(ext)

    findings = []
    for sev, title, pat, reason, remediation, regression_test in patterns:
        try:
            for m in re.finditer(pat, text, re.MULTILINE):
                findings.append(
                    _make_finding(sev, title, reason, remediation, regression_test,
                                  filename_str, text, m.start())
                )
        except Exception:
            # A bad pattern must never crash the scanner.
            continue

    high   = sum(f["severity"] == "HIGH"   for f in findings)
    medium = sum(f["severity"] == "MEDIUM" for f in findings)
    low    = sum(f["severity"] == "LOW"    for f in findings)
    score  = max(0, 100 - high * 25 - medium * 10 - low * 3)

    return {
        "count": len(findings),
        "high": high,
        "medium_low": medium + low,
        "findings": findings,
        "score": score,
        "score_label": "Prototype static-analysis score — not a security guarantee.",
        "language": _ext_to_language(ext),
    }


def security_scan(root):
    """Recursively scan all supported source files under *root*.

    Returns the same shape as scan_text plus a per-file breakdown.
    Never raises.
    """
    root = Path(root)
    findings = []
    _SKIP = {".venv", "venv", "node_modules", "__pycache__", ".git", ".pytest_cache"}

    if not root.exists():
        return {"count": 0, "high": 0, "medium_low": 0, "findings": [],
                "score": 100,
                "score_label": "Prototype static-analysis score — not a security guarantee."}

    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in _SKIP):
            continue
        ext = f.suffix.lower()
        if ext not in ALL_EXTENSIONS:
            continue
        patterns = _patterns_for_extension(ext)
        if not patterns:
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        filename_rel = str(f.relative_to(root))
        for sev, title, pat, reason, remediation, regression_test in patterns:
            try:
                for m in re.finditer(pat, txt, re.MULTILINE):
                    findings.append(
                        _make_finding(sev, title, reason, remediation, regression_test,
                                      filename_rel, txt, m.start())
                    )
            except Exception:
                continue

    high = sum(x["severity"] == "HIGH" for x in findings)
    score = max(0, 100 - high * 25 - sum(x["severity"] == "MEDIUM" for x in findings) * 10
                - sum(x["severity"] == "LOW" for x in findings) * 3)
    return {
        "count": len(findings),
        "high": high,
        "medium_low": len(findings) - high,
        "findings": findings,
        "score": score,
        "score_label": "Prototype static-analysis score — not a security guarantee.",
    }


def _ext_to_language(ext):
    _map = {
        **{e: "Python"     for e in _PY_EXTS},
        **{e: "C"          for e in _C_EXTS},
        **{e: "C++"        for e in _CPP_EXTS},
        **{e: "Rust"       for e in _RUST_EXTS},
        **{e: "Go"         for e in _GO_EXTS},
        **{e: "Java"       for e in _JAVA_EXTS},
        **{e: "JavaScript" for e in _JS_EXTS},
        **{e: "TypeScript" for e in _TS_EXTS},
    }
    return _map.get(ext, "Unknown")
