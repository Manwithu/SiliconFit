"""Public security reference database - Phase 8A.

LOCAL CURATED SECURITY REFERENCE - not a live CVE database.
CWE identifiers are included only where the mapping is confident.
No network access. No fabricated CVE data.
"""

# ---------------------------------------------------------------------------
# Curated vulnerability entries
# Format: {id, vuln_class, cwe, cwe_name, severity, languages, remediation, description}
# ---------------------------------------------------------------------------

ENTRIES = [
    {
        "id": "SF-001",
        "vuln_class": "Hard-coded Credentials",
        "cwe": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "severity": "HIGH",
        "languages": ["Python", "C", "C++", "Java", "JavaScript", "TypeScript", "Go", "Rust"],
        "remediation": "Store credentials in environment variables or a secrets manager. Never commit secrets to source control.",
        "description": "Credentials embedded directly in source code are exposed to anyone with repository access and cannot be rotated without a code change.",
    },
    {
        "id": "SF-002",
        "vuln_class": "SQL Injection",
        "cwe": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "severity": "HIGH",
        "languages": ["Python", "Java", "JavaScript", "TypeScript", "Go", "PHP"],
        "remediation": "Use parameterised queries or prepared statements. Never concatenate user input into SQL strings.",
        "description": "Unsanitised user input inserted into SQL queries allows attackers to read, modify, or delete database contents and bypass authentication.",
    },
    {
        "id": "SF-003",
        "vuln_class": "Command Injection",
        "cwe": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "severity": "HIGH",
        "languages": ["Python", "C", "C++", "Java", "JavaScript", "TypeScript", "Go"],
        "remediation": "Avoid shell=True and string concatenation for commands. Use argument arrays (execvp, subprocess list form). Validate and whitelist all inputs.",
        "description": "User-controlled input passed to a shell command allows attackers to execute arbitrary operating system commands.",
    },
    {
        "id": "SF-004",
        "vuln_class": "Buffer Overflow",
        "cwe": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
        "severity": "HIGH",
        "languages": ["C", "C++"],
        "remediation": "Replace strcpy with strlcpy/strncpy, sprintf with snprintf, gets with fgets. Enable compiler protections: -fstack-protector-strong, AddressSanitizer.",
        "description": "Writing beyond the bounds of a fixed-size buffer corrupts adjacent memory, enabling code execution or denial of service.",
    },
    {
        "id": "SF-005",
        "vuln_class": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "severity": "HIGH",
        "languages": ["JavaScript", "TypeScript"],
        "remediation": "Avoid innerHTML assignments with user data. Use textContent for plain text. Sanitise HTML with DOMPurify. Apply Content-Security-Policy headers.",
        "description": "Injecting malicious scripts into web pages allows attackers to steal session tokens, redirect users, or perform actions on their behalf.",
    },
    {
        "id": "SF-006",
        "vuln_class": "Insecure Deserialization",
        "cwe": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "severity": "HIGH",
        "languages": ["Python", "Java"],
        "remediation": "Avoid pickle/marshal/ObjectInputStream for untrusted data. Use JSON with schema validation. Sign serialized data if persistence is required.",
        "description": "Deserializing attacker-controlled data can execute arbitrary code during the reconstruction of objects.",
    },
    {
        "id": "SF-007",
        "vuln_class": "Use After Free",
        "cwe": "CWE-416",
        "cwe_name": "Use After Free",
        "severity": "HIGH",
        "languages": ["C", "C++"],
        "remediation": "Set pointers to NULL immediately after free(). Use AddressSanitizer during testing. Consider smart pointers in C++ (unique_ptr, shared_ptr).",
        "description": "Accessing memory after it has been freed can corrupt the heap, leak sensitive data, or allow code execution.",
    },
    {
        "id": "SF-008",
        "vuln_class": "NULL Pointer Dereference",
        "cwe": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
        "severity": "HIGH",
        "languages": ["C", "C++"],
        "remediation": "Always check for NULL before dereferencing pointers. Use assertions in debug builds. Enable compiler warnings (-Wall -Wextra).",
        "description": "Dereferencing a NULL pointer causes undefined behaviour, typically a segmentation fault and process termination.",
    },
    {
        "id": "SF-009",
        "vuln_class": "Path Traversal",
        "cwe": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "severity": "HIGH",
        "languages": ["Python", "Java", "JavaScript", "TypeScript", "Go", "C", "C++"],
        "remediation": "Canonicalise file paths with os.path.realpath/Path.resolve and verify they reside within the intended base directory before opening.",
        "description": "User-controlled file paths containing '../' sequences can access files outside the intended directory, exposing sensitive data.",
    },
    {
        "id": "SF-010",
        "vuln_class": "Prototype Pollution",
        "cwe": "CWE-1321",
        "cwe_name": "Improperly Controlled Modification of Object Prototype Attributes",
        "severity": "HIGH",
        "languages": ["JavaScript", "TypeScript"],
        "remediation": "Use Object.create(null) for property maps. Validate that user-supplied keys are not __proto__, constructor, or prototype. Use a library like lodash with known-safe merge functions.",
        "description": "Injecting properties into JavaScript's Object.prototype can corrupt all objects in the process and enable denial of service or code execution.",
    },
    {
        "id": "SF-011",
        "vuln_class": "Weak Randomness",
        "cwe": "CWE-338",
        "cwe_name": "Use of Cryptographically Weak Pseudo-Random Number Generator",
        "severity": "MEDIUM",
        "languages": ["Python", "Java", "Go"],
        "remediation": "Use cryptographically secure RNG: Python secrets module, java.security.SecureRandom, crypto/rand in Go.",
        "description": "Predictable random values used for tokens, passwords, or cryptographic keys allow attackers to guess or brute-force security-sensitive values.",
    },
    {
        "id": "SF-012",
        "vuln_class": "Unhandled Exception / Error Swallowing",
        "cwe": "CWE-390",
        "cwe_name": "Detection of Error Condition Without Action",
        "severity": "MEDIUM",
        "languages": ["Python", "Java", "JavaScript", "TypeScript", "Go"],
        "remediation": "Catch specific exceptions. Log all unexpected errors. Never use bare except: or empty catch blocks. In Go, handle every error return.",
        "description": "Silently swallowing exceptions hides failures, making bugs impossible to diagnose and leaving the application in an unknown state.",
    },
    {
        "id": "SF-013",
        "vuln_class": "Insecure TLS Configuration",
        "cwe": "CWE-295",
        "cwe_name": "Improper Certificate Validation",
        "severity": "MEDIUM",
        "languages": ["Go", "Java", "Python"],
        "remediation": "Never set InsecureSkipVerify=true or ALLOW_ALL_HOSTNAME_VERIFIER in production. Use a correctly configured TLS context with trusted CA certificates.",
        "description": "Disabling TLS certificate validation allows man-in-the-middle attackers to intercept and modify encrypted communications.",
    },
    {
        "id": "SF-014",
        "vuln_class": "Integer Overflow",
        "cwe": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound",
        "severity": "MEDIUM",
        "languages": ["C", "C++", "Rust"],
        "remediation": "Use checked arithmetic (checked_add in Rust). Validate that values remain within expected ranges before arithmetic operations.",
        "description": "Arithmetic overflow can produce unexpected values, leading to incorrect buffer sizes, infinite loops, or security bypass.",
    },
    {
        "id": "SF-015",
        "vuln_class": "Format String Vulnerability",
        "cwe": "CWE-134",
        "cwe_name": "Use of Externally-Controlled Format String",
        "severity": "HIGH",
        "languages": ["C", "C++"],
        "remediation": "Always use a literal format string: printf(\"%s\", user_input) never printf(user_input). Enable compiler warnings -Wformat -Wformat-security.",
        "description": "Passing user-controlled data as the printf format string allows reading stack memory, writing to arbitrary addresses, and code execution.",
    },
    {
        "id": "SF-016",
        "vuln_class": "Missing Memory Deallocation (Memory Leak)",
        "cwe": "CWE-401",
        "cwe_name": "Missing Release of Memory after Effective Lifetime",
        "severity": "MEDIUM",
        "languages": ["C", "C++"],
        "remediation": "Pair every malloc/calloc with a free(). Use RAII (unique_ptr) in C++. Run Valgrind or AddressSanitizer to detect leaks.",
        "description": "Failing to release allocated memory eventually exhausts the heap, causing denial of service; critical on MCU targets with limited RAM.",
    },
    {
        "id": "SF-017",
        "vuln_class": "eval() / Arbitrary Code Execution",
        "cwe": "CWE-95",
        "cwe_name": "Improper Neutralization of Directives in Dynamically Evaluated Code",
        "severity": "HIGH",
        "languages": ["Python", "JavaScript", "TypeScript"],
        "remediation": "Avoid eval() entirely. Use JSON.parse() for data, explicit dispatch tables for logic. If dynamic execution is unavoidable, use a strongly sandboxed environment.",
        "description": "Executing user-controlled code via eval() or new Function() allows attackers to run arbitrary code in the application's context.",
    },
    {
        "id": "SF-018",
        "vuln_class": "Unsafe Memory Operations in Rust",
        "cwe": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "severity": "MEDIUM",
        "languages": ["Rust"],
        "remediation": "Minimise unsafe blocks. Document safety invariants with SAFETY comments. Use safe wrappers where possible. Review all unsafe code in security audits.",
        "description": "Rust's unsafe blocks bypass memory-safety guarantees and can introduce the same vulnerabilities as C/C++ code if misused.",
    },
    {
        "id": "SF-019",
        "vuln_class": "Unhandled Promise Rejection",
        "cwe": "CWE-755",
        "cwe_name": "Improper Handling of Exceptional Conditions",
        "severity": "MEDIUM",
        "languages": ["JavaScript", "TypeScript"],
        "remediation": "Append .catch() to every promise chain, or use async/await with try/catch. Register process.on('unhandledRejection') as a last resort.",
        "description": "Unhandled promise rejections can silently fail or crash the Node.js process, leading to data loss or service interruption.",
    },
    {
        "id": "SF-020",
        "vuln_class": "Debug Mode Left Enabled",
        "cwe": "CWE-489",
        "cwe_name": "Active Debug Code",
        "severity": "LOW",
        "languages": ["Python", "JavaScript", "TypeScript", "Java"],
        "remediation": "Set DEBUG=False in production. Control debug flags via environment variables, not hard-coded values.",
        "description": "Debug mode may expose stack traces, internal state, and verbose error messages to end users or attackers.",
    },
]


def get_all():
    """Return all curated entries. Never raises."""
    return list(ENTRIES)


def search(language=None, keyword=None, severity=None):
    """Filter entries by language, keyword, and/or severity.

    All filters are case-insensitive substring matches.
    Returns a list of matching entry dicts.
    """
    results = list(ENTRIES)

    if language:
        lang_lower = language.strip().lower()
        results = [
            e for e in results
            if any(lang_lower in l.lower() for l in e["languages"])
        ]

    if severity:
        sev_upper = severity.strip().upper()
        results = [e for e in results if e.get("severity") == sev_upper]

    if keyword:
        kw = keyword.strip().lower()
        results = [
            e for e in results
            if kw in e.get("vuln_class", "").lower()
            or kw in e.get("description", "").lower()
            or kw in e.get("remediation", "").lower()
            or kw in e.get("cwe_name", "").lower()
        ]

    return results


DISCLAIMER = (
    "LOCAL CURATED SECURITY REFERENCE - not a live CVE database. "
    "CWE identifiers are included only where the mapping is confident. "
    "No CVE data is fabricated. This reference does not reflect your specific codebase. "
    "No network access is required or performed."
)
