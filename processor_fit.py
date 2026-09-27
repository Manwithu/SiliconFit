"""Processor Fit and hardware-aware source analysis.

This module provides two levels of analysis:

1. processor_fit(language, target)
   A static language-to-target compatibility matrix.
   Source: publicly documented toolchain and platform support facts.
   Output: fit level + reason + advisory notes.

2. analyse_source(filename, text, target)
   Heuristic static analysis of source code for processor-relevant
   characteristics (CPU intensity, memory patterns, threading, etc.)
   Produces per-target observations and recommendations.

Rules:
- No invented processor specifications.
- No invented benchmark measurements.
- All output is STATIC_ANALYSIS, never VERIFIED_HARDWARE_RESULT.
- advisory: True on every recommendation.
- No Ollama, Granite, or cloud API calls.
- Never raises on empty, malformed, or unsupported input.
"""

import re

# ---------------------------------------------------------------------------
# Supported targets
# ---------------------------------------------------------------------------

TARGETS = [
    "Generic x86-64",
    "Intel x86-64",
    "AMD x86-64",
    "ARM64",
    "RISC-V 64",
    "ESP32-class MCU",
]

# Normalised target aliases for user input tolerance.
_TARGET_ALIASES = {
    "generic x86": "Generic x86-64",
    "generic x86-64": "Generic x86-64",
    "x86": "Generic x86-64",
    "x86-64": "Generic x86-64",
    "x86_64": "Generic x86-64",
    "intel": "Intel x86-64",
    "intel x86": "Intel x86-64",
    "intel x86-64": "Intel x86-64",
    "amd": "AMD x86-64",
    "amd x86": "AMD x86-64",
    "amd x86-64": "AMD x86-64",
    "arm": "ARM64",
    "arm64": "ARM64",
    "aarch64": "ARM64",
    "riscv": "RISC-V 64",
    "riscv64": "RISC-V 64",
    "risc-v": "RISC-V 64",
    "risc-v 64": "RISC-V 64",
    "esp32": "ESP32-class MCU",
    "esp32-class mcu": "ESP32-class MCU",
    "mcu": "ESP32-class MCU",
}

# Supported languages.
LANGUAGES = ["C", "C++", "Python", "Rust", "Go", "Java", "JavaScript", "TypeScript", "Custom"]

# ---------------------------------------------------------------------------
# Static fit matrix
#
# Values: "STRONG" | "PARTIAL" | "UNSUPPORTED" | "UNKNOWN"
#
# Sources:
#   - C/C++: ISO C standard; platform vendor toolchain docs (GCC, Clang, MSVC, Xtensa SDK)
#   - Python: CPython portability docs; MicroPython project docs
#   - Rust: Rust platform support tiers (https://doc.rust-lang.org/nightly/rustc/platform-support.html)
#   - Go: Go platform support (https://go.dev/doc/install/source#environment)
#   - Java: JVM platform availability (OpenJDK supported platforms)
#   - JS/TS: Node.js and browser runtime availability
#
# These are toolchain-support ratings, NOT performance benchmarks.
# ---------------------------------------------------------------------------

_FIT_MATRIX = {
    # (language, target) → (fit, reason, notes)
    ("C", "Generic x86-64"): (
        "STRONG",
        "C compiles to native x86-64 code via GCC, Clang, or MSVC. "
        "Full ABI access, SIMD intrinsics, and OS syscalls are available.",
        ["Use -O2 or -O3 and -march=x86-64 for portable optimised builds.",
         "SIMD via SSE2 (baseline), AVX, or AVX-512 requires explicit intrinsics or auto-vectorisation flags."],
    ),
    ("C", "Intel x86-64"): (
        "STRONG",
        "C compiles to native Intel x86-64 code. Intel-specific features "
        "(AVX-512 on server SKUs, Intel TBB) are accessible via intrinsics or libraries.",
        ["Use -march=native on the build host to enable all available ISA extensions.",
         "AVX-512 is present on Skylake-X/Ice Lake server; verify the deployment CPU before using."],
    ),
    ("C", "AMD x86-64"): (
        "STRONG",
        "C compiles to native AMD x86-64 code. AMD Zen CPUs support AVX2 "
        "and have competitive SIMD throughput.",
        ["Use -march=znver3 (or the appropriate Zen generation) for AMD-specific tuning.",
         "AVX-512 support varies by Zen generation; prefer AVX2 for broad AMD compatibility."],
    ),
    ("C", "ARM64"): (
        "STRONG",
        "C is the primary language for ARM64 targets. GCC and Clang both "
        "produce high-quality AArch64 code. NEON SIMD intrinsics are available.",
        ["Use -march=armv8-a or the platform SDK's default flags.",
         "Apple Silicon, AWS Graviton, and mobile SoCs all run AArch64 C binaries."],
    ),
    ("C", "RISC-V 64"): (
        "STRONG",
        "C is fully supported on RISC-V 64 via GCC (riscv64-unknown-linux-gnu) "
        "and Clang. Toolchain maturity is good for Linux targets.",
        ["The vector extension (RVV) requires explicit target flags; not universally available.",
         "Bare-metal RISC-V 64 requires a cross-toolchain and a linker script."],
    ),
    ("C", "ESP32-class MCU"): (
        "STRONG",
        "C is the primary language for ESP32 development via the ESP-IDF SDK "
        "(Xtensa LX6/LX7 or RISC-V core depending on variant).",
        ["Use the ESP-IDF toolchain; standard C99/C11 is supported.",
         "Dynamic allocation (malloc/free) works but heap is limited (~250–520 KB SRAM).",
         "Avoid recursive calls in ISRs; stack size is configured per task in FreeRTOS."],
    ),

    ("C++", "Generic x86-64"): (
        "STRONG",
        "C++ compiles to native x86-64 code. The full standard library, "
        "templates, and SIMD intrinsics are available.",
        ["Exceptions and RTTI add binary size; disable with -fno-exceptions -fno-rtti if not needed.",
         "Link-time optimisation (-flto) can improve cross-TU inlining."],
    ),
    ("C++", "Intel x86-64"): (
        "STRONG",
        "C++ is fully supported on Intel x86-64. Intel oneAPI and TBB "
        "provide threading and vectorisation libraries.",
        ["Intel VTune Amplifier can profile C++ binaries on Intel CPUs."],
    ),
    ("C++", "AMD x86-64"): (
        "STRONG",
        "C++ is fully supported on AMD x86-64 via GCC and Clang.",
        ["AMD uProf can profile C++ binaries on AMD CPUs."],
    ),
    ("C++", "ARM64"): (
        "STRONG",
        "C++ is fully supported on AArch64 via GCC and Clang. "
        "The ARM Neon intrinsics API is available.",
        ["C++ exceptions and dynamic_cast require unwinding tables; verify code-size impact on constrained targets."],
    ),
    ("C++", "RISC-V 64"): (
        "STRONG",
        "C++ is supported on RISC-V 64 via GCC and Clang cross-toolchains.",
        ["Standard library support depends on the sysroot; verify libstdc++ or libc++ availability."],
    ),
    ("C++", "ESP32-class MCU"): (
        "PARTIAL",
        "C++ is usable on ESP32 via ESP-IDF but with restrictions: "
        "exceptions are disabled by default, RTTI is unavailable, "
        "and dynamic allocation must be managed carefully.",
        ["Avoid STL containers with unbounded growth on heap-constrained ESP32 targets.",
         "Use -fno-exceptions and avoid virtual destructors unless memory is well-managed.",
         "Arduino-style C++ (subset) is more widely tested on ESP32."],
    ),

    ("Python", "Generic x86-64"): (
        "STRONG",
        "CPython 3.x runs on x86-64 Linux/Windows/macOS. "
        "NumPy and SciPy use optimised BLAS/LAPACK with SIMD acceleration.",
        ["CPython is interpreted; CPU-bound loops benefit from NumPy vectorisation or Cython.",
         "Consider PyPy for pure-Python CPU-bound workloads."],
    ),
    ("Python", "Intel x86-64"): (
        "STRONG",
        "CPython runs on Intel x86-64. Intel MKL (via numpy+mkl) "
        "provides AVX-512 accelerated linear algebra.",
        ["Install numpy linked against Intel MKL for maximum linear-algebra throughput on Intel CPUs."],
    ),
    ("Python", "AMD x86-64"): (
        "STRONG",
        "CPython runs on AMD x86-64. OpenBLAS (numpy default) "
        "supports AVX2 on AMD Zen CPUs.",
        ["AMD CPUs work well with OpenBLAS; Intel MKL may be suboptimal on non-Intel CPUs."],
    ),
    ("Python", "ARM64"): (
        "STRONG",
        "CPython 3.x runs on AArch64 (Linux, macOS/Apple Silicon). "
        "NumPy is available with NEON acceleration on Apple Silicon via Accelerate framework.",
        ["Use native arm64 wheels; Rosetta 2 emulation adds overhead on Apple Silicon.",
         "Apple Silicon MPS backend is available for PyTorch ML workloads."],
    ),
    ("Python", "RISC-V 64"): (
        "PARTIAL",
        "CPython can be compiled for RISC-V 64 Linux but pre-built distributions "
        "and binary wheel availability are limited compared to x86-64 and ARM64.",
        ["Binary wheel availability for data-science packages (numpy, scipy) on RISC-V 64 is limited.",
         "Expect to build dependencies from source."],
    ),
    ("Python", "ESP32-class MCU"): (
        "UNSUPPORTED",
        "CPython does not run on ESP32-class MCUs. "
        "MicroPython is available but has significant runtime and library differences.",
        ["MicroPython is a distinct runtime; standard CPython code is not directly portable.",
         "Use MicroPython only for non-critical prototyping; production ESP32 firmware is typically C/C++ or Rust.",
         "CircuitPython (Adafruit fork) is an alternative MicroPython variant."],
    ),

    ("Rust", "Generic x86-64"): (
        "STRONG",
        "Rust has Tier 1 support for x86_64-unknown-linux-gnu and "
        "x86_64-pc-windows-msvc. The standard library is fully supported.",
        ["SIMD via std::arch or the packed_simd crate.",
         "Rayon provides data-parallel iterators for multi-core x86-64."],
    ),
    ("Rust", "Intel x86-64"): (
        "STRONG",
        "Rust compiles to optimised Intel x86-64 code via LLVM. "
        "AVX-512 intrinsics are available through std::arch.",
        ["Use target_feature = '+avx512f' in .cargo/config.toml for AVX-512; verify CPU availability."],
    ),
    ("Rust", "AMD x86-64"): (
        "STRONG",
        "Rust compiles to optimised AMD x86-64 code via LLVM. "
        "AVX2 intrinsics are available through std::arch.",
        ["Rust's LLVM backend generates competitive code for AMD Zen CPUs."],
    ),
    ("Rust", "ARM64"): (
        "STRONG",
        "Rust has Tier 1 support for aarch64-unknown-linux-gnu and "
        "aarch64-apple-darwin (Apple Silicon). NEON intrinsics available via std::arch.",
        ["Cross-compile with cargo build --target aarch64-unknown-linux-gnu.",
         "Rust is widely used on AWS Graviton and Apple Silicon."],
    ),
    ("Rust", "RISC-V 64"): (
        "STRONG",
        "Rust supports riscv64gc-unknown-linux-gnu (Tier 2 with host tools). "
        "Bare-metal RISC-V 64 targets are also available.",
        ["riscv64gc-unknown-none-elf for bare-metal; riscv64gc-unknown-linux-gnu for Linux.",
         "Standard library availability on bare-metal requires the 'no_std' attribute."],
    ),
    ("Rust", "ESP32-class MCU"): (
        "PARTIAL",
        "Rust on ESP32 is possible via the esp-rs project (esp-idf-sys crate for "
        "Xtensa; RISC-V ESP32-C3/C6 uses standard riscv32imc target). "
        "Active community support but less mature than C/C++ ESP-IDF.",
        ["Use the esp-rs template: https://github.com/esp-rs/esp-idf-template",
         "RISC-V-based ESP32 variants (C3, C6, H2) are easier to target with standard Rust.",
         "Xtensa ESP32/ESP32-S2/S3 requires a forked LLVM backend maintained by Espressif."],
    ),

    ("Go", "Generic x86-64"): (
        "STRONG",
        "Go has first-class support for GOOS=linux/windows/darwin on GOARCH=amd64. "
        "The Go runtime includes a concurrent garbage collector and goroutine scheduler.",
        ["Go's GC introduces latency spikes; tune GOGC for latency-sensitive workloads.",
         "SIMD is not directly accessible from Go; use cgo for SIMD-optimised C libraries."],
    ),
    ("Go", "Intel x86-64"): (
        "STRONG",
        "Go compiles to native Intel x86-64 code. Performance is competitive "
        "for network services and concurrent workloads.",
        ["pprof profiling works on Intel CPUs; use 'go tool pprof' for CPU profiling."],
    ),
    ("Go", "AMD x86-64"): (
        "STRONG",
        "Go compiles to native AMD x86-64 code with the same GOARCH=amd64 target.",
        ["Go binaries built with GOARCH=amd64 run on both Intel and AMD x86-64 CPUs."],
    ),
    ("Go", "ARM64"): (
        "STRONG",
        "Go has first-class support for GOARCH=arm64 on Linux and macOS. "
        "AWS Graviton and Apple Silicon are well-supported.",
        ["Build with GOOS=linux GOARCH=arm64 for Graviton targets.",
         "Go's GC and scheduler work correctly on AArch64."],
    ),
    ("Go", "RISC-V 64"): (
        "PARTIAL",
        "Go supports GOARCH=riscv64 for Linux (experimental/community-maintained). "
        "The runtime and standard library compile but not all packages are well-tested.",
        ["GOARCH=riscv64 is less tested than amd64/arm64; expect potential edge cases.",
         "CGo may require a RISC-V 64 cross-compiler sysroot."],
    ),
    ("Go", "ESP32-class MCU"): (
        "UNSUPPORTED",
        "Go requires a full operating system and cannot run on bare-metal "
        "microcontrollers like the ESP32. The Go runtime needs virtual memory, "
        "OS-level threads, and a heap far larger than ESP32 SRAM.",
        ["Use C, C++, or Rust for ESP32 targets.",
         "TinyGo (a Go subset) has experimental ESP32 support but is not production-ready."],
    ),

    ("Java", "Generic x86-64"): (
        "STRONG",
        "OpenJDK and GraalVM are available for x86-64 Linux/Windows/macOS. "
        "The JVM JIT compiler produces optimised native code at runtime.",
        ["JVM startup time and heap footprint are significant; consider GraalVM native-image for CLI tools.",
         "Use JVM flags (-Xms, -Xmx, -XX:+UseG1GC) to tune memory and GC behaviour."],
    ),
    ("Java", "Intel x86-64"): (
        "STRONG",
        "Java runs on Intel x86-64 via OpenJDK. The JIT can utilise AVX/AVX-512 "
        "for vectorised operations in hotspot loops (JDK 17+).",
        ["Java Vector API (JEP 338, JDK 17+) enables explicit SIMD programming on Intel CPUs."],
    ),
    ("Java", "AMD x86-64"): (
        "STRONG",
        "Java runs on AMD x86-64 via OpenJDK. Performance is equivalent to Intel "
        "for JVM workloads.",
        ["GraalVM on AMD x86-64 produces native binaries without JVM startup overhead."],
    ),
    ("Java", "ARM64"): (
        "STRONG",
        "OpenJDK 11+ supports AArch64 (Linux and macOS). AWS Graviton and "
        "Apple Silicon are well-supported. Azul Zulu and Amazon Corretto "
        "provide ARM64 builds.",
        ["Use Amazon Corretto or Azul Zulu for AWS Graviton deployments.",
         "GraalVM native-image supports AArch64 Linux."],
    ),
    ("Java", "RISC-V 64"): (
        "PARTIAL",
        "OpenJDK has a RISC-V 64 port (JEP 422, mainlined in JDK 19). "
        "Production readiness and performance optimisation are still maturing.",
        ["The JIT compiler on RISC-V 64 is less optimised than on x86-64 or ARM64.",
         "Consider GraalVM native-image if startup time and memory are constraints."],
    ),
    ("Java", "ESP32-class MCU"): (
        "UNSUPPORTED",
        "The JVM requires substantially more RAM (minimum ~64 MB for a minimal JVM) "
        "than the ESP32's ~520 KB SRAM. Java cannot run on ESP32-class hardware.",
        ["Use C, C++, or Rust for ESP32 targets.",
         "There is no production-quality JVM for ESP32."],
    ),

    ("JavaScript", "Generic x86-64"): (
        "STRONG",
        "Node.js (V8 engine) runs on x86-64 Linux/Windows/macOS. "
        "V8 JIT produces optimised native code for hot paths.",
        ["JavaScript is single-threaded; use Worker threads or child processes for CPU parallelism.",
         "For CPU-bound work, consider WebAssembly (WASM) modules compiled from C/Rust."],
    ),
    ("JavaScript", "Intel x86-64"): (
        "STRONG",
        "Node.js runs on Intel x86-64 with the same V8 JIT optimisations.",
        ["Node.js on Intel CPUs benefits from the same V8 optimisations as on AMD."],
    ),
    ("JavaScript", "AMD x86-64"): (
        "STRONG",
        "Node.js runs on AMD x86-64 with the same V8 JIT optimisations.",
        [],
    ),
    ("JavaScript", "ARM64"): (
        "STRONG",
        "Node.js has first-class ARM64 support for Linux and macOS (Apple Silicon). "
        "V8 generates native AArch64 code.",
        ["Use native arm64 Node.js builds on Apple Silicon; Rosetta 2 emulation adds overhead.",
         "AWS Graviton ARM64 Node.js deployments are production-supported."],
    ),
    ("JavaScript", "RISC-V 64"): (
        "PARTIAL",
        "Node.js can be compiled for RISC-V 64 Linux but pre-built binaries "
        "are not officially distributed by the Node.js project.",
        ["Expect to build Node.js from source for RISC-V 64.",
         "V8 JIT support for RISC-V 64 is available but less optimised than for x86-64 or ARM64."],
    ),
    ("JavaScript", "ESP32-class MCU"): (
        "UNSUPPORTED",
        "Node.js requires an operating system and substantially more memory "
        "than the ESP32 provides. JavaScript cannot run on bare-metal ESP32.",
        ["Espruino (a JavaScript interpreter) targets some microcontrollers but is not "
         "suitable for production ESP32 firmware.",
         "Use C, C++, or Rust for production ESP32 development."],
    ),

    ("TypeScript", "Generic x86-64"): (
        "STRONG",
        "TypeScript compiles to JavaScript and runs on Node.js (x86-64). "
        "The same V8 JIT optimisations apply to the compiled output.",
        ["TypeScript adds zero runtime cost; it compiles to plain JavaScript.",
         "Use ts-node or esbuild for development; compile to plain JS for production."],
    ),
    ("TypeScript", "Intel x86-64"): (
        "STRONG",
        "TypeScript runs on Node.js on Intel x86-64 with full V8 JIT optimisation.",
        [],
    ),
    ("TypeScript", "AMD x86-64"): (
        "STRONG",
        "TypeScript runs on Node.js on AMD x86-64 with full V8 JIT optimisation.",
        [],
    ),
    ("TypeScript", "ARM64"): (
        "STRONG",
        "TypeScript runs on Node.js ARM64 (Linux and Apple Silicon). "
        "Deno also supports ARM64.",
        [],
    ),
    ("TypeScript", "RISC-V 64"): (
        "PARTIAL",
        "TypeScript inherits Node.js RISC-V 64 limitations: "
        "no official pre-built binaries, must build Node.js from source.",
        ["V8 RISC-V 64 JIT is available but less mature than on other architectures."],
    ),
    ("TypeScript", "ESP32-class MCU"): (
        "UNSUPPORTED",
        "TypeScript cannot run on ESP32-class hardware for the same reasons as JavaScript.",
        ["Use C, C++, or Rust for production ESP32 development."],
    ),

    ("Custom", "Generic x86-64"): (
        "UNKNOWN",
        "Custom language fit depends on the toolchain, runtime, and compilation target.",
        ["Verify that the language toolchain produces x86-64 native code or runs on a supported runtime."],
    ),
    ("Custom", "Intel x86-64"): (
        "UNKNOWN",
        "Custom language fit depends on the toolchain, runtime, and compilation target.",
        [],
    ),
    ("Custom", "AMD x86-64"): (
        "UNKNOWN",
        "Custom language fit depends on the toolchain, runtime, and compilation target.",
        [],
    ),
    ("Custom", "ARM64"): (
        "UNKNOWN",
        "Custom language fit depends on the toolchain, runtime, and compilation target.",
        [],
    ),
    ("Custom", "RISC-V 64"): (
        "UNKNOWN",
        "Custom language fit depends on the toolchain, runtime, and compilation target.",
        [],
    ),
    ("Custom", "ESP32-class MCU"): (
        "UNKNOWN",
        "Custom language fit depends on the toolchain, runtime, and compilation target.",
        [],
    ),
}

# ---------------------------------------------------------------------------
# Source heuristic patterns
#
# Each entry: (category, signal_name, pattern, observation_template, targets_affected)
#
# observation_template uses {file} and {count} for interpolation.
# targets_affected: list of target names to which the observation applies,
#   or ["ALL"] for universal applicability.
# ---------------------------------------------------------------------------

_SOURCE_PATTERNS = [
    # CPU intensity — tight loops
    (
        "CPU Intensity",
        "nested_loops",
        r"\bfor\b[^\n]*\n[^\n]*\bfor\b",
        "Detected nested loop structure — possible O(n²) or higher complexity hotspot.",
        ["ALL"],
    ),
    (
        "CPU Intensity",
        "while_loop",
        r"\bwhile\s*\(",
        "while() loop detected — verify that termination conditions prevent unbounded CPU consumption.",
        ["ALL"],
    ),
    (
        "CPU Intensity",
        "recursive_function",
        # Heuristic: function body that calls itself (simple name re-use pattern)
        r"\b(\w+)\s*\([^)]*\)[^{]*\{[^}]*\b\1\s*\(",
        "Potential recursive function detected — deep recursion can exhaust the call stack, "
        "especially on MCU targets with small stack sizes.",
        ["ESP32-class MCU", "RISC-V 64"],
    ),

    # Vectorization opportunities
    (
        "Vectorization",
        "array_arithmetic_c",
        r"\b(int|float|double|uint\d+_t|int\d+_t)\s+\w+\s*\[",
        "Fixed-size array of numeric type detected — may be a candidate for SIMD vectorisation.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),
    (
        "Vectorization",
        "numpy_op",
        r"\bnp\.(dot|matmul|sum|multiply|add|subtract|sqrt|exp|log)\s*\(",
        "NumPy vectorised operation detected — runs on optimised BLAS/LAPACK with SIMD on x86-64/ARM64.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),
    (
        "Vectorization",
        "simd_intrinsic",
        r"\b(_mm|_mm256|_mm512|vld1|vst1|vmovq|__m128|__m256|__m512)\b",
        "Architecture-specific SIMD intrinsic detected — this code is not portable across targets.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64", "RISC-V 64", "ESP32-class MCU"],
    ),

    # Threading / parallelism
    (
        "Threading",
        "posix_thread",
        r"\bpthread_create\s*\(",
        "POSIX thread creation detected — pthreads are unavailable on bare-metal MCU targets.",
        ["ESP32-class MCU"],
    ),
    (
        "Threading",
        "openmp",
        r"#pragma\s+omp\s+parallel",
        "OpenMP pragma detected — OpenMP support requires a compatible compiler and OS thread support.",
        ["ESP32-class MCU", "RISC-V 64"],
    ),
    (
        "Threading",
        "python_threading",
        r"\bimport\s+threading\b|\bfrom\s+threading\b",
        "Python threading module imported — CPython GIL limits true CPU parallelism; "
        "consider multiprocessing or async for CPU-bound work.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),
    (
        "Threading",
        "python_multiprocessing",
        r"\bimport\s+multiprocessing\b|\bfrom\s+multiprocessing\b",
        "Python multiprocessing detected — bypasses GIL for CPU-bound parallelism; "
        "process spawn overhead is significant on Windows.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),
    (
        "Threading",
        "go_goroutine",
        r"\bgo\s+\w+\s*\(",
        "Go goroutine detected — maps to OS threads via the Go runtime scheduler; "
        "not available without the Go runtime (i.e. bare metal).",
        ["ESP32-class MCU"],
    ),
    (
        "Threading",
        "rust_thread",
        r"\bthread::spawn\s*\(",
        "Rust std::thread::spawn detected — requires OS thread support; "
        "not available in no_std bare-metal targets.",
        ["ESP32-class MCU"],
    ),
    (
        "Threading",
        "java_thread",
        r"\bnew\s+Thread\s*\(|\bExecutorService\b|\bForkJoinPool\b",
        "Java threading API detected — requires JVM; unavailable on bare-metal targets.",
        ["ESP32-class MCU", "RISC-V 64"],
    ),

    # Memory usage patterns
    (
        "Memory",
        "dynamic_alloc_c",
        r"\b(malloc|calloc|realloc)\s*\(",
        "Dynamic heap allocation detected — on MCU targets, heap fragmentation and "
        "allocation failure must be handled explicitly.",
        ["ESP32-class MCU"],
    ),
    (
        "Memory",
        "large_stack_array_c",
        r"\b(int|float|double|char)\s+\w+\s*\[\s*\d{4,}\s*\]",
        "Large stack-allocated array detected (≥1000 elements) — "
        "may overflow the stack on MCU or embedded targets with small default stack sizes.",
        ["ESP32-class MCU", "RISC-V 64"],
    ),
    (
        "Memory",
        "python_list_comprehension",
        r"\[[^\]]+\s+for\s+\w+\s+in\s+",
        "Python list comprehension detected — materialises entire collection in memory; "
        "use generator expressions for large datasets.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),
    (
        "Memory",
        "rust_vec_collect",
        r"\.collect::<Vec",
        "Rust Vec collect detected — allocates a new heap vector; "
        "use iterators without collect where possible on memory-constrained targets.",
        ["ESP32-class MCU"],
    ),
    (
        "Memory",
        "java_gc_pressure",
        r"\bnew\s+[A-Z]\w+\s*\(",
        "Heap object allocation detected — frequent short-lived object creation increases "
        "GC pressure on JVM targets.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),

    # I/O intensity
    (
        "I/O",
        "file_io_c",
        r"\b(fopen|fread|fwrite|fclose|fprintf)\s*\(",
        "File I/O operation detected — verify I/O is buffered and errors are handled.",
        ["ALL"],
    ),
    (
        "I/O",
        "network_socket_c",
        r"\b(socket|connect|bind|listen|accept|recv|send)\s*\(",
        "Network socket API detected — ensure non-blocking I/O or separate I/O threads "
        "to avoid CPU stalls.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "ARM64"],
    ),
    (
        "I/O",
        "python_open",
        r"\bopen\s*\(['\"][^'\"]+['\"]",
        "File open detected — use context managers (with open(...)) and buffered I/O.",
        ["ALL"],
    ),
    (
        "I/O",
        "blocking_sleep",
        r"\b(time\.sleep|usleep|sleep\s*\(|vTaskDelay)\s*\(",
        "Blocking sleep detected — on RTOS targets (e.g. FreeRTOS/ESP-IDF) use vTaskDelay; "
        "on bare-metal, busy-wait delays waste CPU cycles.",
        ["ESP32-class MCU"],
    ),

    # Native dependencies / portability
    (
        "Portability",
        "x86_asm_inline",
        r"\b(__asm__|asm\s*volatile)\b",
        "Inline assembly detected — this code is architecture-specific and "
        "will not compile on non-x86-64 targets without modification.",
        ["ARM64", "RISC-V 64", "ESP32-class MCU"],
    ),
    (
        "Portability",
        "arch_specific_include",
        r"#include\s*[<\"](x86intrin\.h|immintrin\.h|xmmintrin\.h|emmintrin\.h|nmmintrin\.h)[>\"]",
        "x86-specific intrinsics header included — this file will not compile on ARM64, "
        "RISC-V 64, or ESP32 targets.",
        ["ARM64", "RISC-V 64", "ESP32-class MCU"],
    ),
    (
        "Portability",
        "arm_neon_include",
        r"#include\s*[<\"](arm_neon\.h)[>\"]",
        "ARM NEON intrinsics header included — this code is specific to ARM/ARM64 "
        "and will not compile on x86-64 or RISC-V 64 without modification.",
        ["Generic x86-64", "Intel x86-64", "AMD x86-64", "RISC-V 64", "ESP32-class MCU"],
    ),
    (
        "Portability",
        "windows_api",
        r"\b(HANDLE|CreateThread|LoadLibrary|RegOpenKey|VirtualAlloc)\b",
        "Windows API usage detected — this code requires Win32 and is not portable "
        "to Linux, ARM64 Linux, RISC-V 64, or ESP32 targets.",
        ["ARM64", "RISC-V 64", "ESP32-class MCU"],
    ),
    (
        "Portability",
        "linux_specific_syscall",
        r"\b(epoll_create|io_uring_setup|perf_event_open|inotify_init)\s*\(",
        "Linux-specific syscall detected — not portable to macOS, Windows, or bare-metal targets.",
        ["ESP32-class MCU"],
    ),
    (
        "Portability",
        "endian_assumption",
        r"\*\s*\(\s*(int|uint32_t|uint16_t)\s*\*\s*\)",
        "Type-punning via pointer cast detected — behaviour depends on platform endianness; "
        "may differ between x86-64 (little-endian) and some RISC-V or embedded targets.",
        ["RISC-V 64", "ESP32-class MCU", "ARM64"],
    ),

    # Compiler/toolchain considerations
    (
        "Compiler",
        "pragma_once",
        r"#pragma\s+once",
        "#pragma once is supported by GCC, Clang, and MSVC but is not part of the C/C++ standard.",
        ["RISC-V 64", "ESP32-class MCU"],
    ),
    (
        "Compiler",
        "attribute_gcc",
        r"__attribute__\s*\(\s*\(",
        "GCC __attribute__ extension detected — may not be supported by all C++ compilers "
        "(e.g. MSVC). Verify compatibility with the target SDK toolchain.",
        ["ALL"],
    ),
    (
        "Compiler",
        "compiler_barrier",
        r"\b(asm volatile\s*\(\s*\"\"\s*:\s*:\s*:)|__sync_synchronize\s*\(\s*\)|std::atomic_thread_fence\b",
        "Memory barrier or compiler fence detected — semantics and portability vary by architecture.",
        ["ARM64", "RISC-V 64", "ESP32-class MCU"],
    ),

    # Embedded constraints
    (
        "Embedded",
        "floating_point",
        r"\b(float|double)\b[^*]",
        "Floating-point type detected — ESP32 has hardware FPU on some variants (ESP32-S3); "
        "RISC-V 64 Linux targets have hardware FPU; verify FPU availability for the specific MCU variant.",
        ["ESP32-class MCU", "RISC-V 64"],
    ),
    (
        "Embedded",
        "printf_usage",
        r"\bprintf\s*\(",
        "printf() detected — on ESP32/FreeRTOS, use ESP_LOGI/ESP_LOGE instead of printf "
        "for thread-safe, level-filtered logging.",
        ["ESP32-class MCU"],
    ),
    (
        "Embedded",
        "heap_check",
        r"\b(esp_get_free_heap_size|heap_caps_get_free_size)\s*\(",
        "ESP-IDF heap monitoring API detected — confirms awareness of heap constraints.",
        ["ESP32-class MCU"],
    ),
]


# ---------------------------------------------------------------------------
# Recommendation templates keyed by (category, signal_name)
# ---------------------------------------------------------------------------

_RECOMMENDATION_TEMPLATES = {
    ("CPU Intensity", "nested_loops"): {
        "proposed_optimization": "Profile with gprof, perf, or Instruments to confirm this is a hotspot before optimising. "
                                  "Consider loop tiling for cache efficiency or SIMD for arithmetic-heavy inner loops.",
        "expected_benefit": "HYPOTHESIS: Reducing cache misses in tight loops may improve throughput. "
                             "Benefit is workload-dependent and must be measured.",
        "risk": "Premature optimisation may harm readability without measurable gain.",
        "verification_method": "Measure wall-clock time before and after optimisation with a representative input.",
    },
    ("CPU Intensity", "while_loop"): {
        "proposed_optimization": "Verify loop termination invariants. For CPU-bound loops, profile to confirm "
                                  "they represent a significant fraction of execution time before optimising.",
        "expected_benefit": "HYPOTHESIS: Removing unnecessary iterations reduces CPU time.",
        "risk": "Incorrect termination conditions may introduce correctness bugs.",
        "verification_method": "Run with a representative workload under a profiler (perf stat, py-spy).",
    },
    ("CPU Intensity", "recursive_function"): {
        "proposed_optimization": "Convert deep recursion to an iterative algorithm with an explicit stack "
                                  "to bound stack usage. On RTOS targets, configure task stack size explicitly.",
        "expected_benefit": "HYPOTHESIS: Iterative implementation prevents stack overflow on MCU targets "
                             "with configurable but limited stack sizes.",
        "risk": "Iterative refactoring may be more complex to maintain.",
        "verification_method": "Test with maximum expected recursion depth on the target hardware or emulator.",
    },
    ("Vectorization", "array_arithmetic_c"): {
        "proposed_optimization": "Annotate loops with restrict pointers and compile with -O3 -ffast-math "
                                  "to enable auto-vectorisation. Alternatively, use explicit SIMD intrinsics "
                                  "or a library such as XSIMD.",
        "expected_benefit": "HYPOTHESIS: SIMD vectorisation may increase arithmetic throughput 2-8x "
                             "for independent loop iterations. Actual gain must be measured.",
        "risk": "ffast-math can change floating-point results; verify numerical correctness.",
        "verification_method": "Compare auto-vectorised vs scalar output with identical inputs. "
                                "Profile with perf or VTune to measure actual throughput.",
    },
    ("Vectorization", "numpy_op"): {
        "proposed_optimization": "Ensure numpy is linked against an optimised BLAS (MKL on Intel, "
                                  "OpenBLAS on AMD/ARM). Use batch operations instead of element-wise Python loops.",
        "expected_benefit": "HYPOTHESIS: BLAS-backed numpy operations can be 10-100x faster than "
                             "equivalent Python loops for large arrays. Verify with timeit.",
        "risk": "BLAS configuration varies by installation; numpy.show_config() reveals the active backend.",
        "verification_method": "Benchmark with numpy.testing and timeit for representative array sizes.",
    },
    ("Vectorization", "simd_intrinsic"): {
        "proposed_optimization": "Wrap architecture-specific intrinsics in #ifdef guards and provide "
                                  "portable fallbacks. Consider the highway or xsimd portability layers.",
        "expected_benefit": "HYPOTHESIS: Portable SIMD abstractions allow the same code to run on multiple "
                             "ISAs without separate codepaths.",
        "risk": "Portability layers add a compilation dependency and may not achieve the same performance "
                 "as hand-tuned intrinsics on every target.",
        "verification_method": "Build and run the portable version on each target and measure throughput.",
    },
    ("Threading", "posix_thread"): {
        "proposed_optimization": "Replace pthreads with FreeRTOS xTaskCreate on ESP32 targets. "
                                  "The ESP-IDF FreeRTOS port provides a threading model appropriate for the MCU.",
        "expected_benefit": "HYPOTHESIS: FreeRTOS tasks use configurable stack sizes and cooperative "
                             "or preemptive scheduling suited to the ESP32 real-time requirements.",
        "risk": "FreeRTOS task API differs from pthreads; requires porting effort.",
        "verification_method": "Build against ESP-IDF FreeRTOS headers and test task scheduling behaviour.",
    },
    ("Threading", "openmp"): {
        "proposed_optimization": "OpenMP requires OS threads. On ESP32, use FreeRTOS xTaskCreate to distribute "
                                  "work across cores (dual-core ESP32 only). On RISC-V 64 Linux, OpenMP is available.",
        "expected_benefit": "HYPOTHESIS: Multi-core ESP32 can parallelise independent work items via FreeRTOS tasks.",
        "risk": "FreeRTOS multi-core support is SMP-limited; verify the specific ESP32 variant has two cores.",
        "verification_method": "Profile task execution on both cores with ESP-IDF xtensa-profiler or FreeRTOS tracing.",
    },
    ("Threading", "python_threading"): {
        "proposed_optimization": "For CPU-bound work, use multiprocessing or concurrent.futures.ProcessPoolExecutor "
                                  "to bypass the GIL. For I/O-bound work, threading or asyncio is appropriate.",
        "expected_benefit": "HYPOTHESIS: ProcessPoolExecutor can achieve near-linear CPU scaling for "
                             "CPU-bound tasks on multi-core x86-64/ARM64 systems.",
        "risk": "Process spawn overhead is significant on Windows; fork is faster on Linux.",
        "verification_method": "Benchmark with concurrent.futures on a multi-core machine with CPU-bound workload.",
    },
    ("Threading", "python_multiprocessing"): {
        "proposed_optimization": "Pin worker processes to specific cores using os.sched_setaffinity() on Linux "
                                  "for predictable NUMA-aware scheduling on multi-socket x86-64 servers.",
        "expected_benefit": "HYPOTHESIS: NUMA-aware process pinning may reduce cross-socket memory latency.",
        "risk": "Core pinning reduces scheduler flexibility; only beneficial on NUMA or highly-loaded systems.",
        "verification_method": "Compare pinned vs unpinned performance under numactl on a multi-socket system.",
    },
    ("Threading", "go_goroutine"): {
        "proposed_optimization": "Goroutines require the Go runtime and OS-level scheduling. "
                                  "For ESP32, use FreeRTOS tasks instead.",
        "expected_benefit": "HYPOTHESIS: FreeRTOS tasks on ESP32 provide cooperative/preemptive scheduling "
                             "without the full Go runtime overhead.",
        "risk": "Go code cannot be compiled for bare-metal ESP32 without substantial porting.",
        "verification_method": "Port goroutine logic to FreeRTOS xTaskCreate and test on target hardware.",
    },
    ("Threading", "rust_thread"): {
        "proposed_optimization": "Replace std::thread with esp-idf-hal task spawning or no_std async runtimes "
                                  "for ESP32 targets.",
        "expected_benefit": "HYPOTHESIS: Embassy or RTIC async runtimes provide concurrent execution "
                             "without full OS thread support on ESP32.",
        "risk": "no_std async runtimes have different APIs and require no_std-compatible dependencies.",
        "verification_method": "Build the crate with the esp32 target and test task scheduling.",
    },
    ("Threading", "java_thread"): {
        "proposed_optimization": "Java threading is JVM-dependent. For RISC-V 64 Linux, the JVM is available "
                                  "but less optimised. For ESP32, Java threading is not applicable.",
        "expected_benefit": "HYPOTHESIS: On RISC-V 64 Linux, Java virtual threads (Project Loom, JDK 21+) "
                             "reduce thread overhead for I/O-bound workloads.",
        "risk": "JVM threading on RISC-V 64 is less tested than on x86-64.",
        "verification_method": "Run the application under JDK 21 on RISC-V 64 and profile with JFR.",
    },
    ("Memory", "dynamic_alloc_c"): {
        "proposed_optimization": "Audit all malloc/calloc/realloc calls on ESP32 for NULL return handling. "
                                  "Use heap_caps_malloc(size, MALLOC_CAP_DMA) for DMA-capable buffers. "
                                  "Pre-allocate fixed-size buffers where possible.",
        "expected_benefit": "HYPOTHESIS: Pre-allocation eliminates heap fragmentation and allocation failure "
                             "on memory-constrained targets.",
        "risk": "Pre-allocation increases static memory use; size the buffers carefully.",
        "verification_method": "Monitor heap usage with esp_get_free_heap_size() during stress testing.",
    },
    ("Memory", "large_stack_array_c"): {
        "proposed_optimization": "Move large arrays to the heap (malloc) or to static/global storage. "
                                  "Configure FreeRTOS task stack sizes explicitly with the required headroom.",
        "expected_benefit": "HYPOTHESIS: Moving large arrays off the stack prevents stack overflow on targets "
                             "with default stack sizes of 4–8 KB.",
        "risk": "Heap allocation requires NULL-check and lifetime management.",
        "verification_method": "Run uxTaskGetStackHighWaterMark() in FreeRTOS to measure stack usage.",
    },
    ("Memory", "python_list_comprehension"): {
        "proposed_optimization": "Replace list comprehensions with generator expressions where the result "
                                  "is iterated only once: (x for x in ...) instead of [x for x in ...].",
        "expected_benefit": "HYPOTHESIS: Generator expressions reduce peak memory usage from O(n) to O(1) "
                             "for streaming workloads.",
        "risk": "Generators cannot be indexed or reused; convert to list only when random access is needed.",
        "verification_method": "Profile memory with tracemalloc before and after the change.",
    },
    ("Memory", "rust_vec_collect"): {
        "proposed_optimization": "Avoid .collect::<Vec<_>>() on ESP32; iterate lazily instead. "
                                  "Use heapless::Vec from the heapless crate for fixed-capacity vectors.",
        "expected_benefit": "HYPOTHESIS: heapless::Vec avoids dynamic allocation entirely, "
                             "preventing heap fragmentation on MCU targets.",
        "risk": "heapless::Vec has a fixed capacity; exceed it and operations return an error (not a panic).",
        "verification_method": "Build with no_std and heapless, measure heap usage on target.",
    },
    ("Memory", "java_gc_pressure"): {
        "proposed_optimization": "Reduce short-lived object creation by reusing objects (object pooling), "
                                  "using value types (JEP 169 / Valhalla), or primitive arrays instead of "
                                  "boxed collections.",
        "expected_benefit": "HYPOTHESIS: Reducing allocation rate lowers GC frequency and pause duration.",
        "risk": "Object pooling introduces complexity and potential concurrency issues.",
        "verification_method": "Profile with JFR (Java Flight Recorder) and measure GC pause time before/after.",
    },
    ("I/O", "file_io_c"): {
        "proposed_optimization": "Ensure all fopen() calls check for NULL return. Use setvbuf() for "
                                  "explicit I/O buffering on performance-critical paths.",
        "expected_benefit": "HYPOTHESIS: Proper buffering reduces syscall frequency and I/O latency.",
        "risk": "Buffered writes may delay data flush; call fflush() or fsync() where durability is required.",
        "verification_method": "Measure I/O throughput with a synthetic benchmark (dd or custom).",
    },
    ("I/O", "network_socket_c"): {
        "proposed_optimization": "Use non-blocking sockets with epoll/kqueue/IOCP or an async I/O library "
                                  "to prevent CPU stalls while waiting for network data.",
        "expected_benefit": "HYPOTHESIS: Async I/O allows a single thread to handle many connections "
                             "without blocking, reducing latency under load.",
        "risk": "Async socket code is more complex to reason about and test.",
        "verification_method": "Load-test with wrk or hey and measure throughput and latency percentiles.",
    },
    ("I/O", "python_open"): {
        "proposed_optimization": "Always use 'with open(...)' context managers. For large files, iterate "
                                  "line-by-line instead of read() to bound memory usage.",
        "expected_benefit": "HYPOTHESIS: Context managers ensure file handles are closed promptly, "
                             "preventing file descriptor exhaustion.",
        "risk": "Line-by-line iteration is slower for binary I/O; use binary mode with buffered reads.",
        "verification_method": "Check file descriptor usage with lsof or /proc/self/fd.",
    },
    ("I/O", "blocking_sleep"): {
        "proposed_optimization": "Use vTaskDelay(pdMS_TO_TICKS(n)) on FreeRTOS/ESP-IDF instead of "
                                  "busy-wait delays. This yields CPU to other tasks during the delay.",
        "expected_benefit": "HYPOTHESIS: vTaskDelay yields CPU time to other FreeRTOS tasks, "
                             "improving overall system responsiveness.",
        "risk": "Timer resolution is limited by the FreeRTOS tick rate (default 100–1000 Hz on ESP-IDF).",
        "verification_method": "Observe task scheduling with FreeRTOS trace or ESP-IDF SystemView.",
    },
    ("Portability", "x86_asm_inline"): {
        "proposed_optimization": "Guard inline assembly with #ifdef __x86_64__ and provide a portable "
                                  "C fallback for other architectures.",
        "expected_benefit": "HYPOTHESIS: Portable fallback allows the code to compile on ARM64, "
                             "RISC-V 64, and ESP32 without changes.",
        "risk": "The fallback may be significantly slower than the SIMD assembly; measure both.",
        "verification_method": "Compile with a cross-compiler targeting each architecture and run unit tests.",
    },
    ("Portability", "arch_specific_include"): {
        "proposed_optimization": "Wrap x86 intrinsic headers in #ifdef __x86_64__ or __SSE2__ guards. "
                                  "Provide ARM NEON or portable scalar fallbacks.",
        "expected_benefit": "HYPOTHESIS: Conditional compilation allows a single codebase to target "
                             "multiple architectures.",
        "risk": "Maintaining multiple SIMD codepaths increases maintenance burden.",
        "verification_method": "Build with ARM and RISC-V cross-compilers and run the test suite.",
    },
    ("Portability", "arm_neon_include"): {
        "proposed_optimization": "Wrap ARM NEON includes in #ifdef __ARM_NEON__ and provide scalar "
                                  "or SSE fallbacks for x86-64 targets.",
        "expected_benefit": "HYPOTHESIS: Conditional SIMD selection allows the same source to run on "
                             "both x86-64 and ARM64.",
        "risk": "Cross-platform SIMD wrappers add complexity; consider the highway library.",
        "verification_method": "Build for both x86-64 and AArch64 and run benchmarks on each.",
    },
    ("Portability", "windows_api"): {
        "proposed_optimization": "Abstract Windows-specific API calls behind a platform HAL (hardware "
                                  "abstraction layer) and provide POSIX implementations for non-Windows targets.",
        "expected_benefit": "HYPOTHESIS: A thin abstraction layer enables cross-platform compilation "
                             "without duplicating business logic.",
        "risk": "HAL design requires careful API design; Win32 and POSIX semantics differ in subtle ways.",
        "verification_method": "Build and test on Linux and macOS with a POSIX implementation.",
    },
    ("Portability", "linux_specific_syscall"): {
        "proposed_optimization": "Provide a POSIX-compatible fallback (e.g. select/poll) for non-Linux "
                                  "platforms. Use libuv or libevent for portable async I/O.",
        "expected_benefit": "HYPOTHESIS: Portable I/O libraries abstract OS differences and enable "
                             "deployment on multiple platforms.",
        "risk": "Portable libraries may not achieve the same throughput as native Linux io_uring.",
        "verification_method": "Benchmark both implementations under equivalent load.",
    },
    ("Portability", "endian_assumption"): {
        "proposed_optimization": "Replace type-punning pointer casts with memcpy() or byte-order-explicit "
                                  "functions (htole32/be32toh) to ensure correct behaviour on both "
                                  "little-endian and big-endian targets.",
        "expected_benefit": "HYPOTHESIS: Explicit byte-order handling produces correct results on "
                             "all endianness configurations.",
        "risk": "Byte-order conversion adds a few instructions per operation; negligible on modern CPUs.",
        "verification_method": "Test on a big-endian emulator or QEMU system and compare output.",
    },
    ("Compiler", "pragma_once"): {
        "proposed_optimization": "Add standard include guards (#ifndef MY_HEADER_H ... #define ... #endif) "
                                  "as a portable fallback alongside #pragma once.",
        "expected_benefit": "HYPOTHESIS: Standard include guards guarantee portability across all C/C++ "
                             "toolchains including less common embedded SDKs.",
        "risk": "Minimal — both guards can coexist in the same header.",
        "verification_method": "Build with a strict ANSI C compiler such as tcc or with -Wpedantic.",
    },
    ("Compiler", "attribute_gcc"): {
        "proposed_optimization": "Wrap GCC-specific __attribute__ in portability macros: "
                                  "#if defined(__GNUC__) #define MY_ATTR(...) __attribute__((__VA_ARGS__)) #endif",
        "expected_benefit": "HYPOTHESIS: Portability macros allow the code to compile under MSVC and "
                             "other compilers that do not support __attribute__.",
        "risk": "Attributes like __attribute__((packed)) have no MSVC equivalent; may require structural changes.",
        "verification_method": "Attempt to compile with cl.exe (MSVC) or scan with -Wpedantic -Werror.",
    },
    ("Compiler", "compiler_barrier"): {
        "proposed_optimization": "Use std::atomic_thread_fence(std::memory_order_seq_cst) for portable "
                                  "memory barriers in C++11 and later. Avoid architecture-specific asm barriers.",
        "expected_benefit": "HYPOTHESIS: std::atomic_thread_fence is portable across all architectures "
                             "and optimised by the compiler for each target.",
        "risk": "Portable barriers may generate stronger (more expensive) fences than strictly necessary "
                 "on weakly-ordered architectures.",
        "verification_method": "Inspect generated assembly on each target to verify fence instruction selection.",
    },
    ("Embedded", "floating_point"): {
        "proposed_optimization": "Verify that the target MCU variant has a hardware FPU. "
                                  "If not, consider fixed-point arithmetic to avoid software FP emulation overhead. "
                                  "ESP32 (Xtensa LX6) has single-precision FPU; ESP32-S3 adds SIMD instructions.",
        "expected_benefit": "HYPOTHESIS: Fixed-point arithmetic avoids ~10-100x FP emulation overhead "
                             "on MCUs without hardware FPU.",
        "risk": "Fixed-point requires careful scaling and range analysis to avoid overflow.",
        "verification_method": "Compare FP vs fixed-point execution time with a cycle-accurate MCU simulator.",
    },
    ("Embedded", "printf_usage"): {
        "proposed_optimization": "Replace printf() with ESP_LOGI(TAG, ...) / ESP_LOGE(TAG, ...) "
                                  "from esp_log.h for level-controlled, thread-safe logging on ESP-IDF.",
        "expected_benefit": "HYPOTHESIS: ESP-IDF logging macros are thread-safe and can be compiled out "
                             "at LOG_LEVEL_NONE for release builds, reducing code size.",
        "risk": "ESP_LOG macros require the esp_log component from ESP-IDF.",
        "verification_method": "Build with LOG_LEVEL set to NONE and verify log output is absent.",
    },
    ("Embedded", "heap_check"): {
        "proposed_optimization": "The presence of heap monitoring calls indicates awareness of memory "
                                  "constraints — this is a positive practice. Ensure checks are also performed "
                                  "during peak allocation and under all error paths.",
        "expected_benefit": "HYPOTHESIS: Regular heap checks during testing reveal fragmentation before "
                             "deployment.",
        "risk": "Heap monitoring calls have a small runtime cost; acceptable in debug builds.",
        "verification_method": "Automate heap logging during integration tests and alert on low-heap conditions.",
    },
}


def _normalise_target(target):
    """Return the canonical target name, or None if not recognised."""
    if target is None:
        return None
    key = str(target).strip().lower()
    return _TARGET_ALIASES.get(key)


def _normalise_language(language):
    """Return the language if in LANGUAGES, otherwise 'Custom'."""
    if language is None:
        return "Custom"
    for lang in LANGUAGES:
        if lang.lower() == str(language).strip().lower():
            return lang
    return "Custom"


# ---------------------------------------------------------------------------
# Public API: static fit matrix query
# ---------------------------------------------------------------------------

def processor_fit(language, target):
    """Return the static fit assessment for a language on a target processor.

    Always returns a dict with 'advisory': True.
    Never raises.
    Never claims compatibility has been verified by running on hardware.
    """
    lang = _normalise_language(language)
    tgt = _normalise_target(target)

    if tgt is None:
        return {
            "language": language or "Unknown",
            "target": target or "Unknown",
            "fit": "UNKNOWN",
            "reason": f"Target '{target}' is not in the supported target list.",
            "notes": [f"Supported targets: {', '.join(TARGETS)}"],
            "advisory": True,
            "analysis_type": "STATIC_ANALYSIS",
            "disclaimer": (
                "This is a static advisory matrix based on publicly documented toolchain support. "
                "It is not a verified hardware compatibility test."
            ),
        }

    entry = _FIT_MATRIX.get((lang, tgt))
    if entry is None:
        # Language may be 'Custom' or an unmapped combination.
        fit = "UNKNOWN"
        reason = (
            f"No fit data available for '{lang}' on '{tgt}'. "
            "Verify toolchain and runtime support independently."
        )
        notes = []
    else:
        fit, reason, notes = entry

    return {
        "language": lang,
        "target": tgt,
        "fit": fit,
        "reason": reason,
        "notes": list(notes),
        "advisory": True,
        "analysis_type": "STATIC_ANALYSIS",
        "disclaimer": (
            "This is a static advisory matrix based on publicly documented toolchain support. "
            "It is not a verified hardware compatibility test."
        ),
    }


def processor_fit_all_targets(language):
    """Return fit assessments for a language across all supported targets."""
    return [processor_fit(language, t) for t in TARGETS]


# ---------------------------------------------------------------------------
# Public API: source heuristic analysis
# ---------------------------------------------------------------------------

def analyse_source(filename, text, target=None):
    """Analyse source text for processor-relevant characteristics.

    Returns observations (detected patterns) and per-target recommendations.
    All results are STATIC_ANALYSIS — never claimed as verified hardware results.
    Never raises.

    Args:
        filename: Source file name (used for language detection and finding context).
        text:     Source code as a string. None and empty string are handled safely.
        target:   Optional target name to filter recommendations. None = all targets.
    """
    text = text or ""
    filename_str = str(filename or "unknown_file")
    canonical_target = _normalise_target(target) if target else None

    observations = []
    recommendations = []

    for category, signal_name, pattern, observation_text, targets_affected in _SOURCE_PATTERNS:
        # Check if this signal is relevant to the requested target.
        if canonical_target is not None:
            if "ALL" not in targets_affected and canonical_target not in targets_affected:
                continue

        try:
            matches = list(re.finditer(pattern, text, re.MULTILINE | re.DOTALL))
        except Exception:
            continue

        if not matches:
            continue

        count = len(matches)
        first_line = text.count("\n", 0, matches[0].start()) + 1

        obs = {
            "category": category,
            "signal": signal_name,
            "file": filename_str,
            "first_line": first_line,
            "occurrences": count,
            "observation": observation_text,
            "targets_affected": targets_affected,
            "advisory": True,
            "analysis_type": "STATIC_ANALYSIS",
        }
        observations.append(obs)

        # Generate recommendations for each relevant target.
        tmpl = _RECOMMENDATION_TEMPLATES.get((category, signal_name))
        if tmpl is None:
            continue

        for tgt in (TARGETS if canonical_target is None else [canonical_target]):
            if "ALL" not in targets_affected and tgt not in targets_affected:
                continue
            rec = {
                "target": tgt,
                "category": category,
                "signal": signal_name,
                "file": filename_str,
                "first_line": first_line,
                "current_implementation": observation_text,
                "potential_issue": observation_text,
                "proposed_optimization": tmpl["proposed_optimization"],
                "expected_benefit": tmpl["expected_benefit"],
                "risk": tmpl["risk"],
                "verification_method": tmpl["verification_method"],
                "advisory": True,
                "analysis_type": "STATIC_ANALYSIS",
                "disclaimer": (
                    "This recommendation is based on static heuristic analysis of source patterns. "
                    "All expected benefits are hypotheses and must be validated by measurement "
                    "on the actual target hardware."
                ),
            }
            recommendations.append(rec)

    return {
        "file": filename_str,
        "target": canonical_target or "All targets",
        "observations": observations,
        "recommendations": recommendations,
        "observation_count": len(observations),
        "recommendation_count": len(recommendations),
        "advisory": True,
        "analysis_type": "STATIC_ANALYSIS",
        "disclaimer": (
            "All results are STATIC_ANALYSIS. No code was executed. "
            "No benchmark measurements were taken. "
            "All recommendations are hypotheses and must be validated on actual hardware."
        ),
    }
