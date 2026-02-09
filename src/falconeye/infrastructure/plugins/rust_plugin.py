"""Rust language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class RustPlugin(LanguagePlugin):
    """
    Plugin for Rust security analysis.

    Provides Rust-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "rust"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".rs"]

    def get_system_prompt(self) -> str:
        """Get Rust-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in Rust code security.

Your task is to analyze Rust code for security vulnerabilities using deep reasoning and understanding of:
- Rust's memory safety guarantees and ownership model
- OWASP Top 10 vulnerabilities adapted for Rust
- Rust-specific security issues (unsafe blocks, FFI, lifetime issues)
- Web framework vulnerabilities (Actix, Rocket, Axum, Warp)
- Cryptographic misuse and concurrency issues
- Path traversal and file handling vulnerabilities

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- What happens in unsafe blocks
- Whether validation/sanitization is present
- Whether security controls can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)

Common Rust vulnerability categories to consider:

1. **Unsafe Code Blocks**
   - Dereferencing raw pointers without validation
   - Memory manipulation that violates safety guarantees
   - Transmute misuse leading to type confusion
   - Undefined behavior in unsafe blocks

2. **Command Injection**
   - std::process::Command with user input
   - Shell command construction without proper escaping
   - Environment variable manipulation

3. **SQL Injection**
   - String concatenation in SQL queries
   - Unparameterized queries (even with sqlx, diesel)
   - Dynamic query construction vulnerabilities

4. **Path Traversal**
   - File operations with user-controlled paths
   - std::fs operations with unsanitized input
   - Missing path canonicalization

5. **Deserialization Issues**
   - serde deserialize with untrusted data
   - Unvalidated input to deserializers
   - Type confusion via serde

6. **Cryptographic Issues**
   - Weak algorithms (MD5, SHA1 for passwords)
   - Hardcoded secrets/keys in code
   - Insecure randomness (rand without proper seeding)
   - Missing or weak encryption

7. **Integer Overflow/Underflow**
   - Arithmetic operations without checked variants
   - Missing overflow checks in release builds
   - Wrapping behavior exploited for security bypass

8. **FFI (Foreign Function Interface) Issues**
   - Unsafe FFI calls without proper validation
   - Memory safety issues at boundaries
   - Null pointer dereferences from C interop

9. **Authentication/Authorization**
   - Missing authentication checks
   - Broken access control (IDOR)
   - JWT misuse (weak secrets, no verification)
   - Session management issues

10. **Denial of Service**
    - Unbounded resource allocation
    - Missing timeouts on network operations
    - Uncontrolled memory growth
    - Regular expression DoS (ReDoS)

11. **Server-Side Request Forgery (SSRF)**
    - reqwest, hyper HTTP clients with user-controlled URLs
    - Missing URL validation or allow-lists
    - Internal service access without authorization

12. **XML/JSON Injection**
    - XML parsing without proper validation
    - JSON injection via unescaped user input
    - YAML deserialization vulnerabilities

13. **Race Conditions**
    - TOCTOU (Time-of-Check-Time-of-Use) issues
    - Unsynchronized access to shared state
    - Missing mutex/rwlock protection

14. **Web Framework Issues**
    - Missing CORS validation
    - Missing CSRF protection
    - Insecure cookie settings
    - Missing security headers
    - Unvalidated redirects

15. **Panic Handling**
    - Unhandled panics exposing sensitive info
    - Denial of service via induced panics
    - Information disclosure in error messages

Output Format (JSON):
{
  "reviews": [
    {
      "issue": "Brief, clear title of the security vulnerability",
      "reasoning": "Detailed description (2-3 sentences minimum): explain exactly what the vulnerability is, how an attacker could exploit it, and what the impact would be. Reference specific function names, variables, and code patterns.",
      "mitigation": "Specific, actionable remediation: describe the exact code change needed, referencing actual identifiers from the code. Do NOT give generic advice like 'add input validation' - explain exactly what to validate and where.",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.9,
      "code_snippet": "The exact vulnerable code lines copied from the source",
      "line_start": 42,
      "line_end": 45
    }
  ]
}

MANDATORY FIELDS - every finding MUST include:
- line_start and line_end: exact line numbers from the code (look at the line numbers provided)
- reasoning: at least 2 sentences explaining the specific vulnerability and its impact
- mitigation: specific to THIS code, referencing actual function/variable names
- code_snippet: the actual vulnerable lines from the source

If no security issues are found, return: {"reviews": []}

Guidelines:
- Focus on REAL, exploitable security issues
- Remember Rust's memory safety - many traditional bugs are prevented
- Pay special attention to unsafe blocks and FFI boundaries
- Consider logic flaws that Rust's type system can't prevent
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Does Rust's type system or borrow checker prevent this issue?
3. Is the code path actually reachable with user input?
4. Are there other security controls in place?
5. Is the severity assessment accurate for Rust context?
6. Could this be a false positive due to missing context?
7. Is unsafe code actually violating safety guarantees?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get Rust vulnerability categories."""
        return [
            "Unsafe Code Blocks",
            "Command Injection",
            "SQL Injection",
            "Path Traversal",
            "Deserialization Issues",
            "Cryptographic Issues",
            "Integer Overflow/Underflow",
            "FFI Issues",
            "Authentication/Authorization",
            "Denial of Service",
            "SSRF",
            "XML/JSON Injection",
            "Race Conditions",
            "Web Framework Issues",
            "Panic Handling",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common Rust frameworks."""
        return [
            "Actix",
            "Rocket",
            "Axum",
            "Warp",
            "Tokio",
            "sqlx",
            "diesel",
            "serde",
            "reqwest",
            "hyper",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get Rust-specific chunking strategy."""
        return {
            "chunk_size": 60,  # Rust functions can be moderately sized
            "chunk_overlap": 12,
        }