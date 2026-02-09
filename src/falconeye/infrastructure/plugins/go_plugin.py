"""Go language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class GoPlugin(LanguagePlugin):
    """
    Plugin for Go security analysis.

    Provides Go-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "go"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".go"]

    def get_system_prompt(self) -> str:
        """Get Go-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in Go (Golang) code security.

Your task is to analyze Go code for security vulnerabilities using deep reasoning and understanding of:
- Go language semantics, goroutines, and channels
- OWASP Top 10 vulnerabilities adapted for Go
- Go-specific security issues (unsafe package, reflection, race conditions)
- Web framework vulnerabilities (Gin, Echo, Fiber, Chi)
- Cryptographic misuse and concurrency issues
- Path traversal and file handling vulnerabilities

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- Goroutine safety and race conditions
- What sanitization/validation is present
- Whether security controls can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)

Common Go vulnerability categories to consider:

1. **Command Injection**
   - exec.Command() with user input
   - os/exec package misuse
   - Shell command construction without proper escaping

2. **SQL Injection**
   - String concatenation in SQL queries
   - Unparameterized queries
   - ORM misuse (GORM, sqlx)

3. **Path Traversal**
   - File operations with user-controlled paths
   - os.Open(), ioutil.ReadFile() with user input
   - Missing path validation (filepath.Clean())

4. **XML External Entity (XXE)**
   - XML parsing without disabling external entities
   - encoding/xml package misuse

5. **Server-Side Request Forgery (SSRF)**
   - http.Get(), http.Post() with user-controlled URLs
   - Missing URL validation or allow-lists

6. **Cryptographic Issues**
   - Weak algorithms (MD5, SHA1 for passwords)
   - Hardcoded secrets/keys in code
   - Insecure randomness (math/rand vs crypto/rand)
   - Missing or weak encryption

7. **Race Conditions**
   - Unsynchronized access to shared data
   - Missing mutex locks
   - Goroutine safety issues

8. **Type Confusion & Unsafe Operations**
   - unsafe package usage
   - Type assertions without checks
   - Reflection misuse

9. **Authentication/Authorization**
   - Missing authentication checks
   - Broken access control (IDOR)
   - JWT misuse (weak secrets, no verification)
   - Session management issues

10. **Denial of Service**
    - Unbounded resource allocation
    - Missing timeouts on HTTP clients
    - Goroutine leaks
    - Uncontrolled memory growth

11. **Deserialization Issues**
    - encoding/gob with untrusted data
    - JSON unmarshaling vulnerabilities

12. **HTTP Security Issues**
    - Missing CORS validation
    - Missing CSRF protection
    - Insecure cookie settings
    - Missing security headers

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
- Consider Go's memory safety (but not its type safety edge cases)
- Think about goroutine-related vulnerabilities
- Evaluate race conditions and concurrency issues
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Are goroutines and race conditions properly handled?
3. Is the code path actually reachable with user input?
4. Are there other security controls in place?
5. Is the severity assessment accurate for Go context?
6. Could this be a false positive due to missing context?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get Go vulnerability categories."""
        return [
            "Command Injection",
            "SQL Injection",
            "Path Traversal",
            "XXE",
            "SSRF",
            "Cryptographic Issues",
            "Race Conditions",
            "Unsafe Operations",
            "Authentication/Authorization",
            "Denial of Service",
            "Deserialization",
            "HTTP Security Issues",
            "Hardcoded Secrets",
            "Type Confusion",
            "Goroutine Leaks",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common Go frameworks."""
        return [
            "Gin",
            "Echo",
            "Fiber",
            "Chi",
            "GORM",
            "sqlx",
            "gorilla/mux",
            "net/http",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get Go-specific chunking strategy."""
        return {
            "chunk_size": 55,  # Go functions can be moderately sized
            "chunk_overlap": 12,
        }