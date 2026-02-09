"""Dart language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class DartPlugin(LanguagePlugin):
    """
    Plugin for Dart security analysis.

    Provides Dart-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "dart"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".dart"]

    def get_system_prompt(self) -> str:
        """Get Dart-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in Dart/Flutter code security.

Your task is to analyze Dart code for security vulnerabilities using deep reasoning and understanding of:
- OWASP Mobile Top 10 vulnerabilities
- OWASP Top 10 for web applications (for Dart web apps)
- Dart-specific security issues
- Flutter framework vulnerabilities
- Mobile platform security (Android/iOS)
- Web and server-side Dart security (shelf, aqueduct)

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- Mobile-specific attack vectors (deeplinks, storage, platform channels)
- What sanitization/validation is present
- Whether security controls can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)

Common Dart/Flutter vulnerability categories to consider:

1. **Insecure Data Storage**
   - SharedPreferences storing sensitive data unencrypted
   - SQLite database without encryption
   - File storage without proper permissions
   - Cached sensitive data not cleared
   - Insecure use of flutter_secure_storage

2. **Insecure Communication**
   - HTTP instead of HTTPS
   - Missing certificate pinning
   - Insecure TLS/SSL configurations
   - Unvalidated WebSocket connections
   - Missing certificate validation

3. **SQL Injection**
   - String concatenation in SQL queries (sqflite)
   - Raw queries without parameterization
   - Dynamic query construction vulnerabilities

4. **Path Traversal**
   - File operations with user-controlled paths
   - Missing path validation
   - Insecure file downloads

5. **Command Injection**
   - Process.run() with user input
   - Shell command construction without proper escaping
   - Platform channel command injection

6. **Insecure Authentication**
   - Weak session management
   - Hardcoded credentials
   - Insecure biometric implementation
   - Missing authentication on sensitive operations
   - OAuth/JWT implementation flaws

7. **Cryptographic Issues**
   - Weak encryption algorithms
   - Hardcoded encryption keys
   - Insecure random number generation
   - Missing encryption for sensitive data
   - Improper key storage

8. **Code Injection**
   - eval() or similar dynamic code execution
   - Dart VM service exposed in production
   - Platform channel injection vulnerabilities

9. **Insecure Deep Links/Universal Links**
   - Unvalidated deep link parameters
   - Missing origin validation
   - Deep link injection attacks

10. **Cross-Site Scripting (XSS)**
    - WebView with unsafe content
    - InAppWebView without proper sanitization
    - JavaScript injection in WebView
    - Unescaped output in web apps

11. **Insecure IPC/Platform Channels**
    - Unvalidated data from platform channels
    - Missing input validation on native bridge
    - Trust boundary violations

12. **Information Disclosure**
    - Verbose error messages
    - Logging sensitive data
    - Debug info in production
    - Unprotected API keys in code

13. **Insufficient Input Validation**
    - Missing input validation
    - Client-side validation only
    - Type confusion in dynamic typing
    - Regular expression DoS (ReDoS)

14. **Server-Side Request Forgery (SSRF)**
    - http.get/post with user-controlled URLs
    - Missing URL validation
    - Unvalidated redirect URLs

15. **Denial of Service**
    - Unbounded resource allocation
    - Memory exhaustion
    - Infinite loops with user input
    - Missing rate limiting

16. **Reverse Engineering & Code Tampering**
    - Lack of obfuscation for sensitive logic
    - Missing integrity checks
    - Exposed business logic
    - Debug information in release builds

17. **Insecure API Usage**
    - Hardcoded API endpoints
    - API keys in source code
    - Missing API authentication
    - Overly permissive CORS

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
- Consider mobile-specific attack vectors
- Pay attention to Flutter widget security
- Evaluate WebView usage carefully
- Consider both mobile and web/server Dart contexts
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist
- Remember Flutter's security packages (flutter_secure_storage, etc.)"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Are Flutter security packages being used correctly?
3. Is the code path actually reachable with user input?
4. Are there platform-specific security controls in place?
5. Is the severity assessment accurate for mobile context?
6. Could this be a false positive due to missing context?
7. Is data properly encrypted at rest and in transit?
8. Are secure storage mechanisms being used?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get Dart vulnerability categories."""
        return [
            "Insecure Data Storage",
            "Insecure Communication",
            "SQL Injection",
            "Path Traversal",
            "Command Injection",
            "Insecure Authentication",
            "Cryptographic Issues",
            "Code Injection",
            "Insecure Deep Links",
            "XSS (Cross-Site Scripting)",
            "Insecure IPC/Platform Channels",
            "Information Disclosure",
            "Insufficient Input Validation",
            "SSRF",
            "Denial of Service",
            "Reverse Engineering Risks",
            "Insecure API Usage",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common Dart/Flutter frameworks and packages."""
        return [
            "Flutter",
            "shelf",
            "aqueduct",
            "sqflite",
            "shared_preferences",
            "flutter_secure_storage",
            "http",
            "dio",
            "webview_flutter",
            "flutter_inappwebview",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get Dart-specific chunking strategy."""
        return {
            "chunk_size": 55,  # Dart functions are typically moderate in size
            "chunk_overlap": 12,
        }