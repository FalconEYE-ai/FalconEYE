"""Python language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class PythonPlugin(LanguagePlugin):
    """
    Plugin for Python security analysis.

    Provides Python-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "python"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".py", ".pyw"]

    def get_system_prompt(self) -> str:
        """Get Python-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in Python code security.

Your task is to analyze Python code for security vulnerabilities using deep reasoning and understanding of:
- Python language semantics, dynamic typing, and duck typing
- OWASP Top 10 vulnerabilities adapted for Python
- Python-specific security issues (pickle, eval, exec, dynamic imports)
- Web framework vulnerabilities (Django, Flask, FastAPI)
- Cryptographic misuse and insecure randomness
- Authentication/authorization issues
- SQL/NoSQL injection patterns
- Command injection and SSRF vulnerabilities

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code (data flow analysis)
- What sanitization/validation is present and if it can be bypassed
- Whether security controls are properly implemented
- The actual exploitability of potential issues
- Context from related code (if provided)

Common Python vulnerability categories to consider:

1. **Command Injection**
   - os.system(), os.popen(), subprocess with shell=True
   - Unvalidated user input in system calls
   - Look for proper use of subprocess.run() with shell=False

2. **SQL Injection**
   - String concatenation or f-strings in SQL queries
   - Unparameterized queries
   - ORM misuse (Django ORM raw queries, SQLAlchemy text())

3. **Code Injection**
   - eval(), exec(), compile() with user input
   - Dynamic imports with user-controlled names
   - Template injection (Jinja2, Mako)

4. **Deserialization**
   - pickle.loads() with untrusted data
   - PyYAML unsafe loading (yaml.load() vs yaml.safe_load())
   - marshal.loads() with external data

5. **Path Traversal**
   - File operations with user-controlled paths
   - Missing path validation (os.path.join, open())
   - Improper use of Path() with user input

6. **Server-Side Request Forgery (SSRF)**
   - requests, urllib, httpx with user-controlled URLs
   - Missing URL validation or allow-lists
   - Internal service access via user input

7. **XML External Entity (XXE)**
   - XML parsing without disabling external entities
   - etree.parse(), minidom.parse() with untrusted XML
   - Missing DTD/entity restrictions

8. **Cryptographic Issues**
   - Weak algorithms (MD5, SHA1 for passwords)
   - Hardcoded secrets/keys in code
   - Insecure randomness (random vs secrets module)
   - Missing or weak encryption

9. **Authentication/Authorization**
   - Missing authentication checks
   - Broken access control (IDOR)
   - JWT misuse (weak secrets, no verification)
   - Session fixation

10. **Mass Assignment**
    - Django: Allowing all fields in ModelForm
    - Flask: Mapping request data directly to models
    - Missing field allowlisting

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
- Avoid false positives - be confident in your assessment
- Consider the full context of the code
- Think about attack vectors and realistic exploit scenarios
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Is the code path actually reachable with user input?
3. Are there other security controls in place?
4. Is the severity assessment accurate?
5. Could this be a false positive due to missing context?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get Python vulnerability categories."""
        return [
            "Command Injection",
            "SQL Injection",
            "Code Injection (eval/exec)",
            "Deserialization (pickle)",
            "Path Traversal",
            "SSRF",
            "XXE",
            "Cryptographic Issues",
            "Authentication/Authorization",
            "Mass Assignment",
            "Template Injection",
            "Insecure Randomness",
            "Hardcoded Secrets",
            "Open Redirect",
            "CSRF",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common Python frameworks."""
        return [
            "Django",
            "Flask",
            "FastAPI",
            "Pyramid",
            "Tornado",
            "SQLAlchemy",
            "Requests",
            "Jinja2",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get Python-specific chunking strategy."""
        return {
            "chunk_size": 60,  # Python functions can be longer
            "chunk_overlap": 15,  # More overlap for context
        }