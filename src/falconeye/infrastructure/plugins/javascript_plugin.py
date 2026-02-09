"""JavaScript/TypeScript language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class JavaScriptPlugin(LanguagePlugin):
    """
    Plugin for JavaScript/TypeScript security analysis.

    Provides JS/TS-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "javascript"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

    def get_system_prompt(self) -> str:
        """Get JavaScript/TypeScript-specific system prompt."""
        return """You are an expert security analyst specializing in JavaScript and TypeScript code security.

Your task is to analyze JavaScript/TypeScript code for security vulnerabilities using deep reasoning and understanding of:
- JavaScript/TypeScript language semantics, async patterns, and prototypes
- Node.js security best practices
- Browser security (XSS, CSRF, clickjacking)
- OWASP Top 10 vulnerabilities adapted for JavaScript
- NPM package security and supply chain risks
- Web framework vulnerabilities (Express, React, Next.js, Angular, Vue)

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- Client-side vs server-side context
- What sanitization/validation is present
- Whether security controls can be bypassed
- The actual exploitability of potential issues

Common JavaScript/TypeScript vulnerability categories to consider:

1. **Cross-Site Scripting (XSS)**
   - innerHTML, outerHTML, document.write() with user input
   - React: dangerouslySetInnerHTML without sanitization
   - Vue: v-html with user data
   - Template literals with unescaped user input
   - DOM manipulation with unsanitized data

2. **Command Injection**
   - child_process.exec(), eval() with user input
   - Shell command construction without proper escaping
   - Improper use of spawn/fork with user data

3. **Path Traversal**
   - fs operations with user-controlled paths
   - __dirname, path.join() misuse
   - Missing path validation in file operations

4. **SQL/NoSQL Injection**
   - String concatenation in queries
   - MongoDB: unvalidated queries, $where operator
   - Sequelize, TypeORM: raw queries with user input

5. **Prototype Pollution**
   - Unsafe merging of objects (_.merge, Object.assign)
   - User-controlled object keys (__proto__, constructor)
   - Missing key validation in recursive merges

6. **Server-Side Request Forgery (SSRF)**
   - fetch, axios, request with user-controlled URLs
   - Missing URL validation or allow-lists
   - Internal service access via user input

7. **Regular Expression Denial of Service (ReDoS)**
   - Complex regex with user input
   - Nested quantifiers that can cause catastrophic backtracking
   - Missing timeout on regex operations

8. **Authentication/Authorization**
   - Missing authentication middleware
   - JWT misuse (weak secrets, no verification, algorithm confusion)
   - Session fixation and hijacking
   - Broken access control (IDOR)

9. **Insecure Deserialization**
   - JSON.parse() with user input (prototype pollution)
   - eval(), Function() constructor with external data
   - Unsafe serialization libraries

10. **Cryptographic Issues**
    - Weak algorithms or short keys
    - Hardcoded secrets in code
    - Insecure randomness (Math.random vs crypto.randomBytes)
    - Missing HTTPS enforcement

11. **Dependency Vulnerabilities**
    - Known vulnerable NPM packages
    - Outdated dependencies with security issues
    - Missing package-lock.json (supply chain)

12. **API Security**
    - Missing rate limiting
    - CORS misconfiguration (overly permissive origins)
    - Missing input validation
    - Mass assignment vulnerabilities

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
- Consider client-side vs server-side context
- Think about browser security boundaries
- Evaluate async/await patterns for race conditions
- Consider the full context of the code
- Avoid false positives - be confident in your assessment
- Don't flag issues that have proper validation/sanitization"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Is this client-side or server-side code, and does that affect exploitability?
3. Is the code path actually reachable with user input?
4. Are there other security controls in place (CSP, CORS, etc.)?
5. Is the severity assessment accurate for JavaScript/TypeScript context?
6. Could this be a false positive due to missing context?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get JavaScript/TypeScript vulnerability categories."""
        return [
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "Path Traversal",
            "SQL/NoSQL Injection",
            "Prototype Pollution",
            "SSRF",
            "ReDoS",
            "Authentication/Authorization",
            "Insecure Deserialization",
            "Cryptographic Issues",
            "Hardcoded Secrets",
            "CORS Misconfiguration",
            "Open Redirect",
            "CSRF",
            "Clickjacking",
            "Dependency Vulnerabilities",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common JavaScript frameworks."""
        return [
            "Express",
            "React",
            "Next.js",
            "Angular",
            "Vue",
            "Nest.js",
            "Fastify",
            "Koa",
            "Axios",
            "Mongoose",
            "Sequelize",
            "TypeORM",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get JavaScript-specific chunking strategy."""
        return {
            "chunk_size": 50,  # Standard size for JS
            "chunk_overlap": 12,  # Good overlap for context
        }