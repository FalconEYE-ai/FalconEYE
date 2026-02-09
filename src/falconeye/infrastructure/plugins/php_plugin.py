"""PHP language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class PHPPlugin(LanguagePlugin):
    """
    Plugin for PHP security analysis.

    Provides PHP-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "php"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".php", ".phtml", ".php3", ".php4", ".php5", ".phps"]

    def get_system_prompt(self) -> str:
        """Get PHP-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in PHP code security.

Your task is to analyze PHP code for security vulnerabilities using deep reasoning and understanding of:
- OWASP Top 10 vulnerabilities adapted for PHP
- PHP-specific security issues (type juggling, magic methods, globals)
- Web framework vulnerabilities (Laravel, Symfony, CodeIgniter, WordPress)
- PHP configuration security (php.ini, security headers)
- Modern PHP features (7.x, 8.x) and their security implications

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- What sanitization/validation is present
- PHP's loose typing and type juggling vulnerabilities
- Whether security controls can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)

Common PHP vulnerability categories to consider:

1. **SQL Injection**
   - String concatenation in SQL queries
   - mysql_query, mysqli_query without prepared statements
   - PDO without parameter binding
   - ORM misuse (Eloquent, Doctrine)

2. **Cross-Site Scripting (XSS)**
   - Unescaped output (echo, print)
   - Missing htmlspecialchars/htmlentities
   - Improper context escaping (HTML, JS, CSS, URL)
   - Stored, reflected, and DOM-based XSS

3. **Command Injection**
   - exec(), system(), shell_exec(), passthru() with user input
   - backtick operator with user input
   - proc_open(), popen() vulnerabilities
   - Missing escapeshellarg/escapeshellcmd

4. **Path Traversal**
   - include/require with user input
   - File operations (fopen, file_get_contents) with user paths
   - Missing path validation
   - Zip extraction vulnerabilities

5. **Remote Code Execution (RCE)**
   - eval() with user input
   - Deserialization vulnerabilities (unserialize)
   - include/require remote file inclusion (RFI)
   - preg_replace /e modifier (deprecated but still seen)
   - create_function() misuse

6. **Authentication/Authorization**
   - Missing authentication checks
   - Broken access control (IDOR)
   - Weak session management
   - Missing CSRF protection
   - Type juggling in authentication (== vs ===)

7. **Type Juggling**
   - Loose comparison (==) instead of strict (===)
   - strcmp() return value misuse
   - in_array() without strict mode
   - Magic hash vulnerabilities

8. **File Upload Vulnerabilities**
   - Missing file type validation
   - Inadequate MIME type checking
   - Unrestricted file upload
   - Double extension bypass (.php.jpg)
   - Path traversal in upload paths

9. **Server-Side Request Forgery (SSRF)**
   - file_get_contents(), curl with user-controlled URLs
   - Missing URL validation
   - Internal service access without authorization

10. **XML External Entity (XXE)**
    - simplexml_load_string/file without disabling external entities
    - DOMDocument without LIBXML_NOENT
    - XML parser misconfigurations

11. **Insecure Deserialization**
    - unserialize() with untrusted data
    - Phar deserialization vulnerabilities
    - Magic method exploitation (__wakeup, __destruct)

12. **Cryptographic Issues**
    - Weak algorithms (MD5, SHA1 for passwords)
    - Hardcoded secrets/keys in code
    - Insecure randomness (rand() vs random_bytes())
    - Missing or weak password hashing
    - Use of password_hash() with weak algorithms

13. **LDAP Injection**
    - Unvalidated input in LDAP queries
    - ldap_search(), ldap_bind() vulnerabilities

14. **Server-Side Template Injection (SSTI)**
    - Twig, Blade, Smarty template injection
    - User-controlled template content
    - Missing sandbox escaping

15. **Session Management Issues**
    - Predictable session IDs
    - Missing session regeneration
    - Session fixation vulnerabilities
    - Insecure cookie settings

16. **Information Disclosure**
    - Verbose error messages (display_errors on)
    - phpinfo() in production
    - Exposed configuration files
    - Sensitive data in logs

17. **Open Redirect**
    - Unvalidated redirect URLs (header("Location:..."))
    - Missing whitelist validation

18. **HTTP Header Injection**
    - Unvalidated input in header()
    - CRLF injection in headers
    - Cookie manipulation

19. **Regular Expression DoS (ReDoS)**
    - Catastrophic backtracking in preg_match
    - Unbounded regex execution

20. **Mass Assignment**
    - Unprotected model binding in frameworks
    - Missing $fillable/$guarded in Laravel

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
- Pay special attention to type juggling vulnerabilities (unique to PHP)
- Consider PHP's dynamic nature and loose typing
- Evaluate both procedural and OOP PHP code
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist
- Remember framework security features (Laravel CSRF, Symfony Security)
- Consider modern PHP versions (7.x, 8.x) vs legacy code"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Are framework security features being used correctly?
3. Is the code path actually reachable with user input?
4. Are there other security controls in place?
5. Is the severity assessment accurate for PHP context?
6. Could this be a false positive due to missing context?
7. Are input filtering functions (filter_input, filter_var) being used?
8. Is output properly escaped for context (HTML, JS, URL)?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get PHP vulnerability categories."""
        return [
            "SQL Injection",
            "XSS (Cross-Site Scripting)",
            "Command Injection",
            "Path Traversal",
            "Remote Code Execution",
            "Authentication/Authorization",
            "Type Juggling",
            "File Upload Vulnerabilities",
            "SSRF",
            "XXE (XML External Entity)",
            "Insecure Deserialization",
            "Cryptographic Issues",
            "LDAP Injection",
            "SSTI (Server-Side Template Injection)",
            "Session Management Issues",
            "Information Disclosure",
            "Open Redirect",
            "HTTP Header Injection",
            "ReDoS (Regular Expression DoS)",
            "Mass Assignment",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common PHP frameworks."""
        return [
            "Laravel",
            "Symfony",
            "CodeIgniter",
            "WordPress",
            "Drupal",
            "Yii",
            "CakePHP",
            "Zend Framework",
            "Slim",
            "Doctrine ORM",
            "Eloquent ORM",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get PHP-specific chunking strategy."""
        return {
            "chunk_size": 50,  # PHP functions can vary in size
            "chunk_overlap": 10,
        }