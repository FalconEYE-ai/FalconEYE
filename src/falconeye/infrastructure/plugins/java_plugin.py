"""Java language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class JavaPlugin(LanguagePlugin):
    """
    Plugin for Java security analysis.

    Provides Java-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "java"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".java"]

    def get_system_prompt(self) -> str:
        """Get Java-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in Java code security.

Your task is to analyze Java code for security vulnerabilities using deep reasoning and understanding of:
- OWASP Top 10 vulnerabilities adapted for Java
- Java-specific security issues (reflection, serialization, class loading)
- Enterprise framework vulnerabilities (Spring, Jakarta EE, Struts)
- JVM security model and limitations
- Authentication, authorization, and session management
- Cryptographic API misuse

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- What sanitization/validation is present
- Whether security controls can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)
- Framework-specific security mechanisms

Common Java vulnerability categories to consider:

1. **SQL Injection**
   - String concatenation in SQL queries
   - Unparameterized JDBC statements
   - HQL/JPQL injection in JPA/Hibernate
   - MyBatis dynamic SQL vulnerabilities

2. **XML External Entity (XXE)**
   - XML parsers without disabling external entities
   - SAXParser, DocumentBuilder, XMLReader misuse
   - JAXB, XStream vulnerabilities
   - Missing secure processing features

3. **Deserialization Vulnerabilities**
   - ObjectInputStream with untrusted data
   - Java Serialization gadget chains
   - JSON/XML deserialization issues (Jackson, Gson, XStream)
   - RMI/JMX deserialization attacks

4. **Command Injection**
   - Runtime.exec(), ProcessBuilder with user input
   - Shell command construction without proper escaping
   - Script engine (ScriptEngine) vulnerabilities

5. **Path Traversal**
   - File operations with user-controlled paths
   - Missing path validation or canonicalization
   - Zip slip vulnerabilities in archive extraction

6. **Server-Side Request Forgery (SSRF)**
   - URL/URLConnection with user-controlled URLs
   - Missing URL validation or allow-lists
   - HTTP client (HttpClient, RestTemplate) misuse

7. **Authentication/Authorization**
   - Missing authentication checks
   - Broken access control (IDOR)
   - JWT misuse (weak secrets, no verification)
   - Spring Security misconfigurations
   - Session fixation vulnerabilities

8. **Cross-Site Scripting (XSS)**
   - Unescaped output in JSP/JSF/Thymeleaf
   - Missing output encoding
   - DOM-based XSS in JavaScript generation
   - Stored and reflected XSS patterns

9. **Cross-Site Request Forgery (CSRF)**
   - Missing CSRF tokens
   - State-changing GET requests
   - Improper CSRF protection in Spring

10. **Cryptographic Issues**
    - Weak algorithms (MD5, SHA1, DES)
    - Hardcoded secrets/keys in code
    - Insecure randomness (Random vs SecureRandom)
    - Missing or weak encryption
    - Improper certificate validation

11. **Reflection and Code Injection**
    - Class.forName() with user input
    - Method.invoke() vulnerabilities
    - Dynamic class loading
    - Expression Language (EL) injection

12. **LDAP Injection**
    - Unvalidated input in LDAP queries
    - LDAP filter construction vulnerabilities

13. **Race Conditions**
    - TOCTOU (Time-of-Check-Time-of-Use) issues
    - Unsynchronized access to shared resources
    - Thread safety violations

14. **Mass Assignment**
    - Unprotected model binding
    - Missing @JsonIgnore on sensitive fields
    - Spring Data binding vulnerabilities

15. **Information Disclosure**
    - Verbose error messages
    - Stack traces in production
    - Sensitive data in logs
    - Directory listings enabled

16. **Denial of Service**
    - Unbounded resource allocation
    - Regular expression DoS (ReDoS)
    - Recursive operations without limits
    - Missing timeout configurations

17. **Server-Side Template Injection (SSTI)**
    - FreeMarker, Velocity, Thymeleaf injection
    - User-controlled template content

18. **Open Redirect**
    - Unvalidated redirect URLs
    - Missing whitelist validation

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
- Consider Java's type safety but remember logic flaws still exist
- Pay attention to framework-specific security features
- Evaluate deserialization risks carefully (critical in Java)
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist
- Remember Spring Security, OWASP ESAPI, and other defensive libraries"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Are framework security features (Spring Security, etc.) in place?
3. Is the code path actually reachable with user input?
4. Are there other security controls in place?
5. Is the severity assessment accurate for Java context?
6. Could this be a false positive due to missing context?
7. Are defensive libraries (OWASP ESAPI) being used?
8. Is deserialization properly restricted?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get Java vulnerability categories."""
        return [
            "SQL Injection",
            "XXE (XML External Entity)",
            "Deserialization Vulnerabilities",
            "Command Injection",
            "Path Traversal",
            "SSRF",
            "Authentication/Authorization",
            "XSS (Cross-Site Scripting)",
            "CSRF",
            "Cryptographic Issues",
            "Reflection and Code Injection",
            "LDAP Injection",
            "Race Conditions",
            "Mass Assignment",
            "Information Disclosure",
            "Denial of Service",
            "SSTI (Server-Side Template Injection)",
            "Open Redirect",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common Java frameworks."""
        return [
            "Spring Framework",
            "Spring Boot",
            "Spring Security",
            "Jakarta EE",
            "Hibernate",
            "JPA",
            "Struts",
            "JSF",
            "Apache Tomcat",
            "JDBC",
            "MyBatis",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get Java-specific chunking strategy."""
        return {
            "chunk_size": 65,  # Java methods can be verbose
            "chunk_overlap": 15,
        }