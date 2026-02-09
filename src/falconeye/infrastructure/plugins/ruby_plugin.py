"""Ruby language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class RubyPlugin(LanguagePlugin):
    """
    Plugin for Ruby security analysis.

    Provides Ruby-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "ruby"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".rb", ".rake", ".gemspec", "Gemfile", "Rakefile"]

    def get_system_prompt(self) -> str:
        """Get Ruby-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in Ruby code security.

Your task is to analyze Ruby code for security vulnerabilities using deep reasoning and understanding of:
- Ruby language semantics, dynamic nature, and metaprogramming
- OWASP Top 10 vulnerabilities adapted for Ruby/Rails
- Ruby-specific security issues (YAML deserialization, eval, send)
- Rails framework vulnerabilities (mass assignment, strong parameters, SQL injection)
- Authentication/authorization issues (Devise, CanCanCan, Pundit)
- Session management and CSRF protection
- Ruby gem security issues

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code (data flow analysis)
- What sanitization/validation is present and if it can be bypassed
- Whether security controls are properly implemented
- The actual exploitability of potential issues
- Context from related code (if provided)
- Rails conventions and security best practices

Common Ruby vulnerability categories to consider:

1. **Command Injection**
   - Backticks (`cmd`), system(), exec(), %x{cmd}
   - Open3.capture2(), Open3.popen3() with user input
   - Kernel.spawn() with shell: true
   - Look for proper command sanitization or use of array arguments

2. **SQL Injection**
   - String interpolation in ActiveRecord queries (where("name = '#{params[:name]}'"))
   - Raw SQL with User.connection.execute()
   - find_by_sql() with unsanitized input
   - Look for parameterized queries: where(name: params[:name]) or where("name = ?", params[:name])

3. **Mass Assignment Vulnerabilities**
   - Missing strong parameters (permit) in Rails controllers
   - Using params directly without filtering
   - attr_accessible misuse (old Rails versions)
   - Look for proper params.require().permit() usage

4. **YAML Deserialization**
   - YAML.load() with untrusted data (allows arbitrary code execution)
   - Look for YAML.safe_load() or YAML.safe_load_file() instead
   - Psych.load() vs Psych.safe_load()

5. **Code Injection**
   - eval(), instance_eval(), class_eval(), module_eval() with user input
   - Dynamic method calls with send(), public_send() on user-controlled input
   - const_get(), constantize() with user input
   - define_method() with user-controlled data

6. **Path Traversal**
   - File.open(), File.read() with user-controlled paths
   - Dir.glob() with unsanitized patterns
   - Missing path validation or sanitization
   - Look for File.expand_path() with proper base directory

7. **XML External Entity (XXE)**
   - Nokogiri::XML() without external entity restrictions
   - REXML parsing without disabling entities
   - Look for Nokogiri::XML(xml) { |config| config.noent.nonet }

8. **Regular Expression DoS (ReDoS)**
   - Complex regex with nested quantifiers
   - User input used in regex patterns
   - Look for catastrophic backtracking patterns: (a+)+, (a|a)*

9. **Authentication/Authorization Issues**
   - Missing before_action :authenticate_user!
   - Broken access control (IDOR - Insecure Direct Object References)
   - JWT misuse (weak secrets, no verification)
   - Devise misconfiguration
   - CanCanCan/Pundit authorization bypass
   - Session fixation vulnerabilities

10. **CSRF Protection**
    - Missing protect_from_forgery in ApplicationController
    - skip_before_action :verify_authenticity_token without proper justification
    - Custom actions bypassing CSRF protection

11. **Symbol Denial of Service**
    - params[:key].to_sym on user input (symbols are not garbage collected)
    - Look for safe alternatives or validation

12. **Template Injection**
    - ERB with user input: ERB.new(user_input).result
    - render inline: with unsanitized user data
    - Slim, Haml template injection

13. **Open Redirect**
    - redirect_to params[:url] without validation
    - Missing URL whitelist or validation
    - Look for proper URL validation before redirects

14. **Insecure Cryptography**
    - Weak hashing algorithms (MD5, SHA1 for passwords)
    - Hardcoded secrets in code
    - Insecure random: rand() vs SecureRandom
    - Missing or weak encryption

15. **Information Disclosure**
    - Detailed error messages in production
    - Debug information exposed
    - Sensitive data in logs

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
- Consider defense-in-depth: multiple layers of protection may exist
- Understand Rails conventions (e.g., strong parameters are enforced by default in modern Rails)"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Is the code path actually reachable with user input?
3. Are there other security controls in place (Rails framework protections)?
4. Is the severity assessment accurate?
5. Could this be a false positive due to missing context?
6. Are Rails conventions properly followed (strong parameters, CSRF protection)?
7. Is this a known safe pattern in the Ruby/Rails ecosystem?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get Ruby vulnerability categories."""
        return [
            "Command Injection",
            "SQL Injection",
            "Mass Assignment",
            "YAML Deserialization",
            "Code Injection (eval/send)",
            "Path Traversal",
            "XXE",
            "Regular Expression DoS (ReDoS)",
            "Authentication Issues",
            "Authorization Issues",
            "CSRF",
            "Symbol DoS",
            "Template Injection",
            "Open Redirect",
            "Insecure Cryptography",
            "Information Disclosure",
            "Session Fixation",
            "IDOR",
            "Hardcoded Secrets",
        ]

    def get_framework_context(self) -> str:
        """Get common Ruby frameworks context."""
        return """Ruby Framework Security Context:

**Ruby on Rails** (Most common Ruby web framework):
- ActiveRecord ORM with built-in SQL injection protection (use parameterized queries)
- Strong Parameters for mass assignment protection (params.require().permit())
- CSRF protection via protect_from_forgery (ApplicationController)
- Secure session management
- Built-in XSS protection in ERB templates (auto-escaping)
- Asset pipeline with integrity checks
- Content Security Policy (CSP) support

**Sinatra** (Lightweight web framework):
- Rack-based, less built-in security
- Manual CSRF protection required
- Manual XSS escaping needed
- Flexible but requires more security awareness

**Hanami** (Modern Ruby framework):
- Built-in security features
- Secure by default approach
- Entity protection against mass assignment
- Strong parameter validation

**Rack** (Web server interface):
- Rack::Protection middleware for common attacks
- Session management
- CSRF token generation

**Common Gems**:
- Devise: Authentication solution
- CanCanCan/Pundit: Authorization frameworks
- Nokogiri: XML/HTML parsing
- BCrypt: Password hashing
- JWT: JSON Web Token handling

Security Best Practices:
- Use parameterized queries or ActiveRecord safe methods
- Always use strong parameters in Rails controllers
- Use YAML.safe_load() instead of YAML.load()
- Validate and sanitize user input
- Use SecureRandom for cryptographic randomness
- Never use eval() or instance_eval() with user input
- Implement proper authentication and authorization
- Keep gems updated (bundle audit)
- Use Content Security Policy headers
- Enable CSRF protection"""

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get Ruby-specific chunking strategy."""
        return {
            "chunk_size": 60,  # Ruby methods can be longer
            "chunk_overlap": 15,  # More overlap for context
        }
