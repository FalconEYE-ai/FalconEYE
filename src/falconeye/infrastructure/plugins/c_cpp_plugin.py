"""C/C++ language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class CCppPlugin(LanguagePlugin):
    """
    Plugin for C/C++ security analysis.

    Provides C/C++-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "c_cpp"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"]

    def get_system_prompt(self) -> str:
        """Get C/C++-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in C/C++ code security.

Your task is to analyze C/C++ code for security vulnerabilities using deep reasoning and understanding of:
- Memory management issues (buffer overflows, use-after-free, double-free)
- OWASP Top 10 vulnerabilities adapted for C/C++
- CWE Top 25 Most Dangerous Software Weaknesses
- C/C++-specific security issues (pointer arithmetic, type confusion)
- Modern C++ features that enhance or reduce security
- Concurrency and race conditions

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code
- Memory allocation and deallocation patterns
- Pointer arithmetic and boundary checks
- Whether validation/sanitization is present
- Whether security controls can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)

Common C/C++ vulnerability categories to consider:

1. **Buffer Overflow/Underflow**
   - strcpy, strcat, sprintf, gets without bounds checking
   - Array indexing without validation
   - Off-by-one errors
   - Stack-based and heap-based buffer overflows

2. **Memory Management Issues**
   - Use-after-free vulnerabilities
   - Double-free vulnerabilities
   - Memory leaks enabling DoS
   - Uninitialized memory reads
   - Null pointer dereferences

3. **Integer Overflow/Underflow**
   - Arithmetic operations without overflow checks
   - Integer truncation issues
   - Signed/unsigned conversion issues
   - Integer overflow leading to buffer overflow

4. **Format String Vulnerabilities**
   - printf, sprintf, fprintf with user-controlled format strings
   - Missing format specifiers
   - Information disclosure via format strings

5. **Command Injection**
   - system(), popen(), exec family with user input
   - Shell command construction without proper escaping
   - Environment variable manipulation

6. **Path Traversal**
   - File operations with user-controlled paths
   - Missing path validation or canonicalization
   - Directory traversal vulnerabilities

7. **SQL Injection**
   - String concatenation in SQL queries
   - Unparameterized queries (MySQL C API, PostgreSQL libpq)
   - Dynamic query construction vulnerabilities

8. **Race Conditions**
   - TOCTOU (Time-of-Check-Time-of-Use) issues
   - Unsynchronized access to shared resources
   - File system race conditions
   - Signal handler race conditions

9. **Type Confusion**
   - Unsafe type casts
   - Union type confusion
   - C++ RTTI bypass
   - Virtual function table corruption

10. **Cryptographic Issues**
    - Weak algorithms (MD5, SHA1, DES)
    - Hardcoded secrets/keys in code
    - Insecure randomness (rand() vs cryptographic RNG)
    - Missing or weak encryption
    - Improper key management

11. **Pointer Issues**
    - Dangling pointers
    - Wild pointers
    - Pointer arithmetic errors
    - Function pointer hijacking

12. **Resource Management**
    - File descriptor leaks
    - Socket resource exhaustion
    - Missing resource cleanup
    - Signal handling issues

13. **Concurrency Issues**
    - Deadlocks
    - Race conditions in multithreaded code
    - Missing mutex protection
    - Improper thread synchronization

14. **C++ Specific Issues**
    - Exception safety violations
    - RAII violations
    - Virtual destructor missing in base classes
    - Slicing problems
    - Move semantics misuse

15. **Input Validation**
    - Missing bounds checks
    - Insufficient input validation
    - Integer validation failures
    - String validation issues

16. **Deserialization Issues**
    - Unsafe deserialization of untrusted data
    - Pickle-like vulnerabilities in custom serialization
    - Buffer overflows in deserialization code

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
- Pay special attention to memory management
- Consider both C and modern C++ (C++11/14/17/20) features
- Evaluate pointer arithmetic and boundary conditions carefully
- Don't flag issues that have proper validation/sanitization
- Consider defense-in-depth: multiple layers of protection may exist
- Remember that C/C++ has minimal memory safety guarantees"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation?
2. Are bounds properly checked before buffer operations?
3. Is the code path actually reachable with user input?
4. Are there other security controls in place (ASLR, stack canaries)?
5. Is the severity assessment accurate for C/C++ context?
6. Could this be a false positive due to missing context?
7. Are modern C++ features (smart pointers, RAII) preventing the issue?
8. Is memory properly managed throughout the lifecycle?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get C/C++ vulnerability categories."""
        return [
            "Buffer Overflow/Underflow",
            "Memory Management Issues",
            "Integer Overflow/Underflow",
            "Format String Vulnerabilities",
            "Command Injection",
            "Path Traversal",
            "SQL Injection",
            "Race Conditions",
            "Type Confusion",
            "Cryptographic Issues",
            "Pointer Issues",
            "Resource Management",
            "Concurrency Issues",
            "C++ Specific Issues",
            "Input Validation",
            "Deserialization Issues",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common C/C++ frameworks and libraries."""
        return [
            "STL",
            "Boost",
            "Qt",
            "OpenSSL",
            "MySQL C API",
            "PostgreSQL libpq",
            "cURL",
            "libc",
            "glibc",
            "POSIX",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get C/C++-specific chunking strategy."""
        return {
            "chunk_size": 60,  # C/C++ functions can be moderately sized
            "chunk_overlap": 15,  # Higher overlap for context (header files, etc.)
        }