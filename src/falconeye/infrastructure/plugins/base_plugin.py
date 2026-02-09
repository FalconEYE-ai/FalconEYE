"""Base plugin interface for language-specific analysis."""

from abc import ABC, abstractmethod
from typing import Dict, List


class LanguagePlugin(ABC):
    """
    Base class for language plugins.

    IMPORTANT: Plugins provide context and prompts for AI analysis,
    NOT pattern-based vulnerability detection rules.

    Each plugin provides:
    - Language-specific system prompts for AI
    - Vulnerability categories for context
    - Validation prompts to reduce false positives
    - Optional chunking strategies
    """

    @property
    @abstractmethod
    def language_name(self) -> str:
        """
        Language name.

        Returns:
            Language name (e.g., "python", "javascript")
        """
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """
        File extensions for this language.

        Returns:
            List of file extensions (e.g., [".py", ".pyw"])
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        Get language-specific system prompt for security analysis.

        This prompt guides the AI to:
        - Understand language semantics
        - Consider common vulnerability patterns (for context, not matching)
        - Perform deep reasoning about code behavior
        - Output findings in structured format

        Returns:
            System prompt string
        """
        pass

    @abstractmethod
    def get_validation_prompt(self) -> str:
        """
        Get prompt for validating findings to reduce false positives.

        The AI uses this prompt to review findings and determine
        if they are genuine vulnerabilities or false positives.

        Returns:
            Validation prompt string
        """
        pass

    @abstractmethod
    def get_vulnerability_categories(self) -> List[str]:
        """
        Get common vulnerability categories for this language.

        These categories provide context for the AI, NOT matching rules.
        They help the AI understand what types of issues to look for.

        Returns:
            List of vulnerability category names
        """
        pass

    def get_chunking_strategy(self) -> Dict[str, int]:
        """
        Get language-specific chunking parameters.

        Can be overridden for languages that need different chunking.

        Returns:
            Dictionary with 'chunk_size' and 'chunk_overlap' keys
        """
        return {
            "chunk_size": 50,
            "chunk_overlap": 10,
        }

    def get_framework_context(self) -> List[str]:
        """
        Get common frameworks/libraries for this language.

        This provides additional context for the AI about common
        security issues in popular frameworks.

        Returns:
            List of framework names
        """
        return []

    @staticmethod
    def get_severity_guidelines() -> str:
        """
        Get severity reasoning guidelines.

        These guidelines teach the LLM to reason about severity based on
        real-world exploitability and impact, not rigid category mappings.

        Returns:
            Severity reasoning guidance string
        """
        return """

SEVERITY RATING - THINK BEFORE YOU RATE:

Before assigning a severity, reason through these questions for EACH finding:

1. EXPLOITABILITY: How easy is it to exploit in a real attack?
   - Can an unauthenticated remote attacker trigger it directly?
   - Does it require special access, credentials, or local presence?
   - Does it need user interaction (clicking a link, opening a file)?
   - How complex is the attack chain?

2. IMPACT: What is the worst realistic outcome if exploited?
   - Does it give the attacker code execution on the server?
   - Does it expose the entire database or sensitive user data?
   - Does it only degrade security posture without direct compromise?
   - Is the impact theoretical or demonstrated by the code?

3. CONTEXT: What does the surrounding code tell you?
   - Are there mitigating controls elsewhere?
   - Is the vulnerable code in a hot path or a rarely-used feature?
   - Is user input actually reaching the vulnerable sink?

Then assign severity honestly:
- CRITICAL: Attacker can directly achieve RCE, full DB access, or complete auth bypass with minimal effort
- HIGH: Attacker can read/write arbitrary files, access internal services, or escalate privileges
- MEDIUM: Issue weakens security but requires chaining with other flaws or has limited direct impact
- LOW: Minor issue, hard to exploit, minimal real-world consequence
- INFO: Observation or recommendation, not an exploitable vulnerability

Common mistakes to AVOID:
- Using a weak hash (MD5/SHA1) or cipher (DES/RC4) is NOT critical - it weakens crypto but doesn't give direct access
- Weak TLS config is NOT critical - it enables potential MITM but requires network position
- A weak PRNG is NOT critical - it makes values predictable but rarely gives direct system access
- Integer overflow is NOT critical unless you can demonstrate it leads to memory corruption or auth bypass
- Not every finding is critical. A realistic scan should have a MIX of severities."""

    def __repr__(self) -> str:
        """String representation."""
        return f"<{self.__class__.__name__}: {self.language_name}>"