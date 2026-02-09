"""Prompt-related domain models."""

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class PromptTemplate:
    """
    Template for AI prompts.

    These prompts instruct the AI on how to analyze code for security issues.
    NO pattern matching - pure AI reasoning.
    """
    system_prompt: str
    user_prompt_template: str
    language: str
    analysis_type: str  # review, validation, summary, etc.

    def format(self, **kwargs) -> str:
        """Format the user prompt with provided variables."""
        return self.user_prompt_template.format(**kwargs)


@dataclass
class PromptContext:
    """
    Context assembled for AI analysis.

    Contains all information the AI needs to perform security analysis,
    including code, structural metadata, and related code from RAG.
    """
    file_path: str
    code_snippet: str
    language: str
    structural_metadata: Optional[Dict[str, Any]] = None
    related_code: Optional[str] = None
    related_docs: Optional[str] = None
    original_file: Optional[str] = None
    analysis_type: str = "review"

    def to_prompt_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for prompt formatting."""
        context = {
            "file_path": self.file_path,
            "code_snippet": self.code_snippet,
            "language": self.language,
            "analysis_type": self.analysis_type,
        }

        if self.structural_metadata:
            context["structural_metadata"] = self.structural_metadata

        if self.related_code:
            context["related_code"] = self.related_code

        if self.related_docs:
            context["related_docs"] = self.related_docs

        if self.original_file:
            context["original_file"] = self.original_file

        return context

    def format_for_ai(self) -> str:
        """
        Format context into a comprehensive prompt for AI.

        The AI uses this context to understand the code deeply
        and identify security vulnerabilities through reasoning,
        NOT through pattern matching.
        """
        # For enrichment requests, the code_snippet is the pre-formatted prompt
        if self.analysis_type == "enrichment":
            return self.code_snippet

        # Add line numbers to code snippet for AI to reference
        numbered_code = self._add_line_numbers(self.code_snippet)

        parts = [
            f"FILE: {self.file_path}",
            f"LANGUAGE: {self.language}",
            f"ANALYSIS TYPE: {self.analysis_type}",
            "",
            "CODE (with line numbers):",
            numbered_code,
        ]

        if self.original_file:
            parts.extend([
                "",
                "ORIGINAL FILE (before changes):",
                self.original_file,
            ])

        if self.structural_metadata:
            parts.extend([
                "",
                "STRUCTURAL CONTEXT:",
                f"- Functions: {len(self.structural_metadata.get('functions', []))}",
                f"- Classes: {len(self.structural_metadata.get('classes', []))}",
                f"- Imports: {len(self.structural_metadata.get('imports', []))}",
                f"- Calls: {len(self.structural_metadata.get('calls', []))}",
            ])

            # Add control flow information
            if control_flow := self.structural_metadata.get('control_flow'):
                parts.extend([
                    "",
                    "CONTROL FLOW INFORMATION:",
                    f"{control_flow}",
                ])

            # Add data flow information
            if data_flows := self.structural_metadata.get('data_flows'):
                parts.extend([
                    "",
                    "DATA FLOW INFORMATION:",
                    f"{data_flows}",
                ])

        if self.related_code:
            parts.extend([
                "",
                "RELATED CODE (from semantic search):",
                self.related_code,
            ])

        if self.related_docs:
            parts.extend([
                "",
                "RELATED DOCUMENTATION (from semantic search):",
                self.related_docs,
            ])

        return "\n".join(parts)

    def _add_line_numbers(self, code: str) -> str:
        """
        Add line numbers to code for AI to reference.

        This allows the AI to provide accurate line_start and line_end
        in its findings.

        Args:
            code: Code snippet

        Returns:
            Code with line numbers prepended to each line
        """
        lines = code.splitlines()
        numbered_lines = []
        for i, line in enumerate(lines, start=1):
            numbered_lines.append(f"{i:4d} | {line}")
        return "\n".join(numbered_lines)