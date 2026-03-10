"""Security analyzer domain service."""

from typing import List, Optional, Callable
import json
import re
import time
from ..models.security import SecurityFinding, Severity, FindingConfidence
from ..models.prompt import PromptContext
from .llm_service import LLMService
from ..exceptions import AnalysisError, InvalidSecurityFindingError
from ...infrastructure.logging import FalconEyeLogger


class SecurityAnalyzer:
    """
    Domain service for security analysis.

    This service orchestrates AI-powered security analysis.
    CRITICAL: ALL analysis is done by AI, NO pattern matching.
    """

    def __init__(self, llm_service: LLMService):
        """
        Initialize security analyzer.

        Args:
            llm_service: LLM service for AI analysis
        """
        self.llm_service = llm_service
        self.logger = FalconEyeLogger.get_instance()

    async def analyze_code(
        self,
        context: PromptContext,
        system_prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        finding_callback: Optional[Callable[[SecurityFinding], None]] = None,
    ) -> List[SecurityFinding]:
        """
        Analyze code for security vulnerabilities using AI.

        This method sends code to the LLM and parses security findings.
        NO pattern matching - pure AI reasoning.

        Args:
            context: Code context with metadata
            system_prompt: Instructions for the AI
            stream_callback: Optional callback to receive streaming tokens

        Returns:
            List of security findings identified by AI

        Raises:
            AnalysisError: If AI analysis fails
        """
        start_time = time.time()

        # Log start
        self.logger.info(
            "Starting security analysis",
            extra={
                "file_path": context.file_path,
                "language": context.language,
                "code_size": len(context.code_snippet),
            }
        )

        try:
            # Accumulate response for incremental parsing
            accumulated_response = []
            parsed_findings = []
            parsed_findings_signatures = set()  # Track by signature to avoid duplicates
            
            # Create a wrapper callback that accumulates tokens and tries to parse findings incrementally
            def incremental_stream_callback(token: str):
                """Callback that accumulates tokens and parses findings as they appear."""
                accumulated_response.append(token)
                
                # Call the original stream callback if provided
                if stream_callback:
                    stream_callback(token)
                
                # Try to parse findings from accumulated response
                # Check when we see closing braces (complete objects) or periodically
                should_check = (
                    finding_callback and (
                        token.strip().endswith('}') or  # Likely end of an object
                        token.strip().endswith(']') or  # Likely end of an array
                        len(accumulated_response) % 5 == 0  # Or every 5 tokens
                    )
                )
                
                if should_check:
                    try:
                        # Get current accumulated text
                        current_text = ''.join(accumulated_response)
                        
                        # Try to extract and parse complete findings
                        incremental_findings = self._parse_findings_incremental(
                            current_text,
                            context.file_path,
                            already_parsed=parsed_findings
                        )
                        
                        # Call callback for new findings
                        for finding in incremental_findings:
                            # Use helper method for consistent signature generation
                            finding_sig = self._finding_signature(finding)
                            if finding_sig not in parsed_findings_signatures:
                                parsed_findings_signatures.add(finding_sig)
                                parsed_findings.append(finding)
                                finding_callback(finding)
                    except Exception as parse_error:
                        # If parsing fails, continue accumulating (not a complete finding yet)
                        # Don't log here as this is expected during incremental parsing
                        pass
            
            # Get AI analysis with incremental parsing callback
            raw_response = await self.llm_service.analyze_code_security(
                context=context,
                system_prompt=system_prompt,
                stream_callback=incremental_stream_callback if finding_callback else stream_callback,
            )

            # Parse AI response into findings (final parse to catch any missed findings)
            all_findings = self._parse_findings(raw_response, context.file_path)
            
            # Add any findings that weren't caught incrementally
            if finding_callback:
                for finding in all_findings:
                    # Use helper method for consistent signature generation
                    finding_sig = self._finding_signature(finding)
                    if finding_sig not in parsed_findings_signatures:
                        parsed_findings_signatures.add(finding_sig)
                        parsed_findings.append(finding)
                        finding_callback(finding)
                findings = parsed_findings
            else:
                findings = all_findings

            # Enrich incomplete findings via LLM (missing mitigation, snippet, etc.)
            findings = await self._enrich_incomplete_findings(findings, context)

            # Enhance findings with line numbers and context
            findings = self._enhance_findings_with_context(findings, context)

            # Calculate duration
            duration = time.time() - start_time

            # Group findings by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Log completion
            self.logger.info(
                "Security analysis completed",
                extra={
                    "file_path": context.file_path,
                    "findings_count": len(findings),
                    "severity_counts": severity_counts,
                    "duration_seconds": round(duration, 2),
                }
            )

            return findings

        except InvalidSecurityFindingError as e:
            duration = time.time() - start_time
            
            # Save problematic response for debugging
            debug_file = f"/tmp/falconeye_failed_response_{int(time.time())}.txt"
            try:
                with open(debug_file, 'w') as f:
                    f.write(f"File: {context.file_path}\n")
                    f.write(f"Error: {str(e)}\n")
                    f.write(f"\n{'='*80}\n")
                    f.write(f"AI Response:\n")
                    f.write(f"{'='*80}\n")
                    f.write(raw_response)
            except Exception as debug_error:
                self.logger.warning(
                    f"Could not save debug file: {debug_error}",
                    extra={"intended_path": debug_file}
                )
            
            self.logger.error(
                "Failed to parse AI response",
                extra={
                    "file_path": context.file_path,
                    "error": str(e),
                    "duration_seconds": round(duration, 2),
                    "debug_file": debug_file,
                    "hint": f"Check {debug_file} for the problematic AI response"
                },
                exc_info=True
            )
            self.logger.warning(
                f"Skipping file due to unparseable AI response. "
                f"Debug info saved to: {debug_file}"
            )
            # Return empty findings instead of crashing
            return []

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(
                "Security analysis failed",
                extra={
                    "file_path": context.file_path,
                    "error": str(e),
                    "duration_seconds": round(duration, 2),
                },
                exc_info=True
            )
            raise AnalysisError(f"AI analysis failed: {str(e)}") from e

    async def validate_findings(
        self,
        findings: List[SecurityFinding],
        context: PromptContext,
    ) -> List[SecurityFinding]:
        """
        Use AI to validate findings and filter false positives.

        The AI re-evaluates each finding to ensure it's a genuine issue.
        NO pattern-based filtering - AI makes all decisions.

        Args:
            findings: Initial findings to validate
            context: Original code context

        Returns:
            Validated findings (false positives removed by AI)
        """
        if not findings:
            return []

        # Prepare findings for AI validation
        findings_json = json.dumps([
            {
                "issue": f.issue,
                "reasoning": f.reasoning,
                "code_snippet": f.code_snippet,
                "severity": f.severity.value,
            }
            for f in findings
        ])

        # Ask AI to validate
        validated_response = await self.llm_service.validate_findings(
            code_snippet=context.code_snippet,
            findings=findings_json,
            context=context.format_for_ai(),
        )

        # Parse validated findings
        validated = self._parse_findings(validated_response, context.file_path)
        return validated

    def _parse_findings_incremental(
        self,
        partial_response: str,
        file_path: str,
        already_parsed: List[SecurityFinding],
    ) -> List[SecurityFinding]:
        """
        Parse findings incrementally from partial response.
        
        Tries to extract complete finding objects from the stream as they appear.
        Looks for complete JSON objects that represent findings, even if they're
        inside an incomplete parent structure.
        
        Args:
            partial_response: Partial JSON response from stream
            file_path: File being analyzed
            already_parsed: List of findings already parsed (to avoid duplicates)
            
        Returns:
            List of newly parsed findings
        """
        new_findings = []
        
        try:
            # Track positions we've already checked to avoid re-parsing
            checked_positions = set()
            
            # Find all complete JSON objects in the response
            # This handles objects that are complete even if parent structure isn't
            i = 0
            while i < len(partial_response):
                if partial_response[i] == '{':
                    # Found start of an object, try to find its end
                    brace_count = 0
                    start_idx = i
                    in_string = False
                    escape_next = False
                    
                    for j in range(i, len(partial_response)):
                        char = partial_response[j]
                        
                        if escape_next:
                            escape_next = False
                            continue
                        
                        if char == '\\':
                            escape_next = True
                            continue
                        
                        if char == '"' and not escape_next:
                            in_string = not in_string
                            continue
                        
                        if not in_string:
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    # Found complete object
                                    obj_str = partial_response[start_idx:j+1]
                                    
                                    # Skip if we've already checked this position
                                    if start_idx in checked_positions:
                                        i = j + 1
                                        break
                                    
                                    checked_positions.add(start_idx)
                                    
                                    # Try to parse as JSON
                                    try:
                                        obj = json.loads(obj_str)
                                        
                                        # Check if this is a finding object (has "issue" field)
                                        if "issue" in obj:
                                            finding = self._create_finding_from_dict(obj, file_path)
                                            if finding and not self._is_duplicate_finding(finding, already_parsed):
                                                new_findings.append(finding)

                                        # Also check if this is a wrapper object with "reviews" array
                                        elif "reviews" in obj and isinstance(obj.get("reviews"), list):
                                            for review in obj["reviews"]:
                                                finding = self._create_finding_from_dict(review, file_path)
                                                if finding and not self._is_duplicate_finding(finding, already_parsed):
                                                    new_findings.append(finding)
                                    except (json.JSONDecodeError, Exception):
                                        # Not valid JSON or not a finding, continue
                                        pass
                                    
                                    i = j + 1
                                    break
                    else:
                        # Didn't find closing brace, move on
                        i += 1
                else:
                    i += 1
            
            # Also try to parse complete arrays of findings
            try:
                # Look for patterns like [{"issue": ...}, {"issue": ...}]
                # Find arrays that might contain findings
                bracket_positions = []
                for i, char in enumerate(partial_response):
                    if char == '[':
                        bracket_positions.append(i)
                    elif char == ']' and bracket_positions:
                        start = bracket_positions.pop()
                        try:
                            array_str = partial_response[start:i+1]
                            array_data = json.loads(array_str)
                            if isinstance(array_data, list):
                                for item in array_data:
                                    if isinstance(item, dict) and "issue" in item:
                                        finding = self._create_finding_from_dict(item, file_path)
                                        if finding and not self._is_duplicate_finding(finding, already_parsed):
                                            new_findings.append(finding)
                        except (json.JSONDecodeError, Exception):
                            pass
            except Exception:
                pass
                
        except Exception:
            # If incremental parsing fails, return empty list (will parse at end)
            pass
        
        return new_findings
    
    def _finding_signature(self, finding: SecurityFinding) -> tuple:
        """
        Generate a unique signature for a finding to detect duplicates.

        Args:
            finding: SecurityFinding to generate signature for

        Returns:
            Tuple of (issue, file_path, severity_value) as signature
        """
        return (finding.issue, finding.file_path, finding.severity.value)

    def _is_duplicate_finding(
        self,
        finding: SecurityFinding,
        existing: List[SecurityFinding],
    ) -> bool:
        """
        Check if a finding already exists in the list.

        Args:
            finding: Finding to check
            existing: List of existing findings

        Returns:
            True if finding is a duplicate
        """
        finding_sig = self._finding_signature(finding)
        return any(
            self._finding_signature(f) == finding_sig
            for f in existing
        )

    def _create_finding_from_dict(self, data: dict, file_path: str) -> Optional[SecurityFinding]:
        """Create a SecurityFinding from a dictionary."""
        try:
            return SecurityFinding.create(
                issue=data.get("issue", "Unknown issue"),
                reasoning=data.get("reasoning", ""),
                mitigation=data.get("mitigation", "") or "",
                severity=self._parse_severity(data.get("severity", "medium")),
                confidence=self._parse_confidence(data.get("confidence", 0.7)),
                file_path=file_path,
                code_snippet=data.get("code_snippet", ""),
                line_start=data.get("line_start"),
                line_end=data.get("line_end"),
                cwe_id=data.get("cwe_id"),
                tags=data.get("tags", []),
            )
        except Exception:
            return None

    def _is_finding_incomplete(self, finding: SecurityFinding) -> bool:
        """Check if a finding has missing or generic fields that need LLM enrichment."""
        # Missing or generic mitigation
        if not finding.mitigation or self._is_generic_mitigation(finding.mitigation):
            return True
        # Short mitigation (likely not specific enough)
        if len(finding.mitigation.strip()) < 40:
            return True
        # Missing code snippet
        if not finding.code_snippet or finding.code_snippet in ("N/A", ""):
            return True
        # Missing or generic reasoning
        if not finding.reasoning or finding.reasoning == "No detailed description provided.":
            return True
        # Short reasoning (likely not specific enough)
        if len(finding.reasoning.strip()) < 60:
            return True
        # Missing line numbers
        if finding.line_start is None:
            return True
        return False

    async def _enrich_incomplete_findings(
        self,
        findings: List[SecurityFinding],
        context: PromptContext,
    ) -> List[SecurityFinding]:
        """
        Enrich findings via LLM: fill missing fields and validate severity ratings.

        All findings are sent for severity validation. Incomplete findings also
        get their missing fields (reasoning, mitigation, snippet, lines) filled.
        """
        if not findings:
            return findings

        # Send ALL findings for enrichment (severity validation + field completion)
        self.logger.info(
            f"Enriching {len(findings)} finding(s) via LLM (severity validation + field completion)",
            extra={
                "file_path": context.file_path,
                "total_findings": len(findings),
                "incomplete_count": sum(1 for f in findings if self._is_finding_incomplete(f)),
            }
        )

        findings_to_enrich = []
        for idx, f in enumerate(findings):
            is_incomplete = self._is_finding_incomplete(f)
            findings_to_enrich.append({
                "index": idx,
                "issue": f.issue,
                "severity": f.severity.value,
                "needs_field_enrichment": is_incomplete,
                "reasoning": f.reasoning if f.reasoning != "No detailed description provided." else "",
                "mitigation": f.mitigation if not self._is_generic_mitigation(f.mitigation) else "",
                "code_snippet": f.code_snippet if f.code_snippet not in ("N/A", "") else "",
                "line_start": f.line_start,
                "line_end": f.line_end,
            })

        enrichment_system_prompt = (
            "You are a security expert reviewing and enriching vulnerability findings.\n"
            "You are given the SOURCE CODE with line numbers and a list of findings.\n\n"
            "Each finding has a 'needs_field_enrichment' flag:\n"
            "- If TRUE: provide ALL fields below (reasoning, mitigation, code_snippet, lines, adjusted_severity)\n"
            "- If FALSE: the finding already has good fields, but you MUST still review the severity "
            "and provide adjusted_severity\n\n"
            "For EACH finding, provide:\n"
            "1. reasoning: Detailed description (2-3+ sentences) - what the vuln is, how to exploit it, what the impact is\n"
            "2. mitigation: Specific fix referencing actual function/variable names from the code\n"
            "3. code_snippet: The exact vulnerable lines from the source\n"
            "4. line_start / line_end: Exact line numbers from the source code\n"
            "5. adjusted_severity: Your assessed severity after reasoning about exploitability and impact\n"
            "6. severity_justification: Brief explanation of WHY you chose this severity level\n\n"
            "SEVERITY ASSESSMENT - reason through these for each finding:\n"
            "- Can a remote unauthenticated attacker exploit this directly? (if yes, likely critical/high)\n"
            "- Does exploitation give code execution or full data access? (if yes, critical)\n"
            "- Does it only weaken security posture without direct compromise? (if yes, medium or lower)\n"
            "- Does it require chaining with other flaws or special conditions? (lower the severity)\n"
            "- A realistic codebase has a MIX of severities - not everything is critical\n\n"
            "Respond ONLY with a JSON object:\n"
            '{"enriched": [\n'
            "  {\n"
            '    "index": <original index>,\n'
            '    "reasoning": "<detailed vulnerability description>",\n'
            '    "mitigation": "<specific actionable recommendation>",\n'
            '    "code_snippet": "<exact vulnerable lines from source>",\n'
            '    "line_start": <integer line number>,\n'
            '    "line_end": <integer line number>,\n'
            '    "adjusted_severity": "critical|high|medium|low|info",\n'
            '    "severity_justification": "<why this severity level>"\n'
            "  }\n"
            "]}\n\n"
            "CRITICAL RULES:\n"
            "- line_start and line_end are MANDATORY integers\n"
            "- code_snippet must be the EXACT lines from the source (max 10 lines)\n"
            "- mitigation must reference specific identifiers from THIS code\n"
            "- adjusted_severity is MANDATORY for every finding - think carefully about real-world impact"
        )

        # Add line numbers to the source code so the LLM can reference them
        numbered_lines = []
        for i, line in enumerate(context.code_snippet.splitlines(), start=1):
            numbered_lines.append(f"{i:4d} | {line}")
        numbered_source = "\n".join(numbered_lines)

        findings_json = json.dumps(findings_to_enrich, indent=2)

        enrichment_user_prompt = (
            f"SOURCE CODE ({context.file_path}) with line numbers:\n"
            f"{numbered_source}\n\n"
            f"FINDINGS TO REVIEW AND ENRICH:\n{findings_json}\n\n"
            "For EVERY finding:\n"
            "1. Read the actual vulnerable code in context above\n"
            "2. Reason about how exploitable this really is - who can trigger it, what access is needed, "
            "what is the real impact\n"
            "3. Assign adjusted_severity based on your reasoning (MANDATORY for ALL findings)\n"
            "4. If needs_field_enrichment is true, also fill in reasoning, mitigation, code_snippet, "
            "line_start, line_end\n"
            "5. Provide severity_justification explaining your severity choice"
        )

        enrichment_context = PromptContext(
            file_path=context.file_path,
            code_snippet=enrichment_user_prompt,
            language=context.language,
            analysis_type="enrichment",
        )

        try:
            raw_response = await self.llm_service.analyze_code_security(
                context=enrichment_context,
                system_prompt=enrichment_system_prompt,
            )

            enrichment_data = self._extract_json(raw_response)
            enriched_list = []
            if isinstance(enrichment_data, dict):
                enriched_list = enrichment_data.get("enriched", [])
            elif isinstance(enrichment_data, list):
                enriched_list = enrichment_data

            enrichment_map = {}
            for item in enriched_list:
                idx = item.get("index")
                if idx is not None:
                    enrichment_map[idx] = item

            result = []
            for i, finding in enumerate(findings):
                if i in enrichment_map:
                    enriched = enrichment_map[i]
                    # Use adjusted severity from enrichment if provided
                    severity = finding.severity
                    adjusted = enriched.get("adjusted_severity")
                    if adjusted:
                        severity = self._parse_severity(adjusted)
                    result.append(SecurityFinding.create(
                        issue=finding.issue,
                        reasoning=enriched.get("reasoning") or finding.reasoning,
                        mitigation=enriched.get("mitigation") or finding.mitigation,
                        severity=severity,
                        confidence=finding.confidence,
                        file_path=finding.file_path,
                        code_snippet=self._pick_best_snippet(
                            finding.code_snippet, enriched.get("code_snippet", "")
                        ),
                        line_start=enriched.get("line_start") or finding.line_start,
                        line_end=enriched.get("line_end") or finding.line_end,
                        cwe_id=finding.cwe_id,
                        tags=finding.tags,
                    ))
                else:
                    result.append(finding)

            # Log severity adjustments
            severity_changes = []
            for i, finding in enumerate(findings):
                if i in enrichment_map:
                    adjusted = enrichment_map[i].get("adjusted_severity")
                    if adjusted and self._parse_severity(adjusted) != finding.severity:
                        severity_changes.append(
                            f"  {finding.issue}: {finding.severity.value} -> {adjusted}"
                        )
            if severity_changes:
                self.logger.info(
                    f"Severity adjustments ({len(severity_changes)}):\n"
                    + "\n".join(severity_changes),
                    extra={"file_path": context.file_path}
                )

            self.logger.info(
                f"Successfully enriched {len(enrichment_map)} finding(s)",
                extra={"file_path": context.file_path}
            )
            return result

        except Exception as e:
            self.logger.warning(
                f"Finding enrichment failed, using original findings: {e}",
                extra={"file_path": context.file_path, "error": str(e)}
            )
            return findings

    def _is_generic_mitigation(self, mitigation: str) -> bool:
        """Check if a mitigation string is generic/unhelpful."""
        if not mitigation:
            return True
        lower = mitigation.strip().lower()
        if lower in ("", "n/a", "none"):
            return True
        generic_starts = (
            "review and remediate",
            "review this finding",
            "fix the vulnerability",
            "fix this issue",
            "fix this vulnerability",
            "remediate this",
            "address this issue",
            "ensure proper",
            "implement proper",
            "add proper",
            "use proper",
        )
        for prefix in generic_starts:
            if lower.startswith(prefix):
                return True
        return False

    def _pick_best_snippet(self, original: str, enriched: str) -> str:
        """Pick the better code snippet between original and enriched."""
        orig_valid = original and original not in ("N/A", "")
        enr_valid = enriched and enriched not in ("N/A", "")
        if enr_valid:
            return enriched
        if orig_valid:
            return original
        return "N/A"

    def _parse_findings(
        self,
        ai_response: str,
        file_path: str,
    ) -> List[SecurityFinding]:
        """
        Parse AI response into SecurityFinding objects.

        The AI returns findings in JSON format. This method just parses them.
        NO analysis or pattern matching happens here.

        Args:
            ai_response: Raw AI response (JSON)
            file_path: File being analyzed

        Returns:
            List of SecurityFinding objects

        Raises:
            InvalidSecurityFindingError: If AI response is malformed
        """
        try:
            # Try to extract JSON from response
            data = self._extract_json(ai_response)

            if not data:
                # AI found no issues
                return []

            # Handle different response formats
            # Check if data itself is a list (direct array response)
            if isinstance(data, list):
                reviews = data
            else:
                # Data is an object, extract reviews array
                reviews = data.get("reviews", [])
                if not reviews:
                    # Maybe the object itself is a single review
                    if "issue" in data:
                        reviews = [data]

            findings = []
            dropped_findings = []
            for review in reviews:
                # Use the shared _create_finding_from_dict method
                finding = self._create_finding_from_dict(review, file_path)
                if finding:
                    findings.append(finding)
                else:
                    # Track dropped findings for later reporting
                    dropped_findings.append({
                        "error": "Failed to create finding from dict",
                        "raw_data": review
                    })
                    self.logger.warning(
                        "Skipping malformed finding",
                        extra={
                            "file_path": file_path,
                            "error": "Failed to create SecurityFinding",
                            "review_data": review,
                        }
                    )

            # Report summary of dropped findings if any
            if dropped_findings:
                self.logger.warning(
                    f"Dropped {len(dropped_findings)} malformed finding(s) during parsing",
                    extra={
                        "file_path": file_path,
                        "dropped_count": len(dropped_findings),
                        "parsed_count": len(findings),
                        "total_attempted": len(reviews),
                    }
                )

            return findings

        except json.JSONDecodeError as e:
            # Save problematic response to debug file
            import tempfile
            import time

            debug_file = tempfile.gettempdir() + f"/falconeye_failed_response_{int(time.time())}.txt"
            debug_file_saved = False
            try:
                with open(debug_file, 'w') as f:
                    f.write(f"File: {file_path}\n")
                    f.write(f"Error: {str(e)}\n")
                    f.write(f"Response length: {len(ai_response) if ai_response else 0}\n")
                    f.write("="*80 + "\n")
                    f.write(ai_response or "(empty response)")
                debug_file_saved = True
                self.logger.error(
                    f"Failed to parse AI response. Debug file saved to: {debug_file}",
                    extra={
                        "file_path": file_path,
                        "json_error": str(e),
                        "response_length": len(ai_response) if ai_response else 0,
                        "debug_file": debug_file,
                    }
                )
            except Exception as write_error:
                self.logger.error(
                    f"Could not save debug file: {write_error}",
                    extra={"intended_path": debug_file, "original_error": str(e)}
                )

            raise InvalidSecurityFindingError(
                f"AI response is not valid JSON: {str(e)}. "
                f"Response length: {len(ai_response) if ai_response else 0}. "
                f"Debug file: {debug_file if debug_file_saved else 'N/A (failed to save)'}"
            ) from e
        except Exception as e:
            raise InvalidSecurityFindingError(
                f"Failed to parse AI findings: {str(e)}"
            ) from e

    def _extract_json(self, text: str) -> dict:
        """
        Extract JSON from AI response.

        AI might wrap JSON in markdown code blocks or include explanatory text.
        
        Args:
            text: Raw AI response text
            
        Returns:
            Parsed JSON object
            
        Raises:
            json.JSONDecodeError: If no valid JSON found
        """
        import re
        
        # Handle empty or None responses
        if not text or not text.strip():
            self.logger.warning("Received empty AI response")
            return {"reviews": []}

        # Strip <think>...</think> reasoning blocks (Qwen3, DeepSeek-R1, etc.)
        # These appear before the actual JSON and can contain ```json markers that
        # would fool the extractor into grabbing the wrong block.
        if "<think>" in text and "</think>" in text:
            think_start = text.find("<think>")
            think_end = text.find("</think>") + len("</think>")
            text = text[:think_start] + text[think_end:]
            text = text.strip()

        # Try to find JSON in markdown code block
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("""`""", start)
            if end == -1:
                end = len(text)
            json_text = text[start:end].strip()
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                # Try to fix common JSON issues; if still broken fall through to repair
                try:
                    fixed = self._fix_json(json_text)
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass  # Fall through to _repair_truncated_json / _extract_partial_findings

        # Try to extract JSON object/array from text FIRST
        # (before checking code blocks, since ``` might be inside JSON strings)
        # Find the first { or [ and try to parse from there
        for start_char in ['{', '[']:
            start_idx = text.find(start_char)
            if start_idx == -1:
                continue
            
            # Try to find the matching closing bracket
            json_text = text[start_idx:]
            
            # Remove trailing non-JSON characters
            while json_text and json_text[-1] not in ('}', ']'):
                json_text = json_text[:-1].strip()
            
            if not json_text:
                continue
                
            try:
                # Try parsing directly first
                return json.loads(json_text)
            except json.JSONDecodeError:
                # Try fixing common issues
                try:
                    fixed_json = self._fix_json(json_text)
                    return json.loads(fixed_json)
                except json.JSONDecodeError:
                    # This attempt failed, try next start character
                    continue

        # Try to find JSON in code block as last resort
        # (only if JSON wasn't found at the start of the text)
        if "```" in text:
            start = text.find("```") + 3
            # Skip language identifier if present (e.g., ```json)
            newline_after_start = text.find('\n', start)
            if newline_after_start != -1 and newline_after_start - start < 20:
                start = newline_after_start + 1
            
            end = text.find("```", start)
            if end == -1:
                end = len(text)
            json_text = text[start:end].strip()
            
            if json_text:
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    try:
                        fixed = self._fix_json(json_text)
                        return json.loads(fixed)
                    except json.JSONDecodeError:
                        pass  # Fall through to repair/partial extraction

        # Try parsing the whole response as last resort
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            try:
                json_text = self._fix_json(text)
                return json.loads(json_text)
            except json.JSONDecodeError:
                pass

        # Last resort: try to repair truncated JSON (model hit max_tokens)
        repaired = self._repair_truncated_json(text)
        if repaired:
            try:
                return json.loads(repaired, strict=False)
            except json.JSONDecodeError:
                try:
                    repaired = self._fix_json(repaired)
                    return json.loads(repaired, strict=False)
                except json.JSONDecodeError:
                    pass

        # Final fallback: extract individual finding objects from partial response
        findings = self._extract_partial_findings(text)
        if findings:
            return {"reviews": findings}

        raise json.JSONDecodeError("No valid JSON found in response", text, 0)

    def _fix_json(self, json_text: str) -> str:
        """
        Attempt to fix common JSON formatting issues.
        
        Args:
            json_text: Potentially malformed JSON string
            
        Returns:
            Fixed JSON string
        """
        import re
        
        # Fix invalid escape sequences (e.g., \U, \u followed by invalid hex, etc.)
        # Replace invalid escapes with escaped backslashes
        def fix_escape_sequences(text: str) -> str:
            """Fix invalid escape sequences in JSON strings."""
            result = []
            i = 0
            in_string = False
            escape_count = 0
            
            while i < len(text):
                char = text[i]
                
                # Track if we're inside a string (handle escaped quotes properly)
                if char == '"':
                    # Count preceding backslashes
                    num_backslashes = 0
                    j = i - 1
                    while j >= 0 and text[j] == '\\':
                        num_backslashes += 1
                        j -= 1
                    
                    # If even number of backslashes (or zero), this quote is not escaped
                    if num_backslashes % 2 == 0:
                        in_string = not in_string
                    
                    result.append(char)
                    i += 1
                    continue
                
                # Only process escapes inside strings
                if in_string and char == '\\' and i + 1 < len(text):
                    next_char = text[i + 1]
                    
                    # Valid JSON escape sequences: " \ / b f n r t u
                    if next_char in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't'):
                        result.append(char)
                        i += 1
                    elif next_char == 'u':
                        # Check if it's a valid unicode escape (4 hex digits)
                        if i + 5 < len(text) and all(c in '0123456789abcdefABCDEF' for c in text[i+2:i+6]):
                            result.append(char)
                            i += 1
                        else:
                            # Invalid unicode escape, escape the backslash
                            result.append('\\\\')
                            i += 1
                    else:
                        # Invalid escape sequence, escape the backslash
                        result.append('\\\\')
                        i += 1
                else:
                    result.append(char)
                    i += 1
            
            return ''.join(result)
        
        json_text = fix_escape_sequences(json_text)
        
        # Additional aggressive fix: replace common problematic patterns
        # Fix Windows-style paths (C:\Users\...) 
        json_text = re.sub(r'([A-Z]):\\', r'\1:\\\\', json_text)
        
        # Fix any remaining single backslashes before common characters
        # This is aggressive but necessary for AI-generated content
        json_text = re.sub(r'\\([^"\\/bfnrtu])', r'\\\\\\1', json_text)
        
        # Fix unescaped quotes within strings (common AI error)
        # This is a more aggressive approach that looks for patterns like ["key"]
        def fix_unescaped_quotes(text: str) -> str:
            """Fix unescaped quotes within JSON string values."""
            import re
            
            # Fix quotes in patterns like $var["key"] or $_GET["cmd"]
            # Use a callback to properly escape
            def escape_array_access(match):
                prefix = match.group(1)  # $var[
                key = match.group(2)      # the key
                return prefix + '\\"' + key + '\\"]'
            
            text = re.sub(r'(\$[\w_]+\[)"([^"]+)"\]', escape_array_access, text)
            
            # Also handle single quotes
            def escape_array_access_single(match):
                prefix = match.group(1)
                key = match.group(2)
                return prefix + "\\'" + key + "\\']"
            
            text = re.sub(r"(\$[\w_]+\[)'([^']+)'\]", escape_array_access_single, text)
            
            return text
        
        json_text = fix_unescaped_quotes(json_text)

        def fix_inner_quotes(text: str) -> str:
            """Escape quotes embedded inside JSON string values."""
            result = []
            i = 0
            in_string = False

            while i < len(text):
                ch = text[i]

                if ch == '\\' and in_string and i + 1 < len(text):
                    result.append(ch)
                    result.append(text[i + 1])
                    i += 2
                    continue

                if ch == '"':
                    if not in_string:
                        in_string = True
                        result.append(ch)
                    else:
                        rest = text[i + 1:].lstrip()
                        if not rest or rest[0] in (':', '}', ']'):
                            in_string = False
                            result.append(ch)
                        elif rest[0] == ',':
                            after_comma = rest[1:].lstrip()
                            if (not after_comma
                                    or after_comma[0] == '"'
                                    or after_comma[0] in ('}', ']')
                                    or after_comma[0].isdigit()):
                                in_string = False
                                result.append(ch)
                            else:
                                result.append('\\"')
                        else:
                            result.append('\\"')
                    i += 1
                else:
                    result.append(ch)
                    i += 1

            return ''.join(result)

        json_text = fix_inner_quotes(json_text)

        # Remove trailing commas before closing braces/brackets
        json_text = re.sub(r',\s*([}\]])', r'\1', json_text)
        
        # Remove any trailing content after final closing brace/bracket
        json_text = json_text.strip()
        if json_text.startswith('{'):
            # Find the last closing brace
            last_brace = json_text.rfind('}')
            if last_brace != -1:
                json_text = json_text[:last_brace + 1]
        elif json_text.startswith('['):
            # Find the last closing bracket
            last_bracket = json_text.rfind(']')
            if last_bracket != -1:
                json_text = json_text[:last_bracket + 1]
        
        return json_text

    def _repair_truncated_json(self, text: str) -> Optional[str]:
        """Attempt to repair JSON that was truncated by max_tokens limit."""
        start_idx = -1
        for ch in ['{', '[']:
            idx = text.find(ch)
            if idx != -1 and (start_idx == -1 or idx < start_idx):
                start_idx = idx

        if start_idx == -1:
            return None

        json_text = text[start_idx:]

        last_complete = -1
        brace_depth = 0
        in_string = False
        escape_next = False

        for i, ch in enumerate(json_text):
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                brace_depth += 1
            elif ch == '}':
                brace_depth -= 1
                if brace_depth >= 1:
                    last_complete = i

        if last_complete == -1:
            return None

        truncated = json_text[:last_complete + 1]

        open_brackets = 0
        open_braces = 0
        in_string = False
        escape_next = False
        for ch in truncated:
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                open_braces += 1
            elif ch == '}':
                open_braces -= 1
            elif ch == '[':
                open_brackets += 1
            elif ch == ']':
                open_brackets -= 1

        result = truncated.rstrip().rstrip(',')
        result += ']' * open_brackets
        result += '}' * open_braces
        return result

    def _extract_partial_findings(self, text: str) -> list:
        """Extract finding data from a truncated response using multiple strategies."""
        findings = []

        i = 0
        while i < len(text):
            if text[i] == '{':
                brace_count = 0
                in_string = False
                escape_next = False

                for j in range(i, len(text)):
                    ch = text[j]
                    if escape_next:
                        escape_next = False
                        continue
                    if ch == '\\' and in_string:
                        escape_next = True
                        continue
                    if ch == '"' and not escape_next:
                        in_string = not in_string
                        continue
                    if not in_string:
                        if ch == '{':
                            brace_count += 1
                        elif ch == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                obj_str = text[i:j + 1]
                                try:
                                    obj = json.loads(obj_str, strict=False)
                                    if isinstance(obj, dict) and "issue" in obj:
                                        findings.append(obj)
                                except (json.JSONDecodeError, Exception):
                                    try:
                                        fixed = self._fix_json(obj_str)
                                        obj = json.loads(fixed, strict=False)
                                        if isinstance(obj, dict) and "issue" in obj:
                                            findings.append(obj)
                                    except (json.JSONDecodeError, Exception):
                                        pass
                                i = j + 1
                                break
                else:
                    i += 1
            else:
                i += 1

        if not findings:
            findings = self._extract_findings_by_regex(text)

        return findings

    def _extract_findings_by_regex(self, text: str) -> list:
        """Extract finding fields using regex from truncated JSON."""
        findings = []

        issue_matches = list(re.finditer(
            r'"issue"\s*:\s*"((?:[^"\\]|\\.)*)"', text
        ))

        if not issue_matches:
            return findings

        for idx, issue_match in enumerate(issue_matches):
            finding = {"issue": issue_match.group(1)}

            start = issue_match.start()
            if idx + 1 < len(issue_matches):
                end = issue_matches[idx + 1].start()
            else:
                end = len(text)

            region = text[start:end]

            for field in ("reasoning", "mitigation", "severity", "code_snippet"):
                match = re.search(
                    rf'"{field}"\s*:\s*"((?:[^"\\]|\\.)*)"', region
                )
                if match:
                    finding[field] = match.group(1)

            conf_match = re.search(
                r'"confidence"\s*:\s*([0-9.]+)', region
            )
            if conf_match:
                try:
                    finding["confidence"] = float(conf_match.group(1))
                except ValueError:
                    pass

            if "confidence" not in finding:
                conf_str_match = re.search(
                    r'"confidence"\s*:\s*"((?:[^"\\]|\\.)*)"', region
                )
                if conf_str_match:
                    finding["confidence"] = conf_str_match.group(1)

            for line_field in ("line_start", "line_end"):
                match = re.search(
                    rf'"{line_field}"\s*:\s*(\d+)', region
                )
                if match:
                    finding[line_field] = int(match.group(1))

            findings.append(finding)

        return findings

    def _enhance_findings_with_context(
        self,
        findings: List[SecurityFinding],
        context: PromptContext,
    ) -> List[SecurityFinding]:
        """
        Enhance findings with accurate line numbers and expanded code context.
        
        Args:
            findings: List of findings to enhance
            context: Original code context
            
        Returns:
            Enhanced findings with line numbers and context
        """
        from pathlib import Path
        
        enhanced_findings = []
        
        # Read the full file content
        try:
            file_path = Path(context.file_path)
            if not file_path.exists():
                return findings
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_lines = f.readlines()
        except Exception as e:
            self.logger.warning(
                f"Could not read file for context enhancement: {e}",
                extra={"file_path": context.file_path}
            )
            return findings
        
        for finding in findings:
            line_start = None
            line_end = None

            # Strategy 1: Try to find the code snippet in the file
            if finding.code_snippet and finding.code_snippet not in ("N/A", ""):
                line_start, line_end = self._find_snippet_location(
                    finding.code_snippet,
                    file_lines
                )

            # Strategy 2: Use line numbers provided by the AI
            if line_start is None and finding.line_start:
                line_start = finding.line_start
                line_end = finding.line_end or finding.line_start

            # Strategy 3: Search for identifiers in issue text, reasoning, and code_snippet
            if line_start is None:
                line_start, line_end = self._find_location_from_issue(
                    finding.issue,
                    finding.reasoning,
                    file_lines,
                    code_snippet=finding.code_snippet,
                )

            # If we found the location, expand the context
            if line_start is not None:
                context_snippet = self._extract_context_snippet(
                    file_lines,
                    line_start,
                    line_end or line_start,
                    context_lines=4
                )
                
                # Create enhanced finding
                enhanced_finding = SecurityFinding.create(
                    issue=finding.issue,
                    reasoning=finding.reasoning,
                    mitigation=finding.mitigation,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    file_path=finding.file_path,
                    code_snippet=context_snippet,
                    line_start=line_start,
                    line_end=line_end or line_start,
                    cwe_id=finding.cwe_id,
                    tags=finding.tags,
                )
                enhanced_findings.append(enhanced_finding)
            else:
                # Keep original finding if we couldn't locate it
                enhanced_findings.append(finding)
        
        return enhanced_findings

    def _find_snippet_location(
        self,
        snippet: str,
        file_lines: List[str],
    ) -> tuple[int | None, int | None]:
        """
        Find the line numbers where a code snippet appears in the file.
        
        Args:
            snippet: Code snippet to find
            file_lines: Lines of the file
            
        Returns:
            Tuple of (line_start, line_end) or (None, None) if not found
        """
        if not snippet or not file_lines:
            return None, None
        
        # Clean the snippet (remove line numbers if present, trim whitespace)
        snippet_lines = []
        for line in snippet.strip().splitlines():
            # Remove line numbers like "  123 | code"
            cleaned = line.strip()
            if '|' in cleaned and cleaned.split('|')[0].strip().isdigit():
                cleaned = '|'.join(cleaned.split('|')[1:]).strip()
            snippet_lines.append(cleaned)
        
        if not snippet_lines:
            return None, None
        
        # Search for the snippet in the file
        for i in range(len(file_lines)):
            # Try to match starting from this line
            match = True
            for j, snippet_line in enumerate(snippet_lines):
                if i + j >= len(file_lines):
                    match = False
                    break
                
                file_line = file_lines[i + j].strip()
                if snippet_line and snippet_line not in file_line:
                    match = False
                    break
            
            if match:
                # Found it! Return 1-indexed line numbers
                return i + 1, i + len(snippet_lines)
        
        return None, None

    def _extract_identifier_candidates(
        self,
        issue: str,
        reasoning: str,
        code_snippet: str = "",
    ) -> List[str]:
        """Extract identifier candidates from finding text for source file search."""
        skip_words = {
            "the", "and", "that", "this", "from", "with", "for", "not",
            "can", "could", "should", "would", "may", "might", "has",
            "have", "are", "was", "were", "been", "being", "use", "used",
            "using", "code", "function", "variable", "value", "data",
            "file", "line", "return", "void", "int", "char", "bool",
            "true", "false", "null", "NULL", "define", "include",
            "struct", "enum", "typedef", "static", "const", "unsigned",
            "signed", "else", "while", "break", "continue", "switch",
            "case", "default", "sizeof", "Potential", "security",
            "vulnerability", "due", "hardcoded", "configuration",
        }

        combined_text = f"{issue} {reasoning}"
        candidates = []
        seen = set()

        def add(name):
            if name not in seen and name not in skip_words and len(name) >= 3:
                seen.add(name)
                candidates.append(name)

        for m in re.findall(r'`(\w+)`', combined_text):
            add(m)

        for m in re.findall(r'\b(\w{3,})\s*\(', combined_text):
            add(m)

        if code_snippet and code_snippet not in ("N/A", ""):
            for m in re.findall(r'\b([A-Z][A-Z0-9_]{2,})\b', code_snippet):
                add(m)
            for m in re.findall(r'\b([a-z_]\w{3,})\s*\(', code_snippet):
                add(m)
            for m in re.findall(r'\b([a-z_]\w{3,})\b', code_snippet):
                add(m)

        for m in re.findall(r'\b([A-Z][A-Z0-9_]{2,})\b', combined_text):
            add(m)

        for m in re.findall(r'\b([a-z_]\w*_\w+)\b', combined_text):
            if len(m) >= 4:
                add(m)

        return candidates

    def _find_location_from_issue(
        self,
        issue: str,
        reasoning: str,
        file_lines: List[str],
        code_snippet: str = "",
    ) -> tuple[int | None, int | None]:
        """Find code location by extracting identifiers from the finding text."""
        if not file_lines:
            return None, None

        candidates = self._extract_identifier_candidates(
            issue, reasoning, code_snippet
        )

        for name in candidates:
            for i, line in enumerate(file_lines):
                if name in line:
                    line_start = i + 1

                    line_end = line_start
                    brace_depth = 0
                    found_open_brace = False
                    for j in range(i, min(i + 60, len(file_lines))):
                        for ch in file_lines[j]:
                            if ch == '{':
                                brace_depth += 1
                                found_open_brace = True
                            elif ch == '}':
                                brace_depth -= 1
                        if found_open_brace and brace_depth == 0:
                            line_end = j + 1
                            break

                    if line_end - line_start > 30:
                        line_end = line_start + 30

                    return line_start, line_end

        return None, None

    def _extract_context_snippet(
        self,
        file_lines: List[str],
        line_start: int,
        line_end: int,
        context_lines: int = 4,
    ) -> str:
        """
        Extract code snippet with surrounding context lines.
        
        Args:
            file_lines: All lines from the file
            line_start: Starting line number (1-indexed)
            line_end: Ending line number (1-indexed)
            context_lines: Number of context lines before and after
            
        Returns:
            Code snippet with context and line numbers
        """
        # Convert to 0-indexed
        start_idx = max(0, line_start - 1 - context_lines)
        end_idx = min(len(file_lines), line_end + context_lines)
        
        # Extract lines with line numbers
        snippet_lines = []
        for i in range(start_idx, end_idx):
            line_num = i + 1
            line_content = file_lines[i].rstrip()
            
            # Mark the actual finding lines
            if line_start <= line_num <= line_end:
                snippet_lines.append(f"{line_num:4d} > {line_content}")
            else:
                snippet_lines.append(f"{line_num:4d} | {line_content}")
        
        return "\n".join(snippet_lines)

    def _parse_severity(self, severity: str) -> Severity:
        """Parse severity string to Severity enum."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return severity_map.get(severity.lower(), Severity.MEDIUM)

    def _parse_confidence(self, confidence) -> FindingConfidence:
        """Parse confidence value to FindingConfidence enum.

        Accepts floats (0.0-1.0) or strings ("high", "medium", "low").
        """
        if isinstance(confidence, str):
            confidence_lower = confidence.lower().strip()
            if confidence_lower == "high":
                return FindingConfidence.HIGH
            elif confidence_lower == "medium":
                return FindingConfidence.MEDIUM
            else:
                return FindingConfidence.LOW

        try:
            conf_val = float(confidence)
            if conf_val >= 0.8:
                return FindingConfidence.HIGH
            elif conf_val >= 0.5:
                return FindingConfidence.MEDIUM
            else:
                return FindingConfidence.LOW
        except (TypeError, ValueError):
            return FindingConfidence.MEDIUM