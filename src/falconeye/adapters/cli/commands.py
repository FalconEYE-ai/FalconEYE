"""CLI command implementations."""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional, Callable
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from ...infrastructure.di.container import DIContainer
from ...infrastructure.config.config_loader import ConfigLoader
from ...infrastructure.presentation.error_presenter import ErrorPresenter
from ...infrastructure.logging import FalconEyeLogger
from ...application.commands.index_codebase import IndexCodebaseCommand
from ...application.commands.review_file import ReviewFileCommand
from ..formatters.formatter_factory import FormatterFactory
from ...domain.models.security import SecurityFinding, Severity, FindingConfidence


def _format_finding_realtime(finding: SecurityFinding, console: Console, finding_number: int = None) -> None:
    """
    Format and display a security finding in real-time with Rich formatting.
    
    Args:
        finding: SecurityFinding to display
        console: Rich console instance
        finding_number: Optional finding number for display
    """
    # Determine severity color and border style
    severity_colors = {
        Severity.CRITICAL: ("red", "bold red"),
        Severity.HIGH: ("bright_red", "red"),
        Severity.MEDIUM: ("yellow", "yellow"),
        Severity.LOW: ("blue", "blue"),
        Severity.INFO: ("cyan", "cyan"),
    }
    
    border_color, title_color = severity_colors.get(finding.severity, ("white", "white"))
    
    # Create title with severity badge
    title_parts = []
    if finding_number is not None:
        title_parts.append(f"[dim]#{finding_number}[/dim] ")
    
    severity_text = finding.severity.value.upper()
    title_parts.append(f"[{title_color}]{severity_text}[/{title_color}]")
    title_parts.append(f" [bold white]{finding.issue}[/bold white]")
    
    title = "".join(title_parts)
    
    # Build finding content
    content_parts = []
    
    # Location information
    if finding.file_path:
        location = f"[cyan]📁 {finding.file_path}[/cyan]"
        if finding.line_start:
            if finding.line_end and finding.line_end != finding.line_start:
                location += f" [dim](lines {finding.line_start}-{finding.line_end})[/dim]"
            else:
                location += f" [dim](line {finding.line_start})[/dim]"
        content_parts.append(location)
        content_parts.append("")
    
    # Confidence badge
    confidence_colors = {
        FindingConfidence.HIGH: "green",
        FindingConfidence.MEDIUM: "yellow",
        FindingConfidence.LOW: "orange",
    }
    conf_color = confidence_colors.get(finding.confidence, "white")
    content_parts.append(f"[{conf_color}]Confidence: {finding.confidence.value.upper()}[/{conf_color}]")
    content_parts.append("")
    
    # Reasoning
    if finding.reasoning:
        content_parts.append("[bold]Description:[/bold]")
        content_parts.append(f"  {finding.reasoning}")
        content_parts.append("")
    
    # Mitigation
    if finding.mitigation:
        content_parts.append("[bold green]💡 Recommendation:[/bold green]")
        content_parts.append(f"  {finding.mitigation}")
        content_parts.append("")
    
    # Code snippet (if verbose or if available)
    if finding.code_snippet:
        content_parts.append("[dim]Code snippet:[/dim]")
        # Indent code snippet
        for line in finding.code_snippet.split("\n")[:5]:  # Limit to 5 lines
            content_parts.append(f"  [dim]{line}[/dim]")
        if finding.code_snippet.count("\n") > 5:
            content_parts.append("  [dim]...[/dim]")
    
    content = "\n".join(content_parts)
    
    # Create panel with styled border
    panel = Panel(
        content,
        title=title,
        border_style=border_color,
        box=box.ROUNDED,
        padding=(0, 1),
    )
    
    console.print(panel)
    console.print("")  # Spacing between findings


def _configure_logger_verbosity(container, verbose: bool) -> None:
    """
    Configure logger console output based on verbose flag.

    In non-verbose mode, removes console handlers so logs only go to file.

    Args:
        container: DI container with config
        verbose: Whether verbose mode is enabled
    """
    import sys

    logger = FalconEyeLogger.get_instance(
        level=container.config.logging.level,
        log_file=Path(container.config.logging.file),
        console=True,  # Initialize with console enabled
        rotation=container.config.logging.rotation,
        retention_days=container.config.logging.retention_days,
    )

    # Disable console handlers if not verbose
    if not verbose:
        logger.logger.handlers = [
            h for h in logger.logger.handlers
            if not (isinstance(h, logging.StreamHandler) and h.stream == sys.stderr)
        ]


def _estimate_time_based_progress(elapsed_seconds: float) -> int:
    """
    Estimate progress percentage based on elapsed time.

    Uses a logarithmic-like curve: fast initial progress, slowing over time.
    This provides smooth progress feedback when actual progress can't be measured.

    Args:
        elapsed_seconds: Time elapsed since operation started

    Returns:
        Estimated progress percentage (0-95, never 100)
    """
    if elapsed_seconds < 10:
        # First 10 seconds: 0-20%
        return int((elapsed_seconds / 10) * 20)
    elif elapsed_seconds < 30:
        # 10-30 seconds: 20-60%
        return 20 + int(((elapsed_seconds - 10) / 20) * 40)
    elif elapsed_seconds < 60:
        # 30-60 seconds: 60-85%
        return 60 + int(((elapsed_seconds - 30) / 30) * 25)
    else:
        # After 60 seconds: 85-95% (slow increase)
        return 85 + min(10, int((elapsed_seconds - 60) / 10))


def index_command(
    path: Path,
    language: Optional[str],
    chunk_size: Optional[int],
    chunk_overlap: Optional[int],
    exclude: Optional[list[str]],
    project_id: Optional[str],
    force_reindex: bool,
    config_path: Optional[str],
    verbose: bool,
    console: Console,
):
    """
    Execute index command.

    Args:
        path: Path to codebase
        language: Language name
        chunk_size: Chunk size
        chunk_overlap: Chunk overlap
        exclude: Exclusion patterns
        project_id: Explicit project ID
        force_reindex: Force re-index all files
        config_path: Config file path
        verbose: Enable verbose output
        console: Rich console
    """
    if verbose:
        console.print(Panel.fit(
            "[bold]FalconEYE Indexer[/bold]",
            border_style="blue"
        ))

    # Create DI container
    container = DIContainer.create(config_path)

    # Configure logger verbosity
    _configure_logger_verbosity(container, verbose)

    # Use config values if not specified
    if chunk_size is None:
        chunk_size = container.config.chunking.default_size
    if chunk_overlap is None:
        chunk_overlap = container.config.chunking.default_overlap
    if exclude is None:
        exclude = container.config.file_discovery.default_exclusions

    # Create command
    command = IndexCodebaseCommand(
        codebase_path=path,
        language=language,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        excluded_patterns=exclude,
        project_id=project_id,
        force_reindex=force_reindex,
    )

    # Discover files first to get total count for progress
    from ...domain.services.language_detector import LanguageDetector
    language_detector = container.language_detector
    
    # Detect language if not specified
    if language is None:
        detected_language = language_detector.detect_language(path)
    else:
        detected_language = language
    
    # Discover files to get total count
    try:
        detected_languages = language_detector.detect_all_languages(path)
    except Exception:
        detected_languages = [detected_language]
    
    files = []
    for lang in detected_languages:
        extensions = language_detector.LANGUAGE_EXTENSIONS.get(lang, [])
        for ext in extensions:
            files.extend(list(path.rglob(f"*{ext}")))
    
    # Filter excluded patterns
    filtered_files = []
    for file_path in files:
        should_exclude = False
        relative_path = str(file_path.relative_to(path))
        for pattern in exclude:
            pattern_clean = pattern.replace("**", "").replace("*", "")
            if pattern_clean in relative_path or pattern_clean in str(file_path):
                should_exclude = True
                break
        if not should_exclude:
            filtered_files.append(file_path)
    
    total_files = len(filtered_files)
    
    # Track progress
    processed_files = [0]
    
    def update_progress(current: int, total: int):
        """Update progress callback."""
        processed_files[0] = current
        if total > 0:
            percentage = int((current / total) * 100)
            return percentage
        return 0

    # Execute with progress
    if verbose:
        # Verbose mode: show spinner and all logs
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Indexing codebase...", total=None)
            try:
                codebase = asyncio.run(container.index_handler.handle(command))
                progress.update(task, description="[green]Indexing complete!")
            except KeyboardInterrupt:
                progress.update(task, description="[yellow]Indexing cancelled")
                error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
                console.print(f"\n{error_msg}")
                raise SystemExit(1)
            except Exception as e:
                progress.update(task, description="[red]Indexing failed!")
                error_msg = ErrorPresenter.present(e, verbose=verbose)
                console.print(f"\n{error_msg}")
                raise SystemExit(1)
    else:
        # Non-verbose mode: show progress percentage only
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"Indexing codebase...",
                total=100  # Use percentage (0-100)
            )
            
            # Start with 0%
            progress.update(task, completed=0)
            
            # Run indexing in background and update progress periodically
            import threading
            import time
            
            progress_value = [0]  # Use list for mutable reference
            indexing_done = [False]
            indexing_error = [None]
            
            def update_progress_loop():
                """Update progress bar while indexing is running."""
                while not indexing_done[0] and progress_value[0] < 95:
                    time.sleep(0.5)  # Update every 500ms
                    if progress_value[0] < 90:
                        progress_value[0] += 2  # Gradually increase
                    progress.update(task, completed=progress_value[0])
            
            # Start progress updater
            progress_thread = threading.Thread(target=update_progress_loop, daemon=True)
            progress_thread.start()
            
            try:
                codebase = asyncio.run(container.index_handler.handle(command))
                indexing_done[0] = True
                progress.update(task, completed=100, description="[green]Indexing complete!")
            except KeyboardInterrupt:
                indexing_done[0] = True
                progress.update(task, description="[yellow]Indexing cancelled")
                raise SystemExit(1)
            except Exception as e:
                indexing_done[0] = True
                indexing_error[0] = e
                progress.update(task, description="[red]Indexing failed!")
                error_msg = ErrorPresenter.present(e, verbose=verbose)
                console.print(f"\n{error_msg}")
                raise SystemExit(1)

    # Display summary
    if not verbose:
        console.print("")  # Add newline after progress bar
    console.print(f"[green]Indexed {codebase.total_files} files[/green]")
    
    # Show all detected languages
    all_langs = codebase.all_languages
    if len(all_langs) == 1:
        console.print(f"[green]Language: {all_langs[0]}[/green]")
    else:
        langs_str = ", ".join(all_langs)
        console.print(f"[green]Languages: {langs_str}[/green]")
    
    console.print(f"[green]Total lines: {codebase.total_lines}[/green]")


def review_command(
    path: Path,
    language: Optional[str],
    validate: bool,
    top_k: Optional[int],
    output_format: Optional[str],
    output_file: Optional[Path],
    severity: Optional[str],
    config_path: Optional[str],
    verbose: bool,
    console: Console,
):
    """
    Execute review command.

    Args:
        path: Path to review
        language: Language name
        validate: Enable validation
        top_k: Context count
        output_format: Output format
        output_file: Output file
        severity: Minimum severity
        config_path: Config file path
        verbose: Verbose output
        console: Rich console
    """
    if verbose:
        console.print(Panel.fit(
            "[bold]FalconEYE Security Review[/bold]",
            border_style="blue"
        ))

    # Create DI container
    container = DIContainer.create(config_path)

    # Configure logger verbosity
    _configure_logger_verbosity(container, verbose)

    # Use config values if not specified
    if top_k is None:
        top_k = container.config.analysis.top_k_context
    if output_format is None:
        output_format = container.config.output.default_format

    # Detect language if not specified
    if language is None:
        language = container.language_detector.detect_language(path)

    # Check if path is directory or file
    if path.is_dir():
        # Directory - review all files from ALL detected languages
        
        # Detect all languages in the codebase
        try:
            all_languages = container.language_detector.detect_all_languages(path)
            console.print(f"[cyan]Detected languages: {', '.join(all_languages)}[/cyan]")
        except Exception:
            # Fallback to single language
            all_languages = [language]
        
        # Collect files from all detected languages
        files = []
        for lang in all_languages:
            extensions = container.language_detector.LANGUAGE_EXTENSIONS.get(lang, [])
            for ext in extensions:
                files.extend(list(path.rglob(f"*{ext}")))
        
        # Remove duplicates
        files = list(set(files))

        if not files:
            console.print(f"[yellow]No source files found in {path}[/yellow]")
            return

        # Create aggregate review
        from ...domain.models.security import SecurityReview
        aggregate_review = SecurityReview.create(
            codebase_path=str(path),
            language=language,
        )

        # Review each file
        if verbose:
            # Verbose mode: show spinner and all logs
            progress_columns = [
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ]
        else:
            # Non-verbose mode: show progress bar with file count and percentage
            progress_columns = [
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ]
        
        # Track failed files for summary reporting
        failed_files = []

        with Progress(
            *progress_columns,
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(f"Security Review: Analyzing {len(files)} files...", total=len(files))

            for file_index, file_path in enumerate(files, start=1):
                try:
                    # Detect language for this specific file
                    file_language = container.language_detector.detect_language(file_path)
                    file_system_prompt = container.get_system_prompt(file_language)

                    # Create streaming callback to show LLM thought process
                    stream_buffer = []
                    findings_displayed = []
                    
                    def stream_callback(token: str):
                        """Callback to display LLM streaming tokens."""
                        stream_buffer.append(token)
                        # Display in real-time (only in verbose mode or when explicitly enabled)
                        if verbose:
                            console.print(token, end="", style="dim italic")
                    
                    def finding_callback(finding: SecurityFinding):
                        """Callback to display findings as soon as they're detected."""
                        # Stop progress bar temporarily
                        progress.stop()
                        
                        # Display the finding immediately
                        if finding not in findings_displayed:
                            findings_displayed.append(finding)
                            finding_num = len(findings_displayed)
                            console.print(f"\n[bold cyan]🔍 Finding #{finding_num} in [white]{file_path.name}[/white]:[/bold cyan]")
                            console.print("")
                            _format_finding_realtime(finding, console, finding_number=finding_num)
                            console.print("")
                        
                        # Restart progress bar
                        progress.start()
                        progress.update(
                            task,
                            description=f"Analyzing file {file_index}/{len(files)}: {file_path.name}",
                            completed=file_index - 1
                        )
                    
                    command = ReviewFileCommand(
                        file_path=file_path,
                        language=file_language,
                        system_prompt=file_system_prompt,
                        validate_findings=validate,
                        top_k_context=top_k,
                        stream_callback=stream_callback if verbose else None,
                        finding_callback=finding_callback,
                    )

                    # Show progress updates during analysis phases
                    if not verbose:
                        # Update progress to show current file being analyzed
                        progress.update(
                            task,
                            description=f"Analyzing file {file_index}/{len(files)}: {file_path.name}",
                            completed=file_index - 1
                        )
                    
                    # Create a wrapper to show progress during async operations
                    async def handle_with_progress(cmd):
                        """Wrapper to show progress during review."""
                        import time as time_module  # Import inside function to avoid closure issues
                        handler = container.review_file_handler
                        
                        # Start the handler task
                        handler_task = asyncio.create_task(handler.handle(cmd))
                        
                        # Show periodic progress updates while waiting
                        if not verbose:
                            status_messages = [
                                "[dim]Assembling context...[/dim]",
                                "[dim]Analyzing with AI (this may take a minute)...[/dim]",
                                "[dim]Processing results...[/dim]",
                            ]
                            status_index = 0
                            import time as time_module
                            last_update = time_module.time()
                            
                            while not handler_task.done():
                                await asyncio.sleep(3)  # Update every 3 seconds
                                current_time = time_module.time()
                                
                                # Update status message periodically
                                if current_time - last_update >= 3:
                                    if status_index < len(status_messages):
                                        progress.update(
                                            task,
                                            description=f"Analyzing file {file_index}/{len(files)}: {file_path.name} - {status_messages[status_index]}",
                                            completed=file_index - 1
                                        )
                                        status_index += 1
                                    else:
                                        # Keep showing "Analyzing with AI" message with file count
                                        progress.update(
                                            task,
                                            description=f"Analyzing file {file_index}/{len(files)}: {file_path.name} - {status_messages[1]}",
                                            completed=file_index - 1
                                        )
                                    last_update = current_time
                        else:
                            # In verbose mode, show a header for LLM output
                            console.print("\n[bold cyan]🤖 AI Analysis (Streaming):[/bold cyan]")
                            console.print("[dim]" + "─" * 60 + "[/dim]")
                        
                        return await handler_task
                    
                    review = asyncio.run(handle_with_progress(command))
                    
                    # Add newline after streaming in verbose mode
                    if verbose and stream_buffer:
                        console.print("\n")

                    # Display any findings that weren't caught incrementally
                    if review.findings:
                        # Only display findings that weren't already shown via callback
                        new_findings = [f for f in review.findings if f not in findings_displayed]
                        if new_findings:
                            # Hide progress bar temporarily when displaying findings
                            progress.stop()
                            # Use console.print() which works alongside progress bar
                            # Rich Progress automatically handles this correctly
                            console.print(f"\n[bold cyan]🔍 Additional findings in [white]{file_path.name}[/white]:[/bold cyan]")
                            console.print("")
                            
                            for idx, finding in enumerate(new_findings, start=len(findings_displayed) + 1):
                                _format_finding_realtime(finding, console, finding_number=idx)
                            
                            # Restart progress bar
                            progress.start()
                            # Update progress with file count
                            if verbose:
                                progress.update(task, description=f"Analyzing {file_index}/{len(files)}: {file_path.name}...", completed=file_index)
                            else:
                                progress.update(task, description=f"Analyzing file {file_index}/{len(files)}: {file_path.name}", completed=file_index)
                    
                    # Add all findings to aggregate (including those already displayed)
                    if review.findings:
                        # Only update progress bar if no findings (to avoid cluttering output)
                        if verbose:
                            progress.update(task, description=f"Analyzing {file_index}/{len(files)}: {file_path.name}...")
                        else:
                            # Update to show completed file
                            progress.update(task, description=f"Analyzing file {file_index}/{len(files)}: {file_path.name}", completed=file_index)
                    
                    # Add findings to aggregate
                    for finding in review.findings:
                        aggregate_review.add_finding(finding)

                    progress.advance(task)

                except KeyboardInterrupt:
                    progress.update(task, description="[yellow]Analysis cancelled")
                    error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
                    console.print(f"\n{error_msg}")
                    raise SystemExit(1)

                except Exception as e:
                    # For directory scan, show warning and continue
                    error_type = type(e).__name__
                    error_message = str(e) if str(e) else "Unknown error"

                    # Track failed file for summary
                    failed_files.append((file_path, f"{error_type}: {error_message[:100]}"))

                    # Always show at least the error type and message
                    console.print(f"\n[yellow]⚠ Warning: Failed to analyze {file_path.name}[/yellow]")
                    console.print(f"[dim]Error: {error_type}: {error_message[:200]}[/dim]")

                    if verbose:
                        error_msg = ErrorPresenter.present(e, verbose=True)
                        console.print(error_msg)
                    else:
                        # In non-verbose mode, suggest using -v for more details
                        console.print(f"[dim]Run with -v flag for detailed error information[/dim]")

                    progress.advance(task)
                    continue

            if verbose:
                progress.update(task, description="[green]Analysis complete!")
            else:
                progress.update(
                    task,
                    description="[green]Security Review complete!",
                    completed=len(files)
                )

        # Display summary of failed files if any
        if failed_files:
            console.print("")
            console.print(f"[yellow]⚠ {len(failed_files)} file(s) failed analysis:[/yellow]")
            # Show first 5 failed files
            for failed_path, error in failed_files[:5]:
                console.print(f"  [dim]• {failed_path.name}: {error}[/dim]")
            if len(failed_files) > 5:
                console.print(f"  [dim]... and {len(failed_files) - 5} more[/dim]")
            console.print(f"[dim]Successfully analyzed: {len(files) - len(failed_files)}/{len(files)} files[/dim]")

        review = aggregate_review

    else:
        # Single file - get system prompt for the detected language
        system_prompt = container.get_system_prompt(language)
        
        # Create streaming callback to show LLM thought process
        stream_buffer = []
        
        def stream_callback(token: str):
            """Callback to display LLM streaming tokens."""
            stream_buffer.append(token)
            # Display in real-time (only in verbose mode)
            if verbose:
                console.print(token, end="", style="dim italic")
        
        command = ReviewFileCommand(
            file_path=path,
            language=language,
            system_prompt=system_prompt,
            validate_findings=validate,
            top_k_context=top_k,
            stream_callback=stream_callback if verbose else None,
        )

        if verbose:
            # Verbose mode: show spinner
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Security Review: Analyzing code...", total=None)

                try:
                    # Show progress updates during analysis
                    async def handle_with_progress_single(cmd):
                        """Wrapper to show progress during single file review."""
                        import time as time_module  # Import inside function to avoid closure issues
                        handler = container.review_file_handler
                        handler_task = asyncio.create_task(handler.handle(cmd))
                        
                        # Show periodic progress updates while waiting
                        status_messages = [
                            "[dim]Assembling context...[/dim]",
                            "[dim]Analyzing with AI (this may take a minute)...[/dim]",
                            "[dim]Processing results...[/dim]",
                        ]
                        status_index = 0
                        last_update = time_module.time()
                        
                        # In verbose mode, show a header for LLM output
                        console.print("\n[bold cyan]🤖 AI Analysis (Streaming):[/bold cyan]")
                        console.print("[dim]" + "─" * 60 + "[/dim]")
                        
                        while not handler_task.done():
                            await asyncio.sleep(3)  # Update every 3 seconds
                            current_time = time_module.time()
                            
                            # Update status message periodically
                            if current_time - last_update >= 3:
                                if status_index < len(status_messages):
                                    progress.update(task, description=status_messages[status_index])
                                    status_index += 1
                                else:
                                    # Keep showing "Analyzing with AI" message
                                    progress.update(task, description=status_messages[1])
                                last_update = current_time
                        
                        return await handler_task
                    
                    review = asyncio.run(handle_with_progress_single(command))
                    
                    # Add newline after streaming
                    if stream_buffer:
                        console.print("\n")
                    
                    # Display findings immediately if any are found
                    if review.findings:
                        # Use console.print() which works alongside progress bar
                        console.print(f"\n[bold cyan]🔍 Security Findings:[/bold cyan]")
                        console.print("")
                        
                        for idx, finding in enumerate(review.findings, start=1):
                            _format_finding_realtime(finding, console, finding_number=idx)
                    
                    progress.update(task, description="[green]Analysis complete!")

                except KeyboardInterrupt:
                    progress.update(task, description="[yellow]Analysis cancelled")
                    error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
                    console.print(f"\n{error_msg}")
                    raise SystemExit(1)

                except Exception as e:
                    progress.update(task, description="[red]Analysis failed!")
                    error_type = type(e).__name__
                    error_message = str(e) if str(e) else "Unknown error"
                    
                    console.print(f"\n[red]❌ Analysis failed for {path.name}[/red]")
                    console.print(f"[dim]Error: {error_type}: {error_message[:200]}[/dim]")
                    
                    error_msg = ErrorPresenter.present(e, verbose=verbose)
                    console.print(f"\n{error_msg}")
                    raise SystemExit(1)
        else:
            # Non-verbose mode: show progress bar with percentage
            import threading
            import time
            
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task(
                    "Security Review: Analyzing code...",
                    total=100  # Use percentage (0-100)
                )
                
                # Start with 0%
                progress.update(task, completed=0)
                
                # Track progress
                review_progress = [0]
                review_done = [False]
                review_error = [None]
                review_start_time = time.time()  # Track start time for progress estimation

                def update_review_progress_loop():
                    """Update progress bar while review is running (time-based)."""
                    import time as time_module  # Import inside function to avoid closure issues
                    while not review_done[0] and review_progress[0] < 95:
                        time_module.sleep(0.5)  # Update every 500ms
                        elapsed_time = time_module.time() - review_start_time

                        # Use helper function for consistent progress estimation
                        progress_pct = _estimate_time_based_progress(elapsed_time)

                        # Estimate time remaining
                        if elapsed_time > 5:  # After 5 seconds, start estimating
                            # Rough estimate: if we're at X%, remaining is (100-X)/X * elapsed
                            if progress_pct > 0:
                                estimated_total = elapsed_time / (progress_pct / 100)
                                estimated_remaining = estimated_total - elapsed_time
                                if estimated_remaining > 0:
                                    time_remaining_str = f"{int(estimated_remaining // 60)}m {int(estimated_remaining % 60)}s" if estimated_remaining > 60 else f"{int(estimated_remaining)}s"
                                    description = f"Analyzing code... (est. {time_remaining_str} remaining)"
                                else:
                                    description = "Analyzing code... (almost done)"
                            else:
                                description = "Analyzing code..."
                        else:
                            description = "Analyzing code..."

                        review_progress[0] = progress_pct
                        progress.update(task, completed=progress_pct, description=description)
                
                # Start progress updater
                progress_thread = threading.Thread(target=update_review_progress_loop, daemon=True)
                progress_thread.start()
                
                try:
                    # Show progress updates during analysis
                    async def handle_with_progress_single(cmd):
                        """Wrapper to show progress during single file review."""
                        import time as time_module  # Import inside function to avoid closure issues
                        handler = container.review_file_handler
                        handler_task = asyncio.create_task(handler.handle(cmd))
                        
                        # Show periodic progress updates while waiting
                        status_messages = [
                            "[dim]Assembling context...[/dim]",
                            "[dim]Analyzing with AI (this may take a minute)...[/dim]",
                            "[dim]Processing results...[/dim]",
                        ]
                        status_index = 0
                        last_update = time_module.time()
                        
                        # In verbose mode, show a header for LLM output
                        if verbose:
                            console.print("\n[bold cyan]🤖 AI Analysis (Streaming):[/bold cyan]")
                            console.print("[dim]" + "─" * 60 + "[/dim]")
                        
                        while not handler_task.done():
                            await asyncio.sleep(3)  # Update every 3 seconds
                            current_time = time_module.time()
                            
                            # Update status message periodically
                            if current_time - last_update >= 3:
                                if status_index < len(status_messages):
                                    progress.update(task, completed=min(90, 30 + status_index * 20), description=status_messages[status_index])
                                    status_index += 1
                                else:
                                    # Keep showing "Analyzing with AI" message and gradually increase progress
                                    current_progress = min(90, review_progress[0] + 5)
                                    review_progress[0] = current_progress
                                    progress.update(task, completed=current_progress, description=status_messages[1])
                                last_update = current_time
                        
                        return await handler_task
                    
                    review = asyncio.run(handle_with_progress_single(command))
                    review_done[0] = True
                    
                    # Display findings immediately if any are found
                    if review.findings:
                        # Use console.print() which works alongside progress bar
                        console.print(f"\n[bold cyan]🔍 Security Findings:[/bold cyan]")
                        console.print("")
                        
                        for idx, finding in enumerate(review.findings, start=1):
                            _format_finding_realtime(finding, console, finding_number=idx)
                    
                    progress.update(
                        task,
                        completed=100,
                        description="[green]Security Review complete![/green]"
                    )
                except KeyboardInterrupt:
                    review_done[0] = True
                    progress.update(task, description="[yellow]Analysis cancelled")
                    error_msg = ErrorPresenter.present(KeyboardInterrupt(), verbose=verbose)
                    console.print(f"\n{error_msg}")
                    raise SystemExit(1)
                except Exception as e:
                    review_done[0] = True
                    review_error[0] = e
                    progress.update(task, description="[red]Analysis failed!")
                    error_msg = ErrorPresenter.present(e, verbose=verbose)
                    console.print(f"\n{error_msg}")
                    raise SystemExit(1)

    # Format output
    formatter = FormatterFactory.create(
        output_format,
        use_color=container.config.output.color,
        verbose=verbose
    )

    output = formatter.format_review(review)

    # Display or save
    if output_file:
        output_file.write_text(output)
        console.print(f"\n[green]Results saved to {output_file}[/green]")
    elif output_format == "json" and container.config.output.save_to_file:
        # Auto-save JSON to default location
        from datetime import datetime
        output_dir = Path(container.config.output.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = path.name if path.is_dir() else path.stem
        auto_file = output_dir / f"falconeye_{project_name}_{timestamp}.json"
        
        auto_file.write_text(output)
        console.print(f"\n[green]Results saved to {auto_file}[/green]")
        
        # Also generate HTML report
        html_formatter = FormatterFactory.create("html")
        html_output = html_formatter.format_review(review)
        html_file = output_dir / f"falconeye_{project_name}_{timestamp}.html"
        html_file.write_text(html_output)
        console.print(f"[green]HTML report saved to {html_file}[/green]")
    else:
        # Show final summary - add separator if findings were already shown during scan
        if review.findings and path.is_dir():
            console.print("")  # Extra spacing
            console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]")
            console.print("[bold cyan]Final Summary[/bold cyan]")
            console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]")
        console.print("")
        console.print(output)


def scan_command(
    path: Path,
    language: Optional[str],
    validate: bool,
    output_format: Optional[str],
    output_file: Optional[Path],
    project_id: Optional[str],
    force_reindex: bool,
    config_path: Optional[str],
    verbose: bool,
    console: Console,
):
    """
    Execute scan command (index + review).

    Args:
        path: Path to scan
        language: Language name
        validate: Enable validation
        output_format: Output format
        output_file: Output file
        project_id: Explicit project ID
        force_reindex: Force re-index all files
        config_path: Config file path
        verbose: Verbose output
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE Full Scan[/bold]",
        border_style="blue"
    ))

    # Run index first
    console.print("\n[bold]Step 1: Indexing...[/bold]")
    index_command(
        path=path,
        language=language,
        chunk_size=None,
        chunk_overlap=None,
        exclude=None,
        project_id=project_id,
        force_reindex=force_reindex,
        config_path=config_path,
        verbose=verbose,
        console=console,
    )

    # Then review
    console.print("\n[bold]Step 2: Security Review...[/bold]")
    review_command(
        path=path,
        language=language,
        validate=validate,
        top_k=None,
        output_format=output_format,
        output_file=output_file,
        severity=None,
        config_path=config_path,
        verbose=verbose,
        console=console,
    )


def info_command(config_path: Optional[str], console: Console):
    """
    Execute info command.

    Args:
        config_path: Config file path
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE System Information[/bold]",
        border_style="blue"
    ))

    try:
        # Create DI container
        container = DIContainer.create(config_path)

        # Version info
        console.print("\n[bold]Version:[/bold]")
        console.print("  FalconEYE: 2.0.0")
        console.print("  Analysis: AI-powered (ZERO pattern matching)")

        # LLM info
        console.print("\n[bold]LLM Configuration:[/bold]")
        console.print(f"  Provider: {container.config.llm.provider}")
        console.print(f"  Analysis Model: {container.config.llm.model.analysis}")
        console.print(f"  Embedding Model: {container.config.llm.model.embedding}")
        console.print(f"  Base URL: {container.config.llm.base_url}")

        # Check LLM health
        try:
            is_healthy = asyncio.run(container.llm_service.health_check())
            if is_healthy:
                console.print("  Status: [green]Connected[/green]")
            else:
                console.print("  Status: [red]Not available[/red]")
        except Exception:
            console.print("  Status: [red]Connection failed[/red]")

        # Language support
        console.print("\n[bold]Supported Languages:[/bold]")
        languages = container.plugin_registry.get_supported_languages()
        console.print(f"  {', '.join(languages)}")

        # Storage info
        console.print("\n[bold]Storage:[/bold]")
        console.print(f"  Vector Store: {container.config.vector_store.persist_directory}")
        console.print(f"  Metadata: {container.config.metadata.persist_directory}")

        # Configuration info
        console.print("\n[bold]Configuration:[/bold]")
        config_info = ConfigLoader.get_config_info()
        if config_info["existing_configs"]:
            console.print("  Active configs:")
            for cfg in config_info["existing_configs"]:
                console.print(f"    - {cfg}")
        else:
            console.print("  Using default configuration")

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}")
        raise


def config_command(
    init: bool,
    path: Optional[str],
    show: bool,
    console: Console,
):
    """
    Execute config command.

    Args:
        init: Create default config
        path: Config file path
        show: Show current config
        console: Rich console
    """
    console.print(Panel.fit(
        "[bold]FalconEYE Configuration[/bold]",
        border_style="blue"
    ))

    if init:
        # Create default configuration
        try:
            config_path = ConfigLoader.create_default_config(path)
            console.print(f"\n[green]Configuration file created: {config_path}[/green]")
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {str(e)}")
            raise

    elif show:
        # Show current configuration
        try:
            config = ConfigLoader.load(path)
            yaml_str = config.to_yaml()
            console.print("\n[bold]Current Configuration:[/bold]")
            console.print(yaml_str)
        except Exception as e:
            console.print(f"\n[red]Error:[/red] {str(e)}")
            raise

    else:
        # Show config info
        config_info = ConfigLoader.get_config_info()

        console.print("\n[bold]Configuration Files:[/bold]")
        if config_info["existing_configs"]:
            for cfg in config_info["existing_configs"]:
                console.print(f"  [green]{cfg}[/green]")
        else:
            console.print("  No configuration files found")

        console.print("\n[bold]Environment Overrides:[/bold]")
        if config_info["env_overrides"]:
            for env_var in config_info["env_overrides"]:
                console.print(f"  {env_var}")
        else:
            console.print("  None")

        console.print("\n[bold]Default Locations:[/bold]")
        for default_path in config_info["default_paths"]:
            console.print(f"  {default_path}")