"""Main CLI application entry point."""

import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from .banner import print_banner
from .commands import (
    index_command,
    review_command,
    scan_command,
    info_command,
    config_command,
)
from .commands_projects import (
    projects_list_command,
    projects_info_command,
    projects_delete_command,
    projects_cleanup_command,
)

# Create Typer app
app = typer.Typer(
    name="falconeye",
    help="FalconEYE v2.0 - AI-Powered Security Code Review",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Rich console for output
console = Console()


@app.command(name="index")
def index(
    path: Path = typer.Argument(
        ...,
        help="Path to codebase to index",
        exists=True,
    ),
    language: Optional[str] = typer.Option(
        None,
        "--language", "-l",
        help="Programming language (auto-detected if not specified)",
    ),
    chunk_size: Optional[int] = typer.Option(
        None,
        "--chunk-size",
        help="Lines per chunk",
    ),
    chunk_overlap: Optional[int] = typer.Option(
        None,
        "--chunk-overlap",
        help="Lines of overlap between chunks",
    ),
    exclude: Optional[list[str]] = typer.Option(
        None,
        "--exclude", "-e",
        help="Exclusion patterns (can specify multiple)",
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        help="Explicit project ID (auto-detected if not specified)",
    ),
    force_reindex: bool = typer.Option(
        False,
        "--force-reindex",
        help="Force re-index all files (skip smart re-indexing)",
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with technical details and full logs",
    ),
):
    """
    Index a codebase for analysis.

    Indexes source code files, generates embeddings, and extracts metadata.
    This is required before running security reviews.
    
    Usage:
        falconeye index <path>        # Normal mode: Progress bar only
        falconeye index <path> -v     # Verbose mode: Full indexing logs
    """
    index_command(
        path=path,
        language=language,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        exclude=exclude,
        project_id=project_id,
        force_reindex=force_reindex,
        config_path=config,
        verbose=verbose,
        console=console,
    )


@app.command(name="review")
def review(
    path: Path = typer.Argument(
        ...,
        help="Path to file or directory to review",
        exists=True,
    ),
    language: Optional[str] = typer.Option(
        None,
        "--language", "-l",
        help="Programming language (auto-detected if not specified)",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Enable AI validation to reduce false positives",
    ),
    top_k: Optional[int] = typer.Option(
        None,
        "--top-k",
        help="Number of similar chunks for context",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output format (console, json, sarif, html)",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        help="Save results to file",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        help="Minimum severity to report (critical, high, medium, low)",
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with full logs",
    ),
):
    """
    Review a file or directory for security vulnerabilities.

    Performs AI-powered security analysis on the specified code.
    The codebase should be indexed first for best results (RAG context).
    
    Usage:
        falconeye review <path>       # Normal mode: Progress bar and results
        falconeye review <path> -v    # Verbose mode: Full logs and LLM streaming
    """
    review_command(
        path=path,
        language=language,
        validate=validate,
        top_k=top_k,
        output_format=output_format,
        output_file=output_file,
        severity=severity,
        config_path=config,
        verbose=verbose,
        console=console,
    )


@app.command(name="scan")
def scan(
    path: Path = typer.Argument(
        ...,
        help="Path to codebase to scan",
        exists=True,
    ),
    language: Optional[str] = typer.Option(
        None,
        "--language", "-l",
        help="Programming language (auto-detected if not specified)",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Enable AI validation to reduce false positives",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output format (console, json, sarif, html)",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        help="Save results to file",
    ),
    project_id: Optional[str] = typer.Option(
        None,
        "--project-id",
        help="Explicit project ID (auto-detected if not specified)",
    ),
    force_reindex: bool = typer.Option(
        False,
        "--force-reindex",
        help="Force re-index all files (skip smart re-indexing)",
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with full logs",
    ),
):
    """
    Index and review in one command.

    Convenience command that indexes the codebase and then performs
    a security review.
    
    Usage Examples:
        falconeye scan <path>              # Normal mode: Shows progress bar and final results only
        falconeye scan <path> -v           # Verbose mode: Shows full logs, LLM streaming, and detailed progress
        falconeye scan <path> --verbose    # Verbose mode: Same as -v (alternative syntax)
    
    Output Modes:
        Normal mode (-v not used):
            - Progress bar showing file count and current file being analyzed
            - Findings displayed in real-time as they're detected
            - Final summary with all findings
            - Clean output without detailed logs
        
        Verbose mode (-v or --verbose):
            - All indexing logs (file processing, chunking, embedding generation)
            - LLM thought process streaming (AI analysis in real-time)
            - All security analysis logs
            - Detailed progress information
            - Full error details if analysis fails
    """
    scan_command(
        path=path,
        language=language,
        validate=validate,
        output_format=output_format,
        output_file=output_file,
        project_id=project_id,
        force_reindex=force_reindex,
        config_path=config,
        verbose=verbose,
        console=console,
    )


@app.command(name="info")
def info(
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
):
    """
    Show system information.

    Displays FalconEYE version, LLM status, and configuration.
    """
    info_command(config_path=config, console=console)


@app.command(name="config")
def config_cmd(
    init: bool = typer.Option(
        False,
        "--init",
        help="Create default configuration file",
    ),
    path: Optional[str] = typer.Option(
        None,
        "--path",
        help="Configuration file path",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Show current configuration",
    ),
):
    """
    Manage configuration.

    Create, view, or validate configuration files.
    """
    config_command(
        init=init,
        path=path,
        show=show,
        console=console,
    )


# Create projects subcommand group
projects_app = typer.Typer(
    name="projects",
    help="Manage indexed projects",
    no_args_is_help=True,
)

@projects_app.command(name="list")
def projects_list(
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
):
    """
    List all indexed projects.

    Shows a summary of all projects in the registry.
    """
    projects_list_command(config_path=config, console=console)


@projects_app.command(name="info")
def projects_info(
    project_id: str = typer.Argument(
        ...,
        help="Project ID to show info for",
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
):
    """
    Show detailed information about a project.

    Displays project metadata, file statistics, and configuration.
    """
    projects_info_command(
        project_id=project_id,
        config_path=config,
        console=console,
    )


@projects_app.command(name="delete")
def projects_delete(
    project_id: str = typer.Argument(
        ...,
        help="Project ID to delete",
    ),
    yes: bool = typer.Option(
        False,
        "--yes", "-y",
        help="Skip confirmation prompt",
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
):
    """
    Delete a project from the index.

    Removes all indexed data for the specified project.
    This action cannot be undone.
    """
    projects_delete_command(
        project_id=project_id,
        yes=yes,
        config_path=config,
        console=console,
    )


@projects_app.command(name="cleanup")
def projects_cleanup(
    project_id: str = typer.Argument(
        ...,
        help="Project ID to clean up",
    ),
    yes: bool = typer.Option(
        False,
        "--yes", "-y",
        help="Skip confirmation prompt",
    ),
    config: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file",
    ),
):
    """
    Clean up deleted files from a project.

    Removes metadata for files that have been deleted from disk.
    """
    projects_cleanup_command(
        project_id=project_id,
        yes=yes,
        config_path=config,
        console=console,
    )


# Add projects command group to main app
app.add_typer(projects_app, name="projects")


def main():
    """Main entry point."""
    try:
        # Show banner if not in help mode
        if len(sys.argv) > 1 and sys.argv[1] not in ['--help', '-h', '--version']:
            print_banner(console)
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print("\n[bold red]Error:[/bold red]", end=" ")
        console.print(str(e), markup=False)
        sys.exit(1)


if __name__ == "__main__":
    main()