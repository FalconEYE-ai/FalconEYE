"""Upgrade command implementation for FalconEYE CLI."""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn


def _find_repo_root(start_path: Path) -> Optional[Path]:
    """Walk up from start_path to find a .git directory."""
    current = start_path.resolve()
    for parent in [current] + list(current.parents):
        if (parent / ".git").exists():
            return parent
    return None


def _get_install_location() -> Optional[Path]:
    """
    Find where falconeye is installed on disk.
    Returns the directory containing the falconeye package source.
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec("falconeye")
        if spec and spec.origin:
            # spec.origin is the __init__.py path
            # Go up: falconeye/ -> src/ -> repo root (or similar)
            return Path(spec.origin).parent
    except Exception:
        pass
    return None


def _get_current_version() -> str:
    """Get the currently installed version."""
    try:
        from falconeye import __version__
        return __version__
    except Exception:
        return "unknown"


def _get_remote_version(repo_root: Path) -> Optional[str]:
    """Get version from origin/main without checking out."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "show", "origin/main:src/falconeye/__init__.py"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "__version__" in line and "=" in line:
                    version = line.split("=", 1)[1].strip().strip('"').strip("'")
                    return version
    except Exception:
        pass
    return None


def _run_git_pull(repo_root: Path, console: Console) -> tuple[bool, str]:
    """
    Run git fetch + pull and return (changed: bool, output: str).
    """
    # First fetch to get remote state
    fetch_result = subprocess.run(
        ["git", "-C", str(repo_root), "fetch", "origin", "main"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if fetch_result.returncode != 0:
        raise RuntimeError(
            f"git fetch failed:\n{fetch_result.stderr.strip()}"
        )

    # Check what commits are incoming
    log_result = subprocess.run(
        ["git", "-C", str(repo_root), "log", "HEAD..origin/main", "--oneline"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    incoming_commits = log_result.stdout.strip()

    # Now pull
    pull_result = subprocess.run(
        ["git", "-C", str(repo_root), "pull", "origin", "main"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if pull_result.returncode != 0:
        raise RuntimeError(
            f"git pull failed:\n{pull_result.stderr.strip()}"
        )

    already_up_to_date = (
        "already up to date" in pull_result.stdout.lower()
        and not incoming_commits
    )

    return (not already_up_to_date), pull_result.stdout.strip(), incoming_commits


def _is_editable_install(repo_root: Path) -> bool:
    """Check if falconeye is installed in editable mode."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "show", "-f", "falconeye"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return "editable" in result.stdout.lower() or str(repo_root) in result.stdout


def _run_pip_install(repo_root: Path, editable: bool, console: Console) -> None:
    """Reinstall falconeye package after code update."""
    if editable:
        cmd = [sys.executable, "-m", "pip", "install", "-e", str(repo_root), "--quiet"]
    else:
        cmd = [sys.executable, "-m", "pip", "install", str(repo_root), "--quiet", "--upgrade"]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"pip install failed:\n{result.stderr.strip()}"
        )


def upgrade_command(console: Console) -> None:
    """
    Core logic for the upgrade command.

    Steps:
    1. Find install location and git repo root
    2. Show current version
    3. git fetch + pull from origin/main
    4. If updated: pip install to sync dependencies
    5. Show new version
    """
    console.print()
    console.print("[bold cyan]FalconEYE Upgrade[/bold cyan]")
    console.print()

    # --- Step 1: Find install location ---
    install_path = _get_install_location()
    if install_path is None:
        console.print("[red]✗[/red] Could not determine FalconEYE install location.")
        console.print()
        console.print("[yellow]To upgrade manually:[/yellow]")
        console.print("  git -C <falconeye-repo-dir> pull origin main")
        console.print("  pip install -e <falconeye-repo-dir>")
        return

    repo_root = _find_repo_root(install_path)
    if repo_root is None:
        console.print(
            f"[red]✗[/red] FalconEYE install at [cyan]{install_path}[/cyan] "
            "is not inside a git repository."
        )
        console.print()
        console.print("[yellow]To upgrade from source:[/yellow]")
        console.print("  git clone https://github.com/FalconEYE-ai/FalconEYE.git")
        console.print("  pip install -e FalconEYE/")
        return

    # --- Step 2: Show current version ---
    current_version = _get_current_version()
    console.print(f"  [dim]Install location:[/dim] [cyan]{repo_root}[/cyan]")
    console.print(f"  [dim]Current version: [/dim] [bold white]v{current_version}[/bold white]")
    console.print()

    # --- Step 3: git pull ---
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Fetching latest changes from origin/main...", total=None)
            changed, pull_output, incoming_commits = _run_git_pull(repo_root, console)
            progress.remove_task(task)

    except RuntimeError as e:
        console.print(f"[red]✗ Git error:[/red] {e}")
        console.print()
        console.print("[dim]Your installation is unchanged.[/dim]")
        return

    if not changed:
        console.print("[green]✓[/green] Already up to date — no changes to pull.")
        console.print(f"  [dim]Version:[/dim] [bold white]v{current_version}[/bold white]")
        console.print()
        return

    # Show what changed
    if incoming_commits:
        console.print("[green]✓[/green] New commits pulled:")
        for line in incoming_commits.splitlines()[:10]:
            console.print(f"  [dim]·[/dim] {line}")
        if len(incoming_commits.splitlines()) > 10:
            extra = len(incoming_commits.splitlines()) - 10
            console.print(f"  [dim]... and {extra} more commits[/dim]")
    else:
        console.print("[green]✓[/green] Code updated from origin/main")
    console.print()

    # --- Step 4: pip install ---
    editable = _is_editable_install(repo_root)
    install_mode = "editable" if editable else "standard"

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"Reinstalling dependencies ({install_mode} mode)...", total=None
            )
            _run_pip_install(repo_root, editable, console)
            progress.remove_task(task)

        console.print("[green]✓[/green] Dependencies updated successfully")

    except RuntimeError as e:
        console.print(f"[red]✗ pip install error:[/red] {e}")
        console.print()
        console.print(
            "[yellow]Warning:[/yellow] Code was updated but dependencies may be out of sync."
        )
        console.print(f"  Run manually: [cyan]pip install -e {repo_root}[/cyan]")
        return

    # --- Step 5: Show new version ---
    # Re-import to get updated version (may need new process, show from file)
    new_version = _get_current_version()
    # Try to read directly from updated __init__.py for accuracy
    try:
        init_file = repo_root / "src" / "falconeye" / "__init__.py"
        if init_file.exists():
            for line in init_file.read_text().splitlines():
                if "__version__" in line and "=" in line:
                    new_version = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
    except Exception:
        pass

    console.print()
    if new_version != current_version:
        console.print(Panel(
            f"[bold green]✓ Upgrade complete![/bold green]\n\n"
            f"  [dim]From:[/dim] [white]v{current_version}[/white]\n"
            f"  [dim]To:  [/dim] [bold green]v{new_version}[/bold green]",
            border_style="green",
            padding=(0, 2),
        ))
    else:
        console.print(Panel(
            f"[bold green]✓ Upgrade complete![/bold green]\n\n"
            f"  [dim]Version:[/dim] [bold white]v{new_version}[/bold white]\n"
            f"  [dim](Version number unchanged — code/deps may still have updated)[/dim]",
            border_style="green",
            padding=(0, 2),
        ))
    console.print()
