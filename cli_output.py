"""
BugHunter AI v2 - CLI UI System
Hacker-style terminal interface with Rich library
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.rule import Rule
from rich.tree import Tree
from rich import box
from rich.align import Align
import time
from config import VERSION, TOOL_NAME, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO

console = Console()

# ─── Risk Colors ───────────────────────────────────────────────────────────────
RISK_COLORS = {
    RISK_CRITICAL: "bold red",
    RISK_HIGH:     "bold yellow",
    RISK_MEDIUM:   "yellow",
    RISK_LOW:      "cyan",
    RISK_INFO:     "blue",
}

RISK_ICONS = {
    RISK_CRITICAL: "🔴",
    RISK_HIGH:     "🟠",
    RISK_MEDIUM:   "🟡",
    RISK_LOW:      "🟢",
    RISK_INFO:     "🔵",
}


def print_banner():
    """Print the main ASCII art banner."""
    banner = """
██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"""

    subtitle = "           ██████╗ ██╗         ██╗   ██╗██████╗      ██╗   ██╗██████╗ \n           ██╔══██╗██║         ██║   ██║╚════██╗    ██║   ██║╚════██╗\n           ███████║██║         ██║   ██║ █████╔╝    ██║   ██║ █████╔╝\n           ██╔══██║██║         ╚██╗ ██╔╝██╔═══╝     ╚██╗ ██╔╝██╔═══╝ \n           ██║  ██║██║          ╚████╔╝ ███████╗     ╚████╔╝ ███████╗\n           ╚═╝  ╚═╝╚═╝          ╚═══╝  ╚══════╝      ╚═══╝  ╚══════╝"

    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print()
    console.print(Panel(
        Align.center(
            Text.from_markup(
                f"[bold green]🧠 AI-Powered Web Security Analysis Platform[/bold green]\n"
                f"[dim]Version {VERSION}  •  Ethical Hacking Only  •  SAFE MODE ON[/dim]\n"
                f"[yellow]⚠  For authorized testing only (bug bounty / CTF / owned systems)[/yellow]"
            )
        ),
        border_style="cyan",
        box=box.DOUBLE_EDGE,
        title="[bold cyan][ BugHunter AI v2 ][/bold cyan]",
        title_align="center",
    ))
    console.print()


def print_section(title: str, icon: str = "▸"):
    """Print a styled section separator."""
    console.print()
    console.print(Rule(f"[bold cyan]{icon} {title}[/bold cyan]", style="cyan"))


def print_info(msg: str):
    console.print(f"  [bold cyan]►[/bold cyan] {msg}")


def print_success(msg: str):
    console.print(f"  [bold green]✓[/bold green] {msg}")


def print_warning(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def print_error(msg: str):
    console.print(f"  [bold red]✗[/bold red] {msg}")


def print_finding(finding: dict):
    """Print a single finding with rich formatting."""
    risk  = finding.get("risk", RISK_INFO)
    color = RISK_COLORS.get(risk, "white")
    icon  = RISK_ICONS.get(risk, "●")

    title   = finding.get("title", "Unknown Finding")
    module  = finding.get("module", "")
    url     = finding.get("url", "")
    conf    = finding.get("confidence", 0)
    desc    = finding.get("description", "")
    remedy  = finding.get("remedy", "")
    evidence= finding.get("evidence", "")

    content = Text()
    content.append(f"  Module:     ", style="dim")
    content.append(f"{module}\n", style="white")
    content.append(f"  URL:        ", style="dim")
    content.append(f"{url}\n", style="underline blue")
    content.append(f"  Confidence: ", style="dim")
    content.append(f"{conf}%\n", style="bold white")
    content.append(f"  Detail:     ", style="dim")
    content.append(f"{desc}\n", style="white")
    if evidence:
        content.append(f"  Evidence:   ", style="dim")
        content.append(f"{evidence[:200]}\n", style="italic dim white")
    if remedy:
        content.append(f"  Fix:        ", style="dim")
        content.append(f"{remedy}", style="green")

    console.print(Panel(
        content,
        title=f"[{color}]{icon} [{risk}] {title}[/{color}]",
        border_style=color.replace("bold ", ""),
        box=box.ROUNDED,
    ))


def print_attack_surface(surface: dict):
    """Print discovered attack surface as a tree."""
    tree = Tree(
        f"[bold cyan]🌐 Attack Surface Map — {surface.get('base_url', '')}[/bold cyan]"
    )

    pages_branch = tree.add("[cyan]📄 Pages & Endpoints[/cyan]")
    for url in list(surface.get("pages", []))[:20]:
        pages_branch.add(f"[white]{url}[/white]")
    if len(surface.get("pages", [])) > 20:
        pages_branch.add(f"[dim]... and {len(surface['pages']) - 20} more[/dim]")

    forms_branch = tree.add("[yellow]📝 Forms[/yellow]")
    for form in surface.get("forms", [])[:10]:
        forms_branch.add(f"[white]{form.get('action', 'unknown')} ({form.get('method','GET').upper()})[/white]")

    params_branch = tree.add("[magenta]🔑 Parameters[/magenta]")
    for param in list(surface.get("parameters", set()))[:15]:
        params_branch.add(f"[white]{param}[/white]")

    apis_branch = tree.add("[green]⚡ API Endpoints[/green]")
    for api in list(surface.get("api_endpoints", []))[:10]:
        apis_branch.add(f"[white]{api}[/white]")

    js_branch = tree.add("[blue]📦 JavaScript Files[/blue]")
    for js in list(surface.get("js_files", []))[:8]:
        js_branch.add(f"[white]{js}[/white]")

    console.print()
    console.print(tree)
    console.print()


def print_scan_summary(findings: list, duration: float, target: str):
    """Print the final scan summary table."""
    counts = {RISK_CRITICAL: 0, RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_LOW: 0, RISK_INFO: 0}
    for f in findings:
        level = f.get("risk", RISK_INFO)
        counts[level] = counts.get(level, 0) + 1

    print_section("SCAN COMPLETE", "✅")

    table = Table(
        title=f"[bold white]Scan Summary — {target}[/bold white]",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Severity",  style="bold", min_width=12)
    table.add_column("Count",     style="bold white", justify="center", min_width=8)
    table.add_column("Status",    min_width=20)

    severity_map = [
        (RISK_CRITICAL, "bold red",    "🔴 Immediate action required"),
        (RISK_HIGH,     "bold yellow", "🟠 Fix as soon as possible"),
        (RISK_MEDIUM,   "yellow",      "🟡 Plan remediation"),
        (RISK_LOW,      "cyan",        "🟢 Low priority"),
        (RISK_INFO,     "blue",        "🔵 Informational"),
    ]
    for risk, color, status in severity_map:
        c = counts[risk]
        table.add_row(
            Text(f"{RISK_ICONS[risk]} {risk}", style=color),
            Text(str(c), style=color if c > 0 else "dim"),
            Text(status if c > 0 else "—", style=color if c > 0 else "dim"),
        )

    table.add_section()
    table.add_row(
        Text("TOTAL", style="bold white"),
        Text(str(len(findings)), style="bold white"),
        Text(f"Scan duration: {duration:.1f}s", style="dim"),
    )

    console.print(table)
    console.print()

    if counts[RISK_CRITICAL] > 0 or counts[RISK_HIGH] > 0:
        console.print(Panel(
            f"[bold red]⚠  {counts[RISK_CRITICAL]} Critical and {counts[RISK_HIGH]} High severity findings detected.[/bold red]\n"
            f"[yellow]Immediate review and remediation recommended before deployment.[/yellow]",
            border_style="red",
            box=box.HEAVY,
        ))
    else:
        console.print(Panel(
            "[bold green]✓ No critical or high severity issues detected.[/bold green]\n"
            "[dim]Continue monitoring and apply suggested improvements.[/dim]",
            border_style="green",
        ))

    console.print()


def print_module_status(module_name: str, status: str = "running"):
    """Show module execution status."""
    icons = {"running": "[bold cyan]⟳[/bold cyan]", "done": "[bold green]✓[/bold green]",
             "skip": "[dim]—[/dim]", "error": "[bold red]✗[/bold red]"}
    icon = icons.get(status, "●")
    console.print(f"  {icon}  [dim]{module_name}[/dim]")


def get_progress_bar(description: str = "Scanning"):
    """Return a styled progress bar context manager."""
    return Progress(
        SpinnerColumn(spinner_name="dots", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
        TextColumn("[bold white]{task.percentage:>3.0f}%[/bold white]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def confirm_scan(target: str, mode: str) -> bool:
    """Prompt for scan confirmation — safety control."""
    console.print()
    console.print(Panel(
        f"[bold yellow]Target:[/bold yellow] [white]{target}[/white]\n"
        f"[bold yellow]Mode:[/bold yellow]   [white]{mode.upper()}[/white]\n\n"
        f"[bold red]⚠  Confirm you have EXPLICIT authorization to scan this target.[/bold red]\n"
        f"[dim]Unauthorized scanning is illegal under CFAA, Computer Misuse Act, and similar laws.[/dim]",
        title="[bold yellow][ AUTHORIZATION REQUIRED ][/bold yellow]",
        border_style="yellow",
        box=box.HEAVY,
    ))
    response = console.input("[bold white]Do you have written authorization to scan this target? [y/N]: [/bold white]")
    return response.strip().lower() in ("y", "yes")
