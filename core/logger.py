"""Colored terminal logger using rich library."""
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
import logging

console = Console()

SKULL_BANNER = r"""
 ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
  ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████║   ██║   ██║  ██║██║██║  ██╗███████╗
   ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
                    ⚡ v4.0 QUANTUM EDITION ⚡ Advanced Security Testing & Vulnerability Debugging Framework
                         FOR AUTHORIZED TESTING OF YOUR OWN APPLICATIONS ONLY
"""

def print_banner():
    """Print the VenomStrike ASCII banner."""
    console.print(f"[bold red]{SKULL_BANNER}[/bold red]")
    console.print(Panel("[bold yellow]⚠️  FOR AUTHORIZED TESTING ONLY — Ensure you have permission[/bold yellow]", 
                       border_style="red"))

def log_info(msg):
    console.print(f"[bold blue][*][/bold blue] {msg}")

def log_success(msg):
    console.print(f"[bold green][+][/bold green] {msg}")

def log_warning(msg):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")

def log_error(msg):
    console.print(f"[bold red][-][/bold red] {msg}")

def log_critical(msg):
    console.print(f"[bold red on white][CRITICAL][/bold red on white] [bold red]{msg}[/bold red]")

def log_finding(vuln_type, url, param, severity, confidence):
    """Log a security finding."""
    severity_color = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Info": "white"
    }.get(severity, "white")
    console.print(
        f"[{severity_color}][{severity}][/{severity_color}] "
        f"[bold white]{vuln_type}[/bold white] "
        f"@ [cyan]{url}[/cyan] "
        f"(param: [yellow]{param}[/yellow]) "
        f"[green]Confidence: {confidence}%[/green]"
    )

def log_module(module_name):
    console.print(f"\n[bold red]▶[/bold red] Running module: [bold white]{module_name}[/bold white]")

def log_debug(msg):
    console.print(f"[dim][DEBUG] {msg}[/dim]")
