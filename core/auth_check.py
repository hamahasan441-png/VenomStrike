"""Authorization checker — confirms user owns target before scanning."""
# For authorized security testing only.
import sys
from urllib.parse import urlparse
from core.logger import console, log_warning, log_error, log_info
from config import LEGAL_DISCLAIMER


def check_cli_authorization(target: str) -> bool:
    """CLI authorization check — prompt user to confirm ownership."""
    console.print(f"\n[bold red]{LEGAL_DISCLAIMER}[/bold red]")
    console.print(f"[bold yellow]Target:[/bold yellow] [cyan]{target}[/cyan]\n")
    
    response = input("Do you have explicit authorization to test this target? (yes/no): ").strip().lower()
    if response not in ("yes", "y"):
        log_error("Authorization denied. Scan aborted.")
        sys.exit(1)
    
    response2 = input("Do you confirm this is your own application or you have written permission? (yes/no): ").strip().lower()
    if response2 not in ("yes", "y"):
        log_error("Authorization not confirmed. Scan aborted.")
        sys.exit(1)
    
    log_info("Authorization confirmed. Proceeding with scan.")
    return True


def check_web_authorization(authorized: bool, target: str) -> bool:
    """Web UI authorization check — verify checkbox was checked."""
    if not authorized:
        return False
    return True


def validate_target_url(target: str) -> tuple:
    """Validate the target URL format."""
    if not target:
        return False, "Target URL is required"
    
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    
    try:
        parsed = urlparse(target)
        if not parsed.netloc:
            return False, "Invalid URL: no hostname"
        hostname = parsed.hostname or ""
        return True, target
    except Exception as e:
        return False, f"Invalid URL: {e}"
