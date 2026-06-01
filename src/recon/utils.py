"""
Recon Toolkit - Shared Utilities
Colored logging, file I/O, domain parsing, async helpers.
"""

import asyncio
import io
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import tldextract

# ── Force UTF-8 on Windows ────────────────────────────────────
if sys.platform == "win32":
    # Ensure the Windows console can handle UTF-8 output
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ── Rich Console ──────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

if RICH_AVAILABLE:
    # Force Rich to use UTF-8 and the file-based fallback for safe output
    try:
        console = Console(force_terminal=True)
    except Exception:
        console = Console()
else:
    console = None


# ── Logging Helpers ───────────────────────────────────────────

def banner(tool_name: str, version: str = "1.0"):
    """Print a styled banner for the tool."""
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold cyan]{tool_name}[/bold cyan] v{version}\n"
            f"[dim]Automated Bug Bounty Reconnaissance Toolkit[/dim]",
            border_style="bright_blue",
            box=box.DOUBLE_EDGE,
            padding=(1, 4),
        ))
    else:
        print(f"\n{'='*50}")
        print(f"  {tool_name} v{version}")
        print(f"  Automated Bug Bounty Recon Toolkit")
        print(f"{'='*50}\n")


def log_info(msg: str):
    """Log an info message."""
    if RICH_AVAILABLE:
        console.print(f"  [bold blue][i][/bold blue]  {msg}")
    else:
        print(f"[INFO] {msg}")


def log_success(msg: str):
    """Log a success message."""
    if RICH_AVAILABLE:
        console.print(f"  [bold green][+][/bold green]  {msg}")
    else:
        print(f"[OK] {msg}")


def log_warning(msg: str):
    """Log a warning message."""
    if RICH_AVAILABLE:
        console.print(f"  [bold yellow][!][/bold yellow]  {msg}")
    else:
        print(f"[WARN] {msg}")


def log_error(msg: str):
    """Log an error message."""
    if RICH_AVAILABLE:
        console.print(f"  [bold red][x][/bold red]  {msg}")
    else:
        print(f"[ERR] {msg}", file=sys.stderr)


def log_finding(msg: str):
    """Log a finding / highlight message."""
    if RICH_AVAILABLE:
        console.print(f"  [bold magenta][*][/bold magenta]  {msg}")
    else:
        print(f"[FIND] {msg}")


def log_phase(phase: int, total: int, name: str):
    """Log a pipeline phase header."""
    if RICH_AVAILABLE:
        console.print(f"\n  [bold white on blue] Phase {phase}/{total} [/bold white on blue] [bold]{name}[/bold]")
    else:
        print(f"\n--- Phase {phase}/{total}: {name} ---")


# ── Domain Parsing ────────────────────────────────────────────

def extract_domain_parts(url_or_domain: str) -> dict:
    """
    Extract domain components using tldextract.
    Returns: {subdomain, domain, suffix, registered_domain, fqdn}
    """
    # Strip scheme if present
    if "://" in url_or_domain:
        parsed = urlparse(url_or_domain)
        hostname = parsed.hostname or url_or_domain
    else:
        hostname = url_or_domain.strip().rstrip(".")

    ext = tldextract.extract(hostname)
    return {
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": ext.registered_domain,
        "fqdn": ext.fqdn,
    }


def get_registered_domain(url_or_domain: str) -> str:
    """Get the registered domain (e.g., example.com) from a URL or hostname."""
    parts = extract_domain_parts(url_or_domain)
    return parts["registered_domain"]


def decompose_hostname(hostname: str) -> list:
    """
    Decompose a hostname into all meaningful substrings for backup-gen.
    Example: dev.app.example.com → [dev, dev-app, dev.app, dev-app-example, ...]
    Inspired by Nishantbhagat57's backup-gen logic.
    """
    ext = tldextract.extract(hostname)
    parts_list = []

    # Get subdomain parts
    if ext.subdomain:
        sub_parts = ext.subdomain.split(".")
    else:
        sub_parts = []

    # Add the base domain name
    if ext.domain:
        parts_list.append(ext.domain)

    # Add the suffix parts
    if ext.suffix:
        parts_list.append(ext.suffix.replace(".", "-"))

    # Build combinations from subdomain parts (dash-separated)
    dash_combos = []
    dot_combos = []
    for i in range(len(sub_parts)):
        # Progressive dash-joined
        dash_combos.append("-".join(sub_parts[:i + 1]))
        # Progressive dot-joined
        dot_combos.append(".".join(sub_parts[:i + 1]))

    # Also include full hostname variants with domain
    all_parts_with_domain = sub_parts + [ext.domain]
    if ext.suffix:
        all_parts_with_domain.extend(ext.suffix.split("."))

    full_dash_combos = []
    full_dot_combos = []
    for i in range(len(all_parts_with_domain)):
        full_dash_combos.append("-".join(all_parts_with_domain[:i + 1]))
        full_dot_combos.append(".".join(all_parts_with_domain[:i + 1]))

    # Combine all unique results
    results = set()
    results.update(dash_combos)
    results.update(dot_combos)
    results.update(full_dash_combos)
    results.update(full_dot_combos)
    results.add(ext.domain)

    # Add suffix as standalone if multi-part TLD
    if ext.suffix and "." in ext.suffix:
        for part in ext.suffix.split("."):
            results.add(part)

    # Remove empty strings
    results.discard("")

    return sorted(results)


# ── File I/O ──────────────────────────────────────────────────

def read_lines(filepath: str) -> list:
    """Read non-empty, stripped lines from a file."""
    path = Path(filepath)
    if not path.exists():
        log_error(f"File not found: {filepath}")
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def write_lines(filepath: str, lines, deduplicate: bool = True):
    """Write lines to a file, optionally deduplicating."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    if deduplicate:
        lines = sorted(set(lines))
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")
    log_success(f"Wrote {len(lines)} lines → {filepath}")


def append_lines(filepath: str, lines):
    """Append lines to a file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")


def count_lines(filepath: str) -> int:
    """Count lines in a file."""
    path = Path(filepath)
    if not path.exists():
        return 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


# ── Async Helpers ─────────────────────────────────────────────

class RateLimiter:
    """Simple async rate limiter using token bucket algorithm."""

    def __init__(self, rate: float = 5.0):
        """
        Args:
            rate: Maximum requests per second.
        """
        self.rate = rate
        self.interval = 1.0 / rate
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until a request is allowed."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self._last_request = time.monotonic()


class AsyncSemaphoreRateLimiter:
    """Combines semaphore (concurrency) with rate limiting."""

    def __init__(self, concurrency: int = 10, rate: float = 5.0):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limiter = RateLimiter(rate)

    async def __aenter__(self):
        await self.semaphore.acquire()
        await self.rate_limiter.acquire()
        return self

    async def __aexit__(self, *args):
        self.semaphore.release()


# ── Timestamp ─────────────────────────────────────────────────

def timestamp() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def elapsed_str(start_time: float) -> str:
    """Return human-readable elapsed time."""
    elapsed = time.time() - start_time
    if elapsed < 60:
        return f"{elapsed:.1f}s"
    elif elapsed < 3600:
        return f"{elapsed / 60:.1f}m"
    else:
        return f"{elapsed / 3600:.1f}h"

# ── Notifications ─────────────────────────────────────────────

async def send_discord_alert(webhook_url: str, title: str, description: str, color: int = 16711680):
    """
    Send an asynchronous alert to a Discord webhook.
    Args:
        webhook_url: The Discord webhook URL.
        title: Alert title.
        description: Alert body text.
        color: Embed color (default red: 16711680).
    """
    if not webhook_url:
        return
        
    import aiohttp
    payload = {
        "embeds": [{
            "title": title,
            "description": description[:4000],  # Discord limit
            "color": color,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as resp:
                if resp.status not in (200, 204):
                    log_error(f"Failed to send Discord alert: HTTP {resp.status}")
    except Exception as e:
        log_error(f"Discord alert error: {e}")
