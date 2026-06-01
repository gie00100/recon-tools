#!/usr/bin/env python3
"""
Module 4: Backup File Wordlist Generator
Direct port & enhancement backup-gen + fback tools.

Generates target-specific backup file fuzzing wordlists by decomposing
hostnames into meaningful substrings and combining with backup extensions.
"""

import argparse
import asyncio
import ssl
import sys
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse

import aiohttp
import tldextract

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error, log_finding,
    decompose_hostname, read_lines, write_lines, console, RICH_AVAILABLE,
    RateLimiter
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn


# ── Built-in Default Extensions ──────────────────────────────
DEFAULT_EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".save", ".copy",
    ".tmp", ".temp", ".swp", ".db", ".sql", ".sql.gz",
    ".sql.zip", ".sql.tar.gz", ".tar", ".tar.gz", ".tar.bz2",
    ".tgz", ".gz", ".zip", ".rar", ".7z", ".war",
    ".log", ".conf", ".config", ".cfg", ".ini", ".env",
    ".yaml", ".yml", ".xml", ".json", ".dump",
    "~", ".1", ".0", "_backup", "_bak", "_old",
]


class BackupGenerator:
    """Generate backup file wordlists from URLs/hostnames."""

    def __init__(self, urls: list, extensions: list = None, full_url: bool = False, active: bool = False):
        self.urls = urls
        self.extensions = extensions or DEFAULT_EXTENSIONS
        self.full_url = full_url or active  # Active requires full URLs
        self.active = active
        self.results: List[str] = []
        self.live_backups: List[str] = []
        
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT * 10)
        self._session = None
        self._soft_404_signatures = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=50, resolver=aiohttp.ThreadedResolver())
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": Config.USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _parse_hostname(self, url_or_host: str) -> tuple:
        """Extract hostname and scheme from URL or hostname string."""
        url_or_host = url_or_host.strip()
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            return parsed.hostname or "", parsed.scheme
        return url_or_host, "https"

    def _generate_for_hostname(self, hostname: str, scheme: str = "https") -> Set[str]:
        """Generate all backup filename combinations for a hostname."""
        results = set()

        # Decompose hostname into meaningful parts
        parts = decompose_hostname(hostname)

        # Generate combinations: part + extension
        for part in parts:
            for ext in self.extensions:
                ext = ext.strip()
                if not ext:
                    continue

                # Ensure extension starts with . or _ or - or ~
                combo = f"{part}{ext}"

                if self.full_url:
                    # Include path-based variants
                    results.add(f"{scheme}://{hostname}/{combo}")
                else:
                    results.add(combo)

        # Also add hostname-based common backup patterns
        ext_obj = tldextract.extract(hostname)
        base_domain = ext_obj.domain

        # Common web backup patterns
        common_patterns = [
            f"{base_domain}.sql",
            f"{base_domain}.sql.gz",
            f"{base_domain}.sql.zip",
            f"{base_domain}_db.sql",
            f"{base_domain}_database.sql",
            f"{base_domain}_dump.sql",
            f"{base_domain}.tar.gz",
            f"{base_domain}.zip",
            f"{base_domain}_backup.zip",
            f"{base_domain}_backup.tar.gz",
            f"{base_domain}.rar",
            f"backup.zip",
            f"backup.tar.gz",
            f"backup.sql",
            f"db.sql",
            f"database.sql",
            f"dump.sql",
            f"site.zip",
            f"site.tar.gz",
            f"www.zip",
            f"www.tar.gz",
            f"web.zip",
            f"public_html.zip",
            f"htdocs.zip",
            f"httpdocs.zip",
            f"wp-content.zip",
            f".env",
            f".env.bak",
            f".env.old",
            f".env.local",
            f".env.production",
            f".env.staging",
            f".git/config",
            f".git/HEAD",
            f".svn/entries",
            f".DS_Store",
            f"wp-config.php.bak",
            f"wp-config.php.old",
            f"wp-config.php~",
            f"web.config.bak",
            f"web.config.old",
            f"config.php.bak",
            f"configuration.php.bak",
            f".htaccess.bak",
            f".htpasswd",
            f"robots.txt.bak",
        ]

        for pattern in common_patterns:
            if self.full_url:
                results.add(f"{scheme}://{hostname}/{pattern}")
            else:
                results.add(pattern)

        return results

    async def _detect_soft_404(self, session: aiohttp.ClientSession, base_url: str):
        """Detect the signature of a non-existent page for a host."""
        parsed = urlparse(base_url)
        host = parsed.netloc
        scheme = parsed.scheme
        random_path = "/nonexistent_f8u3j4nf8.txt"
        test_url = f"{scheme}://{host}{random_path}"
        
        try:
            async with session.head(test_url, allow_redirects=False) as resp:
                self._soft_404_signatures[host] = {
                    "status": resp.status,
                    "length": int(resp.headers.get("Content-Length", -1))
                }
        except Exception:
            self._soft_404_signatures[host] = {"status": 0, "length": -1}

    async def _probe_backup(self, url: str, semaphore: asyncio.Semaphore) -> str:
        """Probe a single backup URL."""
        async with semaphore:
            await self.rate_limiter.acquire()
            parsed = urlparse(url)
            host = parsed.netloc
            
            try:
                session = await self._get_session()
                # Use HEAD request for speed
                async with session.head(url, allow_redirects=False) as resp:
                    if resp.status in (200, 206, 301, 302, 403):
                        # Filter Soft 404s
                        sig = self._soft_404_signatures.get(host, {})
                        c_len = int(resp.headers.get("Content-Length", -1))
                        
                        if resp.status == sig.get("status") and c_len == sig.get("length") and c_len != -1:
                            return "" # It's a soft 404
                            
                        # If it's HTML, it's probably not a real backup file
                        content_type = resp.headers.get("Content-Type", "").lower()
                        if "text/html" in content_type:
                            # Verify if it's actually an HTML document/redirect (SPA routing fallback)
                            # Perform a GET request to read the start of the body
                            async with session.get(url, allow_redirects=False) as get_resp:
                                try:
                                    content = await get_resp.content.read(2048)
                                    text_content = content.decode('utf-8', errors='ignore').strip().lower()
                                    html_indicators = ["<!doctype html", "<html", "<head", "<body", "<script", "<title", "<div"]
                                    if any(ind in text_content for ind in html_indicators):
                                        return "" # False positive HTML page redirect
                                except Exception:
                                    pass
                            
                            # If it's not a text/log/ini/env file, but still HTML, skip it
                            if not url.endswith((".txt", ".env", ".log", ".ini")):
                                return ""
                            
                        log_finding(f"[LIVE BACKUP] [{resp.status}] {url} ({c_len} bytes)")
                        return url
            except Exception:
                pass
            return ""

    async def run_active_probe(self):
        """Actively probe the generated URLs."""
        if not self.results:
            return
            
        log_info(f"Actively probing {len(self.results)} generated backup URLs...")
        
        # Detect soft 404s per host
        session = await self._get_session()
        hosts = set(f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in self.results)
        await asyncio.gather(*(self._detect_soft_404(session, h) for h in hosts))
        
        semaphore = asyncio.Semaphore(50)
        tasks = [self._probe_backup(url, semaphore) for url in self.results]
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Probing Backups", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    if res:
                        self.live_backups.append(res)
                    progress.advance(task)
        else:
            res_list = await asyncio.gather(*tasks)
            self.live_backups = [r for r in res_list if r]

    async def generate(self) -> List[str]:
        """Generate backup wordlist for all input URLs."""
        banner("Backup File Wordlist Generator")

        all_results = set()
        for url in self.urls:
            hostname, scheme = self._parse_hostname(url)
            if not hostname:
                continue

            log_info(f"Processing: {hostname}")
            combos = self._generate_for_hostname(hostname, scheme)
            all_results.update(combos)
            log_success(f"  Generated {len(combos)} combinations")

        self.results = sorted(all_results)
        log_success(f"Total unique backup paths: {len(self.results)}")
        
        if self.active:
            await self.run_active_probe()
            log_success(f"Total LIVE backup paths: {len(self.live_backups)}")
            return self.live_backups
            
        return self.results


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Backup File Wordlist Generator (inspired by backup-gen + fback)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python backup_gen.py urls.txt extensions.txt
  python backup_gen.py urls.txt extensions.txt --full
  python backup_gen.py -u urls.txt -o wordlist.txt
  echo "https://dev.app.example.com" | python backup_gen.py -
        """
    )
    parser.add_argument("urls_file", nargs="?", help="File with URLs (one per line), or - for stdin")
    parser.add_argument("extensions_file", nargs="?", help="File with backup extensions (one per line)")
    parser.add_argument("-u", "--urls", help="Alternative: URL file path")
    parser.add_argument("-e", "--extensions", help="Alternative: Extensions file path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--full", action="store_true", help="Output full URLs with scheme")
    parser.add_argument("-t", "--target", help="Single target URL/hostname")
    parser.add_argument("--active", action="store_true", help="Actively probe generated backup URLs")

    args = parser.parse_args()

    # Determine URL source
    urls = []
    url_file = args.urls_file or args.urls
    if args.target:
        urls = [args.target]
    elif url_file == "-":
        urls = [line.strip() for line in sys.stdin if line.strip()]
    elif url_file:
        urls = read_lines(url_file)
    else:
        parser.error("Provide URLs via file, --target, or stdin (-)")

    # Determine extensions
    extensions = None
    ext_file = args.extensions_file or args.extensions
    if ext_file:
        extensions = read_lines(ext_file)

    generator = BackupGenerator(urls=urls, extensions=extensions, full_url=args.full, active=args.active)
    results = asyncio.run(generator.generate())

    if args.output:
        write_lines(args.output, results, deduplicate=False)  # Already sorted
    else:
        for line in results:
            print(line)


if __name__ == "__main__":
    main()
