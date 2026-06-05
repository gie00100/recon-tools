#!/usr/bin/env python3
"""
Module 1: Multi-Source Subdomain Enumeration
Inspired by Nishantbhagat57's STdomains tool.

Passive sources (no API key): crt.sh, HackerTarget, AlienVault OTX, URLScan, RapidDNS
API sources (optional): SecurityTrails, Shodan, VirusTotal
DNS brute-force mode: Dictionary-based async subdomain guessing
"""

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Set

import aiohttp
import tldextract

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error,
    RateLimiter, write_lines, read_lines, elapsed_str, console, RICH_AVAILABLE
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box


class SubdomainEnumerator:
    """Multi-source async subdomain enumerator."""

    def __init__(self, domain: str, brute: bool = False, wordlist: str = None, permutations: bool = False):
        self.domain = domain.lower().strip()
        self.brute = brute
        self.permutations = permutations
        self.wordlist = wordlist or str(Config.SUBDOMAINS_WORDLIST)
        self.subdomains: Set[str] = set()
        self.vt_urls: set = set()
        self.sources_used: dict = {}
        self.wildcard_ips: Set[str] = set()
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT)
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=Config.HTTP_TIMEOUT)
            connector = aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": Config.USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _add_subdomains(self, subs: set, source: str):
        """Add validated subdomains from a source."""
        valid = set()
        for sub in subs:
            sub = sub.lower().strip().rstrip(".")
            # Must end with our target domain
            if sub.endswith(f".{self.domain}") or sub == self.domain:
                # Basic validation: no spaces, wildcards cleaned
                sub = sub.lstrip("*.")
                if sub and " " not in sub and len(sub) < 255:
                    valid.add(sub)
        count_before = len(self.subdomains)
        self.subdomains.update(valid)
        new_count = len(self.subdomains) - count_before
        self.sources_used[source] = len(valid)
        if valid:
            log_success(f"[{source}] Found {len(valid)} subs ({new_count} new) → Total: {len(self.subdomains)}")
        else:
            log_warning(f"[{source}] No results")

    # ── Passive Sources (No API Key) ─────────────────────────

    async def _enum_crtsh(self):
        """Query crt.sh certificate transparency logs."""
        source = "crt.sh"
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = Config.CRTSH_URL.format(domain=self.domain)
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    subs = set()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            subs.add(name.strip())
                    self._add_subdomains(subs, source)
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    async def _enum_hackertarget(self):
        """Query HackerTarget API."""
        source = "HackerTarget"
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = Config.HACKERTARGET_URL.format(domain=self.domain)
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "error" not in text.lower() and "api count" not in text.lower():
                        subs = set()
                        for line in text.strip().split("\n"):
                            if "," in line:
                                subs.add(line.split(",")[0].strip())
                        self._add_subdomains(subs, source)
                    else:
                        log_warning(f"[{source}] API limit or error")
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    async def _enum_alienvault(self):
        """Query AlienVault OTX passive DNS."""
        source = "AlienVault"
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = Config.ALIENVAULT_URL.format(domain=self.domain)
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = set()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "")
                        if hostname:
                            subs.add(hostname)
                    self._add_subdomains(subs, source)
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")


    async def _enum_rapiddns(self):
        """Scrape RapidDNS for subdomains."""
        source = "RapidDNS"
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = Config.RAPIDDNS_URL.format(domain=self.domain)
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Extract domains from the HTML table
                    pattern = r"(?:[\w-]+\.)*" + re.escape(self.domain)
                    matches = re.findall(pattern, text)
                    subs = set(matches)
                    self._add_subdomains(subs, source)
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    # ── API Sources (Require Key) ────────────────────────────

    async def _enum_securitytrails(self):
        """Query SecurityTrails API (requires API key)."""
        source = "SecurityTrails"
        if not Config.has_api_key("securitytrails"):
            log_info(f"[{source}] Skipped (no API key)")
            return
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = Config.SECURITYTRAILS_SUBDOMAINS_URL.format(domain=self.domain)
            headers = {"apikey": Config.SECURITYTRAILS_API_KEY}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = set()
                    for sub in data.get("subdomains", []):
                        subs.add(f"{sub}.{self.domain}")
                    self._add_subdomains(subs, source)
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    async def _enum_shodan(self):
        """Query Shodan DNS API (requires API key)."""
        source = "Shodan"
        if not Config.has_api_key("shodan"):
            log_info(f"[{source}] Skipped (no API key)")
            return
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = Config.SHODAN_DNS_URL.format(domain=self.domain, key=Config.SHODAN_API_KEY)
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = set()
                    for record in data.get("subdomains", []):
                        subs.add(f"{record}.{self.domain}")
                    self._add_subdomains(subs, source)
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    async def _enum_virustotal(self):
        """Query VirusTotal v2 API for subdomains and URLs."""
        source = "VirusTotal"
        if not Config.has_api_key("virustotal"):
            log_info(f"[{source}] Skipped (no API key)")
            return
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={Config.VIRUSTOTAL_API_KEY}&domain={self.domain}"
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = set()
                    
                    # Extract subdomains
                    for sub in data.get("subdomains", []):
                        subs.add(sub)
                    self._add_subdomains(subs, source)
                    
                    # Extract URLs (like virustotalx)
                    urls_found = 0
                    for u in data.get("undetected_urls", []):
                        if isinstance(u, list) and len(u) > 0:
                            self.vt_urls.add(u[0])
                            urls_found += 1
                    for u in data.get("detected_urls", []):
                        if isinstance(u, list) and len(u) > 0:
                            self.vt_urls.add(u[0])
                            urls_found += 1
                            
                    if urls_found > 0:
                        log_success(f"[{source}] Discovered {urls_found} associated URLs")
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    async def _enum_certspotter(self):
        """Query CertSpotter API for subdomains."""
        source = "CertSpotter"
        if not Config.has_api_key("certspotter"):
            log_info(f"[{source}] Skipped (no API key)")
            return
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            headers = {"Authorization": f"Bearer {Config.CERTSPOTTER_API_KEY}"}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = set()
                    for item in data:
                        for dns_name in item.get("dns_names", []):
                            if dns_name.endswith(self.domain):
                                subs.add(dns_name.lower())
                    self._add_subdomains(subs, source)
                else:
                    log_warning(f"[{source}] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[{source}] Error: {e}")

    # ── DNS Brute-Force & Permutations ───────────────────────

    async def _detect_wildcard(self):
        """Detect if the domain has a wildcard DNS record."""
        import socket
        import random
        import string
        
        rand_str = ''.join(random.choices(string.ascii_lowercase, k=12))
        test_host = f"{rand_str}.{self.domain}"
        
        try:
            loop = asyncio.get_event_loop()
            res = await loop.getaddrinfo(test_host, None)
            ips = {info[4][0] for info in res}
            if ips:
                self.wildcard_ips = ips
                log_warning(f"[DNS] Wildcard detected! Resolves to: {', '.join(ips)}")
        except Exception:
            self.wildcard_ips = set()

    def _generate_permutations(self) -> list:
        """Generate subdomain permutations based on passive results."""
        if not self.subdomains:
            return []
            
        words = ["api", "dev", "test", "staging", "prod", "internal", "admin", "vpn", "corp", "mail"]
        perms = set()
        
        for sub in self.subdomains:
            part = sub.replace(f".{self.domain}", "")
            if not part or part == self.domain:
                continue
                
            for w in words:
                perms.add(f"{part}-{w}")
                perms.add(f"{part}.{w}")
                perms.add(f"{w}-{part}")
                perms.add(f"{w}.{part}")
                
        return list(perms)

    async def _dns_bruteforce(self, words_to_try: list, source_name: str = "DNS-Brute"):
        """Brute-force subdomains using async DNS resolution."""
        if not words_to_try:
            log_warning(f"[{source_name}] No words to try")
            return

        log_info(f"[{source_name}] Resolving {len(words_to_try)} hosts...")

        import socket
        found = set()
        semaphore = asyncio.Semaphore(Config.DNS_CONCURRENCY)

        async def resolve(word):
            hostname = f"{word}.{self.domain}" if not word.endswith(self.domain) else word
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    res = await loop.getaddrinfo(hostname, None)
                    ips = {info[4][0] for info in res}
                    
                    # Wildcard check: if all resolved IPs match wildcard IPs, skip
                    if self.wildcard_ips and ips.issubset(self.wildcard_ips):
                        return
                        
                    found.add(hostname)
                except (socket.gaierror, OSError):
                    pass
                except Exception:
                    pass

        tasks = [resolve(w) for w in words_to_try]

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task(f"[cyan]{source_name}", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task)
        else:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._add_subdomains(found, source_name)

    # ── Main Enumeration ─────────────────────────────────────

    async def enumerate(self) -> Set[str]:
        """Run all enumeration sources concurrently."""
        start = time.time()
        banner("Subdomain Enumerator")
        log_info(f"Target: [bold]{self.domain}[/bold]" if RICH_AVAILABLE else f"Target: {self.domain}")

        # Run all passive sources concurrently
        passive_tasks = [
            self._enum_crtsh(),
            self._enum_hackertarget(),
            self._enum_rapiddns(),
            self._enum_certspotter(),
        ]

        # Add API sources (AlienVault & Shodan dropped — always return 403)
        api_tasks = [
            self._enum_securitytrails(),
            self._enum_virustotal(),
        ]

        log_info("Running passive enumeration sources...")
        await asyncio.gather(*passive_tasks, return_exceptions=True)

        log_info("Running API enumeration sources...")
        await asyncio.gather(*api_tasks, return_exceptions=True)

        # Wildcard check
        await self._detect_wildcard()

        # Optional brute-force
        if self.brute:
            log_info("Running DNS brute-force...")
            words = read_lines(self.wordlist)
            await self._dns_bruteforce(words, "DNS-Brute")
            
        # Optional permutations
        if self.permutations:
            log_info("Running Subdomain Permutations...")
            perms = self._generate_permutations()
            await self._dns_bruteforce(perms, "Permutations")

        await self.close()

        # Summary
        log_success(f"Enumeration complete in {elapsed_str(start)}")
        log_success(f"Total unique subdomains: [bold green]{len(self.subdomains)}[/bold green]"
                     if RICH_AVAILABLE else f"Total unique subdomains: {len(self.subdomains)}")

        # Source breakdown
        if RICH_AVAILABLE:
            table = Table(title="Source Breakdown", box=box.SIMPLE_HEAVY)
            table.add_column("Source", style="cyan")
            table.add_column("Found", justify="right", style="green")
            for src, count in sorted(self.sources_used.items(), key=lambda x: x[1], reverse=True):
                table.add_row(src, str(count))
            console.print(table)

        return self.subdomains


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Multi-source subdomain enumeration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_enum.py -d example.com
  python subdomain_enum.py -d example.com -o subs.txt --brute
  python subdomain_enum.py -d example.com --brute -w custom_wordlist.txt
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--brute", action="store_true", help="Enable DNS brute-force")
    parser.add_argument("--permutations", action="store_true", help="Enable subdomain permutations")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for brute-force")

    args = parser.parse_args()

    enumerator = SubdomainEnumerator(
        domain=args.domain,
        brute=args.brute,
        permutations=args.permutations,
        wordlist=args.wordlist,
    )

    results = asyncio.run(enumerator.enumerate())

    if args.output:
        write_lines(args.output, results)
    else:
        for sub in sorted(results):
            print(sub)


if __name__ == "__main__":
    main()
