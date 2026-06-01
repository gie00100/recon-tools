#!/usr/bin/env python3
"""
Module 2: ASN/CIDR Hostname Discovery

Discovers hostnames from ASN numbers and CIDR blocks using:
- RIPE Stat API for ASN → CIDR resolution
- HackerTarget reverse DNS for CIDR → Hostname
- crt.sh for certificate-based hostname discovery per IP
"""

import argparse
import asyncio
import ipaddress
import json
import re
import sys
import time
from pathlib import Path
from typing import Set, List

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error,
    RateLimiter, write_lines, read_lines, elapsed_str,
    console, RICH_AVAILABLE
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn


class ASNCIDRFinder:
    """Discover hostnames from ASN numbers and CIDR blocks."""

    def __init__(self, asns: list = None, cidrs: list = None, filter_regex: str = None):
        self.asns = asns or []
        self.cidrs = cidrs or []
        self.filter_regex = re.compile(filter_regex) if filter_regex else None
        self.discovered_cidrs: Set[str] = set()
        self.hostnames: Set[str] = set()
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT)
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": Config.USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # ── ASN → CIDR Resolution ────────────────────────────────

    async def _resolve_asn_ripe(self, asn: str) -> Set[str]:
        """Resolve ASN to CIDR blocks using RIPE Stat API."""
        cidrs = set()
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            # Normalize ASN format
            asn_num = asn.upper().replace("AS", "")
            url = Config.RIPE_ASN_URL.format(asn=f"AS{asn_num}")

            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    prefixes = data.get("data", {}).get("prefixes", [])
                    for prefix in prefixes:
                        cidr = prefix.get("prefix", "")
                        if cidr:
                            cidrs.add(cidr)
                    log_success(f"[RIPE] AS{asn_num} → {len(cidrs)} CIDR blocks")
                else:
                    log_warning(f"[RIPE] HTTP {resp.status} for AS{asn_num}")
        except Exception as e:
            log_error(f"[RIPE] Error resolving AS{asn}: {e}")
        return cidrs

    async def _resolve_asn_hackertarget(self, asn: str) -> Set[str]:
        """Resolve ASN to CIDR blocks using HackerTarget API."""
        cidrs = set()
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            asn_num = asn.upper().replace("AS", "")
            url = f"https://api.hackertarget.com/aslookup/?q=AS{asn_num}"

            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "error" not in text.lower() and "api count" not in text.lower():
                        for line in text.strip().split("\n"):
                            line = line.strip()
                            # CIDR pattern: x.x.x.x/xx
                            if "/" in line and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", line):
                                cidrs.add(line)
                    log_success(f"[HackerTarget] AS{asn_num} → {len(cidrs)} CIDR blocks")
                else:
                    log_warning(f"[HackerTarget] HTTP {resp.status}")
        except Exception as e:
            log_error(f"[HackerTarget] Error: {e}")
        return cidrs

    # ── CIDR → Hostname Resolution ───────────────────────────

    async def _reverse_dns_ip(self, ip: str, semaphore: asyncio.Semaphore) -> Set[str]:
        """Reverse DNS lookup for a single IP."""
        hostnames = set()
        async with semaphore:
            try:
                import socket
                loop = asyncio.get_event_loop()
                result = await loop.getnameinfo((ip, 0), socket.NI_NAMEREQD)
                if result and result[0]:
                    hostname = result[0].strip().rstrip(".")
                    if hostname and not re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
                        hostnames.add(hostname)
            except Exception:
                pass
        return hostnames

    async def _reverse_dns_hackertarget(self, cidr: str) -> Set[str]:
        """Use HackerTarget reverse DNS for a CIDR block."""
        hostnames = set()
        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            # HackerTarget accepts CIDR ranges
            url = f"https://api.hackertarget.com/reversedns/?q={cidr}"
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "error" not in text.lower() and "api count" not in text.lower():
                        for line in text.strip().split("\n"):
                            if " " in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    hostname = parts[1].strip().rstrip(".")
                                    if hostname and "." in hostname:
                                        hostnames.add(hostname)
        except Exception as e:
            log_error(f"[ReverseDNS] Error for {cidr}: {e}")
        return hostnames

    async def _resolve_cidr_hostnames(self, cidr: str) -> Set[str]:
        """Find all hostnames for a CIDR block."""
        all_hostnames = set()

        # Method 1: HackerTarget reverse DNS
        ht_hosts = await self._reverse_dns_hackertarget(cidr)
        all_hostnames.update(ht_hosts)

        # Method 2: Native reverse DNS for smaller blocks (≤ /24)
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.num_addresses <= 256:  # /24 or smaller
                semaphore = asyncio.Semaphore(50)
                tasks = [self._reverse_dns_ip(str(ip), semaphore) for ip in network.hosts()]

                if RICH_AVAILABLE:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        TimeElapsedColumn(),
                    ) as progress:
                        task = progress.add_task(f"[cyan]Reverse DNS {cidr}", total=len(tasks))
                        for coro in asyncio.as_completed(tasks):
                            result = await coro
                            all_hostnames.update(result)
                            progress.advance(task)
                else:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in results:
                        if isinstance(result, set):
                            all_hostnames.update(result)
            else:
                log_info(f"[ReverseDNS] Skipping native rDNS for {cidr} (>{network.num_addresses} IPs)")
        except ValueError as e:
            log_error(f"Invalid CIDR: {cidr} — {e}")

        return all_hostnames

    # ── Main Discovery ───────────────────────────────────────

    async def discover(self) -> Set[str]:
        """Run full ASN/CIDR hostname discovery."""
        start = time.time()
        banner("ASN/CIDR Hostname Finder")

        # Step 1: Resolve ASNs to CIDRs
        if self.asns:
            log_info(f"Resolving {len(self.asns)} ASN(s) to CIDR blocks...")
            for asn in self.asns:
                ripe_cidrs = await self._resolve_asn_ripe(asn)
                ht_cidrs = await self._resolve_asn_hackertarget(asn)
                self.discovered_cidrs.update(ripe_cidrs)
                self.discovered_cidrs.update(ht_cidrs)
            log_success(f"Discovered {len(self.discovered_cidrs)} unique CIDR blocks from ASNs")

        # Add explicitly provided CIDRs
        for cidr in self.cidrs:
            self.discovered_cidrs.add(cidr.strip())

        if not self.discovered_cidrs:
            log_warning("No CIDR blocks to process")
            await self.close()
            return self.hostnames

        # Step 2: Resolve CIDRs to hostnames
        log_info(f"Resolving {len(self.discovered_cidrs)} CIDR blocks to hostnames...")
        for cidr in sorted(self.discovered_cidrs):
            log_info(f"Processing {cidr}...")
            hosts = await self._resolve_cidr_hostnames(cidr)
            self.hostnames.update(hosts)
            log_success(f"  {cidr} → {len(hosts)} hostnames")

        # Apply filter if specified
        if self.filter_regex:
            before = len(self.hostnames)
            self.hostnames = {h for h in self.hostnames if self.filter_regex.search(h)}
            log_info(f"Filter applied: {before} → {len(self.hostnames)} hostnames")

        await self.close()

        log_success(f"Discovery complete in {elapsed_str(start)}")
        log_success(f"Total unique hostnames: {len(self.hostnames)}")

        return self.hostnames


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ASN/CIDR Hostname Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asn_cidr_finder.py -a AS15169
  python asn_cidr_finder.py -a "AS15169,AS16509"
  python asn_cidr_finder.py -c "192.168.1.0/24"
  python asn_cidr_finder.py -a AS15169 -f "google\\.com$"
  python asn_cidr_finder.py -a AS15169 -o hostnames.txt
        """
    )
    parser.add_argument("-a", "--asn", help="ASN number(s), comma-separated (e.g., AS15169,AS16509)")
    parser.add_argument("-c", "--cidr", help="CIDR block(s), comma-separated (e.g., 8.8.8.0/24)")
    parser.add_argument("-f", "--filter", help="Regex filter for hostnames")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--hosts-format", action="store_true", help="Output in hosts file format (IP hostname)")

    args = parser.parse_args()

    if not args.asn and not args.cidr:
        parser.error("At least one of --asn or --cidr is required")

    asns = [a.strip() for a in args.asn.split(",")] if args.asn else []
    cidrs = [c.strip() for c in args.cidr.split(",")] if args.cidr else []

    finder = ASNCIDRFinder(asns=asns, cidrs=cidrs, filter_regex=args.filter)
    results = asyncio.run(finder.discover())

    if args.output:
        write_lines(args.output, results)
    else:
        for hostname in sorted(results):
            print(hostname)


if __name__ == "__main__":
    main()
