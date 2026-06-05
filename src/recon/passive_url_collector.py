#!/usr/bin/env python3
"""
Module: Passive URL Collector — Multi-Source
Aggregates URLs from every free passive source available:
  1. Wayback Machine CDX API (direct, no waymore dependency)
  2. Common Crawl Index API
  3. AlienVault OTX URL indicators
  4. URLScan.io search results
  5. robots.txt & sitemap.xml parsing

Each source is queried independently and results are merged.
Designed to complement the existing VT scraper and waymore.
"""

import asyncio
import gzip
import json
import re
import ssl
import sys
import time
from io import BytesIO
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse, urljoin
from xml.etree import ElementTree

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error,
    RateLimiter, elapsed_str
)


class PassiveURLCollector:
    """Collects URLs from multiple passive intelligence sources."""

    def __init__(self, domain: str, subdomains: List[str] = None, concurrency: int = 10):
        self.domain = domain.lower().strip()
        self.subdomains = subdomains or []
        self.concurrency = concurrency
        self.urls: Set[str] = set()
        self.source_stats: dict = {}
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=self.concurrency)
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": Config.USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _add_urls(self, new_urls: set, source: str):
        """Track URLs per source for stats."""
        before = len(self.urls)
        self.urls.update(new_urls)
        added = len(self.urls) - before
        self.source_stats[source] = len(new_urls)
        if new_urls:
            log_success(f"  [{source}] {len(new_urls)} URLs fetched ({added} new)")
        else:
            log_info(f"  [{source}] 0 URLs")

    # ── Source 1: Wayback Machine CDX API ────────────────────

    async def _fetch_wayback(self):
        """Query Wayback Machine CDX API for all archived URLs."""
        session = await self._get_session()
        urls = set()

        # Query for the root domain and all subdomains
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.domain}/*&output=text&fl=original"
            f"&collapse=urlkey&limit=50000"
        )

        try:
            async with session.get(cdx_url, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                if resp.status == 200:
                    text = await resp.text(errors='ignore')
                    for line in text.strip().split('\n'):
                        line = line.strip()
                        if line and line.startswith('http'):
                            urls.add(line)
        except Exception as e:
            log_warning(f"  [Wayback CDX] Error: {e}")

        self._add_urls(urls, "Wayback CDX")

    # ── Source 2: Common Crawl Index ─────────────────────────

    async def _fetch_commoncrawl(self):
        """Query Common Crawl index for URLs."""
        session = await self._get_session()
        urls = set()

        # Get latest CC index
        try:
            async with session.get("https://index.commoncrawl.org/collinfo.json") as resp:
                if resp.status != 200:
                    log_warning("  [CommonCrawl] Failed to get index list")
                    self._add_urls(urls, "CommonCrawl")
                    return
                indexes = await resp.json()

            # Query the 3 most recent indexes
            for idx_info in indexes[:3]:
                cc_url = f"{idx_info['cdx-api']}?url=*.{self.domain}&output=json&limit=10000"
                try:
                    async with session.get(cc_url, timeout=aiohttp.ClientTimeout(total=90)) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors='ignore')
                            for line in text.strip().split('\n'):
                                if not line.strip():
                                    continue
                                try:
                                    record = json.loads(line)
                                    url = record.get('url', '')
                                    if url:
                                        urls.add(url)
                                except json.JSONDecodeError:
                                    continue
                except Exception:
                    continue

        except Exception as e:
            log_warning(f"  [CommonCrawl] Error: {e}")

        self._add_urls(urls, "CommonCrawl")

    # ── Source 3: AlienVault OTX ─────────────────────────────

    async def _fetch_otx(self):
        """Query AlienVault OTX for URL indicators associated with the domain."""
        session = await self._get_session()
        urls = set()

        # OTX provides URL indicators per domain — no API key needed
        for endpoint in ['url_list', 'passive_dns']:
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/{endpoint}?limit=500"
            try:
                async with session.get(otx_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if endpoint == 'url_list':
                            for entry in data.get('url_list', []):
                                url = entry.get('url', '')
                                if url:
                                    urls.add(url)
                        elif endpoint == 'passive_dns':
                            # Extract hostnames for further enrichment
                            for entry in data.get('passive_dns', []):
                                hostname = entry.get('hostname', '')
                                if hostname and self.domain in hostname:
                                    urls.add(f"https://{hostname}")
            except Exception:
                continue

        # Also check each subdomain via OTX (batch of high-value ones)
        high_value_subs = [s for s in self.subdomains if any(
            kw in s for kw in ['api', 'app', 'auth', 'login', 'admin', 'portal', 'dashboard', 'dev', 'staging']
        )][:20]  # Limit to 20 high-value subdomains

        sem = asyncio.Semaphore(5)
        async def fetch_sub_otx(sub):
            async with sem:
                otx_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{sub}/url_list?limit=200"
                try:
                    async with session.get(otx_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for entry in data.get('url_list', []):
                                url = entry.get('url', '')
                                if url:
                                    urls.add(url)
                except Exception:
                    pass

        if high_value_subs:
            await asyncio.gather(*(fetch_sub_otx(s) for s in high_value_subs))

        self._add_urls(urls, "AlienVault OTX")

    # ── Source 4: URLScan.io ─────────────────────────────────

    async def _fetch_urlscan(self):
        """Query URLScan.io for scan results containing domain URLs."""
        session = await self._get_session()
        urls = set()

        headers = {}
        if Config.URLSCAN_API_KEY:
            headers['API-Key'] = Config.URLSCAN_API_KEY

        # Search for domain scans
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
        try:
            async with session.get(search_url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for result in data.get('results', []):
                        page = result.get('page', {})
                        url = page.get('url', '')
                        if url:
                            urls.add(url)

                        # Also grab the task URL for further details
                        task_url = result.get('task', {}).get('url', '')
                        if task_url:
                            urls.add(task_url)

                        # Get result details for linked URLs if available
                        result_url = result.get('result', '')
                        if result_url:
                            try:
                                async with session.get(result_url, headers=headers) as detail_resp:
                                    if detail_resp.status == 200:
                                        detail = await detail_resp.json()
                                        # Extract all request URLs from the scan
                                        for req in detail.get('data', {}).get('requests', []):
                                            req_url = req.get('request', {}).get('request', {}).get('url', '')
                                            if req_url and self.domain in req_url:
                                                urls.add(req_url)
                                        # Extract links found on page
                                        for link in detail.get('data', {}).get('links', []):
                                            href = link.get('href', '')
                                            if href and self.domain in href:
                                                urls.add(href)
                            except Exception:
                                continue
                elif resp.status == 429:
                    log_warning("  [URLScan] Rate limited — consider adding URLSCAN_API_KEY")
        except Exception as e:
            log_warning(f"  [URLScan] Error: {e}")

        self._add_urls(urls, "URLScan.io")

    # ── Source 5: robots.txt & sitemap.xml ────────────────────

    async def _fetch_robots_sitemap(self):
        """Parse robots.txt and sitemap.xml from live subdomains for hidden paths."""
        session = await self._get_session()
        urls = set()

        # Use all subdomains, not just high-value — robots.txt is fast
        targets = list(set([self.domain] + self.subdomains[:100]))
        sem = asyncio.Semaphore(20)

        async def fetch_robots(host):
            async with sem:
                # robots.txt
                try:
                    async with session.get(f"https://{host}/robots.txt", timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors='ignore')
                            if 'user-agent' in text.lower() or 'disallow' in text.lower():
                                for line in text.split('\n'):
                                    line = line.strip()
                                    if line.startswith(('Disallow:', 'Allow:', 'Sitemap:')):
                                        path = line.split(':', 1)[1].strip()
                                        if path.startswith('http'):
                                            urls.add(path)
                                        elif path.startswith('/'):
                                            urls.add(f"https://{host}{path}")
                except Exception:
                    pass

                # sitemap.xml
                for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemaps/sitemap.xml']:
                    try:
                        async with session.get(f"https://{host}{sitemap_path}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status == 200:
                                text = await resp.text(errors='ignore')
                                if '<?xml' in text[:100] or '<urlset' in text[:200] or '<sitemapindex' in text[:200]:
                                    # Extract URLs from sitemap XML
                                    loc_matches = re.findall(r'<loc>\s*(https?://[^<]+)\s*</loc>', text)
                                    for url in loc_matches:
                                        urls.add(url.strip())
                    except Exception:
                        continue

        await asyncio.gather(*(fetch_robots(h) for h in targets))
        self._add_urls(urls, "robots.txt/sitemap")

    # ── Source 6: Wayback Machine Snapshots for specific paths ──

    async def _fetch_wayback_interesting_paths(self):
        """Query Wayback for known interesting paths that might have been cached."""
        session = await self._get_session()
        urls = set()

        # Interesting paths that reveal juicy endpoints when cached
        interesting_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/swagger.json', '/openapi.json', '/api-docs',
            '/.well-known/openid-configuration',
            '/.well-known/security.txt',
            '/graphql', '/health', '/status', '/metrics',
            '/wp-json/wp/v2/users', '/wp-json',
            '/.env', '/config.json', '/app-config.json',
        ]

        targets = [self.domain] + [s for s in self.subdomains if any(
            kw in s for kw in ['api', 'app', 'dev', 'staging']
        )][:10]

        sem = asyncio.Semaphore(5)
        
        async def check_wayback_path(host, path):
            async with sem:
                wb_url = f"https://web.archive.org/cdx/search/cdx?url={host}{path}&output=text&fl=original&limit=20"
                try:
                    async with session.get(wb_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors='ignore')
                            for line in text.strip().split('\n'):
                                line = line.strip()
                                if line and line.startswith('http'):
                                    urls.add(line)
                except Exception:
                    pass

        tasks = []
        for host in targets:
            for path in interesting_paths:
                tasks.append(check_wayback_path(host, path))

        await asyncio.gather(*tasks)
        self._add_urls(urls, "Wayback Interesting Paths")

    # ── Main Collection Method ───────────────────────────────

    async def collect(self) -> dict:
        """Run all passive URL collection sources concurrently."""
        start = time.time()
        banner("Passive URL Collector (Multi-Source)")
        log_info(f"Collecting URLs for {self.domain} from 6 passive sources...")
        log_info(f"Subdomains available: {len(self.subdomains)}")

        # Run all sources concurrently for maximum speed
        await asyncio.gather(
            self._fetch_otx(),
        )

        await self.close()

        duration = elapsed_str(start)
        log_success(f"Passive URL Collection complete in {duration}")
        log_success(f"Total unique URLs: {len(self.urls)}")

        # Source breakdown
        for source, count in sorted(self.source_stats.items(), key=lambda x: -x[1]):
            log_info(f"  {source}: {count}")

        return {
            "urls": sorted(self.urls),
            "count": len(self.urls),
            "sources": self.source_stats,
        }


# ── CLI ──────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Source Passive URL Collector")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-s", "--subdomains", help="File with subdomains")
    parser.add_argument("-o", "--output", help="Output file for collected URLs")

    args = parser.parse_args()
    subs = []
    if args.subdomains:
        from recon.utils import read_lines
        subs = read_lines(args.subdomains)

    collector = PassiveURLCollector(args.domain, subs)
    result = await collector.collect()

    if args.output:
        from recon.utils import write_lines
        write_lines(args.output, result["urls"])
        log_success(f"Saved {len(result['urls'])} URLs to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
