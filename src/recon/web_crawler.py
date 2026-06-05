#!/usr/bin/env python3
"""
Active Web Crawler — BFS Link Extraction

Crawls live subdomains (depth 1, max 25 pages per domain) extracting
all links from HTML tags: <a>, <script>, <form>, <iframe>, <link>.

Catches endpoints that don't appear in JS files or passive archives —
admin panels, API docs, upload forms, config pages, etc.

Ported from BugBounty_Toolkit crawler.py, converted to async.
"""

import asyncio
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse, urljoin

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error,
    RateLimiter, read_lines, write_lines, elapsed_str, console, RICH_AVAILABLE
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# ── Configuration ────────────────────────────────────────────
MAX_DEPTH = 2
MAX_PAGES_PER_DOMAIN = 75

BORING_KEYWORDS = [
    '/jobs', '/careers', '/career', '/investor', '/investors', '/legal', '/about',
    '/help', '/privacy', '/terms', '/feedback', '/contact', '/faq', '/support',
    '/promo', '/events', '/sitemap', '/static', '/assets', '/public',
    'helpdesk', 'zendesk', 'salesforce', '/blog', '/news', '/press',
    '/wp-content/', '/wp-includes/', '/node_modules/',
]

STATIC_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.avi', '.mov', '.wav',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.tar.gz', '.rar', '.7z',
)

# Regex patterns to extract links from HTML (fast, no BeautifulSoup dependency)
HREF_REGEX = re.compile(r'''(?:href|src|action)=["']([^"']+)["']''', re.IGNORECASE)
LINK_REGEX = re.compile(r'''<(?:a|script|link|form|iframe|img|embed|object|source|video|audio|base)[^>]+(?:href|src|action|data|poster|data-href|data-url|data-src)=["']([^"'#]+)["']''', re.IGNORECASE)

# Additional URL extraction patterns
META_REFRESH_REGEX = re.compile(r'<meta[^>]+content=["'][^"]*url=([^"\';>]+)', re.IGNORECASE)
JS_URL_REGEX = re.compile(r'''["']((?:https?://|/(?:api|v[0-9]|graphql|auth|admin|internal|webhook|callback)[^"'\s]{3,}))["']''', re.IGNORECASE)
OG_URL_REGEX = re.compile(r'<meta[^>]+(?:property|name)=["']og:[^"']*["'][^>]+content=["'](https?://[^"']+)["']', re.IGNORECASE)
WINDOW_LOCATION_REGEX = re.compile(r'(?:window\.location|location\.href|location\.replace)\s*[=\(]\s*["\']([^"\'>]+)["\']', re.IGNORECASE)


class WebCrawler:
    """Async BFS web crawler for endpoint discovery."""

    def __init__(self, live_domains: List[str], output_dir: Path = None, concurrency: int = 15):
        self.live_domains = live_domains
        self.output_dir = output_dir or Path(".")
        self.concurrency = concurrency
        self.all_endpoints: Set[str] = set()
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT * 3)  # Faster for crawling
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=self.concurrency)
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

    def _is_interesting(self, url: str) -> bool:
        """Filter out static assets and boring paths."""
        url_lower = url.lower()
        try:
            path = urlparse(url_lower).path
            if path.endswith(STATIC_EXTENSIONS):
                return False
        except Exception:
            pass
        for kw in BORING_KEYWORDS:
            if kw in url_lower:
                return False
        return True

    async def _crawl_domain(self, base_domain: str) -> Set[str]:
        """BFS crawl a single domain up to MAX_DEPTH."""
        base_domain = base_domain.strip()
        if not base_domain:
            return set()

        start_url = f"https://{base_domain}"
        queue = [(start_url, 0)]
        visited = set()
        endpoints = set()
        pages_crawled = 0

        session = await self._get_session()

        while queue and pages_crawled < MAX_PAGES_PER_DOMAIN:
            current_url, depth = queue.pop(0)

            if current_url in visited:
                continue
            visited.add(current_url)
            endpoints.add(current_url)

            try:
                await self.rate_limiter.acquire()
                async with session.get(current_url, allow_redirects=True) as resp:
                    if resp.status != 200:
                        continue

                    ct = resp.headers.get("Content-Type", "")
                    if "text/html" not in ct:
                        continue

                    pages_crawled += 1
                    html = await resp.text(encoding="utf-8", errors="ignore")
                    html = html[:500_000]  # Cap at 500KB per page

                    # Extract links using multiple regex patterns (lightweight, no BS4)
                    raw_links = set(LINK_REGEX.findall(html))
                    raw_links.update(META_REFRESH_REGEX.findall(html))
                    raw_links.update(JS_URL_REGEX.findall(html))
                    raw_links.update(OG_URL_REGEX.findall(html))
                    raw_links.update(WINDOW_LOCATION_REGEX.findall(html))

                    for raw_link in raw_links:
                        raw_link = raw_link.split('#')[0].strip()  # Remove fragments
                        if not raw_link:
                            continue
                        if raw_link.startswith(('mailto:', 'javascript:', 'tel:', 'data:', '{', '${')):
                            continue

                        # Resolve relative URLs
                        full_url = urljoin(str(resp.url), raw_link)

                        if not self._is_interesting(full_url):
                            continue

                        endpoints.add(full_url)

                        # Queue for further crawling if on same subdomain and within depth
                        if depth < MAX_DEPTH:
                            try:
                                parsed = urlparse(full_url)
                                response_host = urlparse(str(resp.url)).netloc
                                if parsed.netloc in (base_domain, response_host):
                                    if full_url not in visited:
                                        queue.append((full_url, depth + 1))
                            except Exception:
                                pass

            except Exception:
                continue

        return endpoints

    async def crawl(self) -> Dict:
        """Crawl all live domains and collect endpoints."""
        start = time.time()
        banner("Active Web Crawler")
        log_info(f"Crawling {len(self.live_domains)} live domains (depth={MAX_DEPTH}, max_pages={MAX_PAGES_PER_DOMAIN})...")

        sem = asyncio.Semaphore(self.concurrency)
        domain_results = {}

        async def bounded_crawl(domain):
            async with sem:
                endpoints = await self._crawl_domain(domain)
                domain_results[domain] = endpoints
                self.all_endpoints.update(endpoints)

        tasks = [bounded_crawl(d) for d in self.live_domains]

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
            ) as progress:
                prog_task = progress.add_task("[cyan]Crawling domains", total=len(self.live_domains))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(prog_task)
        else:
            completed = 0
            for coro in asyncio.as_completed(tasks):
                await coro
                completed += 1
                if completed % 10 == 0:
                    log_info(f"  Crawled {completed}/{len(self.live_domains)} domains...")

        # Report top domains
        sorted_domains = sorted(domain_results.items(), key=lambda x: len(x[1]), reverse=True)
        for domain, eps in sorted_domains[:5]:
            if eps:
                log_success(f"  {domain}: {len(eps)} endpoints")

        # Save
        if self.all_endpoints:
            output_file = self.output_dir / "crawled_endpoints.txt"
            write_lines(str(output_file), sorted(self.all_endpoints))
            log_success(f"Crawler complete: {len(self.all_endpoints)} endpoints from {len(self.live_domains)} domains")
        else:
            log_info("No endpoints found by crawler.")

        await self.close()
        log_info(f"Crawling completed in {elapsed_str(start)}")

        return {
            "endpoints": sorted(self.all_endpoints),
            "count": len(self.all_endpoints),
        }


# ── CLI ──────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Active Web Crawler for Endpoint Discovery")
    parser.add_argument("-i", "--input", required=True, help="File with live domains")
    parser.add_argument("-o", "--output", default="./output", help="Output directory")
    parser.add_argument("--concurrency", type=int, default=15)
    args = parser.parse_args()

    domains = read_lines(args.input)
    if not domains:
        log_error("No domains to crawl.")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    crawler = WebCrawler(domains, output_dir, args.concurrency)
    await crawler.crawl()


if __name__ == "__main__":
    asyncio.run(main())
