#!/usr/bin/env python3
"""
Module: Historical JS Archeology
Queries the Wayback Machine for historical versions of JavaScript files
to find deprecated, forgotten API endpoints that are no longer in the UI.

Improvements:
- Broader JS file filter (chunk, bundle, index, runtime)
- Extracts ALL URL-like paths, not just /api/ or /v1/
- Extracts hardcoded secrets from historical snapshots
- Falls back to querying Wayback directly for *.js when no JS URLs given
"""

import argparse
import asyncio
import re
import sys
import ssl
from pathlib import Path
from typing import List, Set, Dict

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, write_lines, read_lines, RateLimiter

# Secret patterns to hunt for in historical JS
HISTORICAL_SECRET_PATTERNS = {
    "AWS_Key": r"(AKIA[0-9A-Z]{16})",
    "Firebase_Key": r"(AIza[0-9A-Za-z\-_]{35})",
    "Google_OAuth": r"([0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com)",
    "Slack_Token": r"(xox[bpoa]-[0-9]{10,13}-[a-zA-Z0-9-]+)",
    "Generic_Token": r"""(?:['"])((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{20,})(?:['"])""",
}


class HistoricalJS:
    def __init__(self, js_urls: List[str], domain: str = None):
        # Broader filter: accept chunk, bundle, index, runtime, webpack files too
        keywords = ["app", "main", "vendor", "chunk", "bundle", "index", "runtime", "webpack", "common"]
        self.js_urls = [u for u in js_urls if any(kw in u.lower() for kw in keywords)]
        self.domain = domain
        self.endpoints: Set[str] = set()
        self.secrets: List[Dict] = []
        self.rate_limiter = RateLimiter(5)  # Wayback is strict

    async def _discover_js_from_wayback(self, session: aiohttp.ClientSession) -> List[str]:
        """When no JS URLs are provided, query Wayback Machine for *.js files on the domain."""
        if not self.domain:
            return []
        
        log_info(f"No JS files from prior phases — querying Wayback Machine for {self.domain}/*.js ...")
        
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={self.domain}/*.js"
            f"&output=json&fl=original&filter=statuscode:200&collapse=urlkey&limit=50"
        )
        
        # Try both naked domain and www. prefix
        queries = [
            f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*.js&output=json&fl=original&filter=statuscode:200&collapse=urlkey&limit=50",
            f"http://web.archive.org/cdx/search/cdx?url=www.{self.domain}/*.js&output=json&fl=original&filter=statuscode:200&collapse=urlkey&limit=50",
        ]
        
        all_urls = set()
        for cdx_url in queries:
            try:
                await self.rate_limiter.acquire()
                async with session.get(cdx_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if len(data) > 1:
                            for row in data[1:]:
                                all_urls.add(row[0])
            except Exception as e:
                log_warning(f"Wayback JS discovery failed for query: {e}")
        
        if all_urls:
            urls = list(all_urls)
            log_success(f"Discovered {len(urls)} historical JS files from Wayback Machine.")
            return urls
        
        return []

    async def _fetch_wayback_snapshots(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        wayback_api = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={url}&output=json&fl=timestamp,original"
            f"&filter=statuscode:200&collapse=digest&limit=20"
        )
        try:
            await self.rate_limiter.acquire()
            async with session.get(wayback_api, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if len(data) > 1:
                        snapshots = data[1:]
                        # Take oldest, middle, and newest for good coverage
                        if len(snapshots) > 5:
                            selected = [
                                snapshots[0],
                                snapshots[len(snapshots) // 4],
                                snapshots[len(snapshots) // 2],
                                snapshots[3 * len(snapshots) // 4],
                                snapshots[-1],
                            ]
                        else:
                            selected = snapshots
                        
                        return [f"http://web.archive.org/web/{s[0]}id_/{s[1]}" for s in selected]
        except Exception:
            pass
        return []

    async def _extract_from_snapshot(self, session: aiohttp.ClientSession, snapshot_url: str):
        try:
            await self.rate_limiter.acquire()
            async with session.get(snapshot_url, timeout=15) as resp:
                if resp.status == 200:
                    content = await resp.text(errors="ignore")
                    
                    # ── Extract API-like paths (broad) ──
                    # Match quoted strings that look like URL paths
                    path_patterns = [
                        # Absolute paths starting with /
                        r"""['"](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-{}]+){1,8})['"]""",
                        # Full URLs with the target domain
                        r"""['"]https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_\-/{}]+)+['"]""",
                    ]
                    
                    for pattern in path_patterns:
                        paths = re.findall(pattern, content)
                        for p in paths:
                            # Filter out common false positives (CSS paths, image paths, node_modules)
                            if any(skip in p.lower() for skip in [
                                ".css", ".png", ".jpg", ".svg", ".gif", ".ico",
                                "node_modules", "webpack", ".woff", ".ttf",
                                "font-awesome", "bootstrap", "jquery",
                            ]):
                                continue
                            # Keep paths that look like API endpoints
                            if (len(p) > 3 and
                                "/" in p and
                                not p.startswith("//") and
                                p.count("/") >= 2):
                                self.endpoints.add(p)
                    
                    # ── Extract secrets ──
                    for secret_type, pattern in HISTORICAL_SECRET_PATTERNS.items():
                        for match in re.finditer(pattern, content):
                            value = match.group(1) if match.lastindex else match.group(0)
                            if not any(s["value"] == value for s in self.secrets):
                                self.secrets.append({
                                    "type": secret_type,
                                    "value": value,
                                    "source": snapshot_url,
                                })
        except Exception:
            pass

    async def run(self) -> List[str]:
        import time
        start = time.time()
        banner("Historical JS Archeology")
        
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
            # Fallback: if no JS URLs, discover them from Wayback
            if not self.js_urls:
                discovered = await self._discover_js_from_wayback(session)
                if discovered:
                    # Apply the same keyword filter
                    keywords = ["app", "main", "vendor", "chunk", "bundle", "index", "runtime", "webpack", "common"]
                    self.js_urls = [u for u in discovered if any(kw in u.lower() for kw in keywords)]
                    # If no matches after filtering, take first 10 anyway
                    if not self.js_urls:
                        self.js_urls = discovered[:10]
                        
            if not self.js_urls:
                log_warning("No JS files found to analyze. Skipping.")
                return []
                
            log_info(f"Querying Wayback Machine for {len(self.js_urls)} JS files...")
            
            # Get snapshots
            tasks = [self._fetch_wayback_snapshots(session, u) for u in self.js_urls[:30]]  # Cap at 30 files
            snapshot_lists = await asyncio.gather(*tasks)
            
            all_snapshots = []
            for slist in snapshot_lists:
                all_snapshots.extend(slist)
                
            if not all_snapshots:
                log_warning("No historical snapshots found.")
                return []
                
            log_info(f"Analyzing {len(all_snapshots)} historical snapshots...")
            
            # Download and extract
            extract_tasks = [self._extract_from_snapshot(session, s) for s in all_snapshots]
            await asyncio.gather(*extract_tasks)
            
        # Log results
        log_success(f"Historical JS Archeology completed. Extracted {len(self.endpoints)} historical endpoints.")
        
        if self.secrets:
            log_success(f"Found {len(self.secrets)} hardcoded secrets in historical JS!")
            for s in self.secrets[:5]:
                log_info(f"  [{s['type']}] {s['value'][:20]}... (from {s['source'].split('/')[-1][:30]})")
        
        return sorted(self.endpoints)

def main():
    parser = argparse.ArgumentParser(description="Historical JS Archeology")
    parser.add_argument("-l", "--list", help="List of JS URLs")
    parser.add_argument("-d", "--domain", help="Target domain (fallback Wayback query)")
    args = parser.parse_args()
    
    urls = []
    if args.list:
        urls = read_lines(args.list)
    
    if not urls and not args.domain:
        print("Provide --list or --domain.")
        return
        
    archeology = HistoricalJS(urls, domain=args.domain)
    results = asyncio.run(archeology.run())
    
    if results:
        print(f"\n[+] {len(results)} Historical API Endpoints Found:")
        for ep in results[:20]:
            print(f"  {ep}")

if __name__ == "__main__":
    main()
