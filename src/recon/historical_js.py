#!/usr/bin/env python3
"""
Module: Historical JS Archeology
Queries the Wayback Machine for historical versions of JavaScript files
to find deprecated, forgotten API endpoints that are no longer in the UI.
"""

import argparse
import asyncio
import re
import sys
import ssl
from pathlib import Path
from typing import List, Set

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, write_lines, read_lines, RateLimiter

class HistoricalJS:
    def __init__(self, js_urls: List[str]):
        # Only take core app files to avoid spamming Wayback Machine
        self.js_urls = [u for u in js_urls if "app" in u.lower() or "main" in u.lower() or "vendor" in u.lower()]
        self.endpoints = set()
        self.rate_limiter = RateLimiter(5) # Wayback is strict

    async def _fetch_wayback_snapshots(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        wayback_api = f"http://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=digest"
        try:
            await self.rate_limiter.acquire()
            async with session.get(wayback_api, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Skip the header row
                    if len(data) > 1:
                        # Get up to 3 snapshots from different years if possible, or just the oldest 3
                        snapshots = data[1:]
                        if len(snapshots) > 3:
                            # take oldest, middle, and newest
                            selected = [snapshots[0], snapshots[len(snapshots)//2], snapshots[-1]]
                        else:
                            selected = snapshots
                        
                        return [f"http://web.archive.org/web/{s[0]}id_/{s[1]}" for s in selected]
        except Exception:
            pass
        return []

    async def _extract_from_snapshot(self, session: aiohttp.ClientSession, snapshot_url: str):
        try:
            await self.rate_limiter.acquire()
            async with session.get(snapshot_url, timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text(errors="ignore")
                    # Simple regex for API paths
                    paths = re.findall(r"""['"](/[a-zA-Z0-9_\-/]+(?:/api/|/v1/|/v2/)[a-zA-Z0-9_\-/]+)['"]""", content)
                    for p in paths:
                        self.endpoints.add(p)
        except Exception:
            pass

    async def run(self) -> List[str]:
        import time
        start = time.time()
        banner("Historical JS Archeology")
        
        if not self.js_urls:
            log_warning("No core JS files (app.js, main.js) found in input. Skipping.")
            return []
            
        log_info(f"Querying Wayback Machine for {len(self.js_urls)} core JS files...")
        
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
            # Get snapshots
            tasks = [self._fetch_wayback_snapshots(session, u) for u in self.js_urls]
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
            
        log_success(f"Historical JS Archeology completed. Extracted {len(self.endpoints)} historical endpoints.")
        return list(self.endpoints)

def main():
    parser = argparse.ArgumentParser(description="Historical JS Archeology")
    parser.add_argument("-l", "--list", required=True, help="List of JS URLs")
    args = parser.parse_args()
    
    urls = read_lines(args.list)
    if not urls:
        print("No URLs provided.")
        return
        
    archeology = HistoricalJS(urls)
    results = asyncio.run(archeology.run())
    
    if results:
        print("\n[+] Historical API Endpoints Found:")
        for ep in list(results)[:20]:
            print(f"  {ep}")

if __name__ == "__main__":
    main()
