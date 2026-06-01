#!/usr/bin/env python3
"""
Module: Headless JS Hooker
Spins up a headless browser to intercept outgoing XHR and Fetch requests,
capturing fully-formed dynamic API URLs that static analysis (regex) misses.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, write_lines, read_lines

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class HeadlessHooker:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.dynamic_endpoints = set()
        self.secrets = []

    async def _intercept_route(self, route):
        request = route.request
        url = request.url
        
        # We only care about XHR, Fetch, and Websockets
        if request.resource_type in ("fetch", "xhr", "websocket"):
            self.dynamic_endpoints.add(url)
            
        await route.continue_()

    async def _process_url(self, context, url: str):
        try:
            page = await context.new_page()
            # Intercept all requests
            await page.route("**/*", self._intercept_route)
            
            # Navigate and wait for network to become idle
            await page.goto(url, wait_until="networkidle", timeout=15000)
            
            # Close page to free resources
            await page.close()
        except Exception as e:
            # log_warning(f"Headless error on {url}: {e}")
            pass

    async def run(self) -> List[str]:
        import time
        start = time.time()
        banner("Headless JS Execution & Hooking")
        
        if not PLAYWRIGHT_AVAILABLE:
            log_error("Playwright is not installed. Skipping headless execution.")
            log_info("Install with: pip install playwright && playwright install chromium")
            return []
            
        log_info(f"Firing up headless Chromium to hook {len(self.urls)} targets...")
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                # Ignore HTTPS errors
                context = await browser.new_context(ignore_https_errors=True, user_agent=Config.USER_AGENT)
                
                # Limit concurrency to 10 headless tabs
                semaphore = asyncio.Semaphore(10)
                
                async def bounded_process(url):
                    async with semaphore:
                        await self._process_url(context, url)
                        
                tasks = [bounded_process(u) for u in self.urls]
                await asyncio.gather(*tasks)
                
                await browser.close()
        except Exception as e:
            log_error(f"Playwright crash: {e}")
            
        log_success(f"Intercepted {len(self.dynamic_endpoints)} fully-formed dynamic API requests.")
        return list(self.dynamic_endpoints)

def main():
    parser = argparse.ArgumentParser(description="Headless JS Hooker")
    parser.add_argument("-l", "--list", required=True, help="List of URLs to test")
    args = parser.parse_args()
    
    urls = read_lines(args.list)
    if not urls:
        print("No URLs provided.")
        return
        
    hooker = HeadlessHooker(urls)
    results = asyncio.run(hooker.run())
    
    if results:
        print("\n[+] Dynamic API Endpoints Intercepted:")
        for ep in results[:20]:
            print(f"  {ep}")

if __name__ == "__main__":
    main()
