#!/usr/bin/env python3
"""
Module: Headless JS Hooker
Spins up a headless browser to intercept outgoing XHR and Fetch requests,
capturing fully-formed dynamic API URLs that static analysis (regex) misses.

Now includes:
- Click interactions (buttons, links) to trigger more XHR calls
- Page scrolling to trigger lazy-loaded content
- localStorage/sessionStorage extraction
- Standalone mode with domain-based target generation
"""

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, write_lines, read_lines

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class HeadlessHooker:
    def __init__(self, urls: List[str], domain: str = None):
        self.urls = urls
        self.domain = domain
        self.dynamic_endpoints = set()
        self.storage_findings = []
        self.api_calls = []  # Full request details

    async def _intercept_route(self, route):
        request = route.request
        url = request.url
        
        # Capture XHR, Fetch, and Websocket requests with full details
        if request.resource_type in ("fetch", "xhr", "websocket"):
            self.dynamic_endpoints.add(url)
            self.api_calls.append({
                "url": url,
                "method": request.method,
                "resource_type": request.resource_type,
                "headers": dict(request.headers) if request.headers else {},
            })
            
        await route.continue_()

    async def _extract_storage(self, page) -> Dict[str, Any]:
        """Extract localStorage and sessionStorage contents."""
        storage = {"localStorage": {}, "sessionStorage": {}}
        try:
            local_data = await page.evaluate("""() => {
                let data = {};
                for (let i = 0; i < localStorage.length; i++) {
                    let key = localStorage.key(i);
                    data[key] = localStorage.getItem(key);
                }
                return data;
            }""")
            storage["localStorage"] = local_data or {}
        except Exception:
            pass
        
        try:
            session_data = await page.evaluate("""() => {
                let data = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    let key = sessionStorage.key(i);
                    data[key] = sessionStorage.getItem(key);
                }
                return data;
            }""")
            storage["sessionStorage"] = session_data or {}
        except Exception:
            pass
        
        return storage

    async def _click_interactive_elements(self, page):
        """Click buttons and links to trigger dynamic API calls."""
        try:
            # Scroll down to trigger lazy loading
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
            await asyncio.sleep(0.5)
            
            # Find and click visible buttons (not navigation links that leave the page)
            buttons = await page.query_selector_all("button:visible, [role='button']:visible, input[type='submit']:visible")
            for btn in buttons[:5]:  # Limit to 5 to avoid excessive interaction
                try:
                    # Only click if it looks like an API trigger, not a page navigation
                    text = await btn.inner_text()
                    text_lower = text.lower().strip() if text else ""
                    # Skip destructive or navigation buttons
                    skip_words = ["delete", "remove", "logout", "sign out", "close", "cancel", "cookie"]
                    if any(w in text_lower for w in skip_words):
                        continue
                    await btn.click(timeout=3000)
                    await asyncio.sleep(0.5)
                except Exception:
                    pass
                    
        except Exception:
            pass

    async def _process_url(self, context, url: str) -> Dict:
        """Process a single URL — load, interact, and extract."""
        result = {"url": url, "endpoints": [], "storage": {}}
        try:
            page = await context.new_page()
            
            # Intercept all requests
            await page.route("**/*", self._intercept_route)
            
            # Track endpoints found specifically from this URL
            pre_count = len(self.dynamic_endpoints)
            
            # Navigate and wait for network to become idle
            await page.goto(url, wait_until="networkidle", timeout=20000)
            
            # Click interactive elements to trigger more API calls
            await self._click_interactive_elements(page)
            
            # Wait a moment for any delayed XHRs
            await asyncio.sleep(1)
            
            # Extract storage
            storage = await self._extract_storage(page)
            result["storage"] = storage
            
            # Track how many new endpoints were found from this page
            new_endpoints = len(self.dynamic_endpoints) - pre_count
            result["new_endpoints_count"] = new_endpoints
            
            # Check storage for interesting tokens/keys
            sensitive_patterns = re.compile(r'(?i)(token|key|secret|auth|session|jwt|bearer|api[_-]?key)', re.IGNORECASE)
            for store_type, data in storage.items():
                for key, value in data.items():
                    if sensitive_patterns.search(key) and value and len(str(value)) > 5:
                        self.storage_findings.append({
                            "source_url": url,
                            "storage_type": store_type,
                            "key": key,
                            "value_preview": str(value)[:100] + ("..." if len(str(value)) > 100 else ""),
                        })
            
            await page.close()
        except Exception as e:
            # Silently handle errors (page timeouts, navigation failures)
            try:
                await page.close()
            except Exception:
                pass
        
        return result

    async def run(self) -> List[Dict]:
        import time
        start = time.time()
        banner("Headless JS Execution & Hooking")
        
        if not PLAYWRIGHT_AVAILABLE:
            log_error("Playwright is not installed. Skipping headless execution.")
            log_info("Install with: pip install playwright && playwright install chromium")
            return []
        
        # Ensure we have targets
        if not self.urls and self.domain:
            self.urls = [f"https://www.{self.domain}", f"https://{self.domain}"]
            log_info(f"No URLs provided — using domain fallback targets.")
            
        log_info(f"Firing up headless Chromium to hook {len(self.urls)} targets...")
        
        results = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=Config.USER_AGENT,
                    viewport={"width": 1920, "height": 1080},
                )
                
                # Process with concurrency limit
                semaphore = asyncio.Semaphore(5)
                
                async def bounded_process(url):
                    async with semaphore:
                        return await self._process_url(context, url)
                        
                tasks = [bounded_process(u) for u in self.urls]
                results = await asyncio.gather(*tasks)
                
                await browser.close()
        except Exception as e:
            log_error(f"Playwright crash: {e}")
        
        # Log results
        log_success(f"Intercepted {len(self.dynamic_endpoints)} dynamic API requests.")
        
        if self.storage_findings:
            log_success(f"Found {len(self.storage_findings)} interesting storage entries (tokens/keys).")
            for sf in self.storage_findings[:5]:
                log_info(f"  [{sf['storage_type']}] {sf['key']} = {sf['value_preview']}")
        
        # Build structured output
        output = {
            "dynamic_endpoints": sorted(self.dynamic_endpoints),
            "api_calls": self.api_calls[:200],  # Cap to prevent huge files
            "storage_findings": self.storage_findings,
            "pages_processed": len(results),
            "duration_seconds": round(time.time() - start, 2),
        }
        
        return output

def main():
    parser = argparse.ArgumentParser(description="Headless JS Hooker")
    parser.add_argument("-l", "--list", help="List of URLs to test")
    parser.add_argument("-d", "--domain", help="Target domain")
    args = parser.parse_args()
    
    urls = []
    if args.list:
        urls = read_lines(args.list)
    
    if not urls and not args.domain:
        print("Provide --list or --domain.")
        return
        
    hooker = HeadlessHooker(urls, domain=args.domain)
    results = asyncio.run(hooker.run())
    
    if results and results.get("dynamic_endpoints"):
        print(f"\n[+] {len(results['dynamic_endpoints'])} Dynamic API Endpoints Intercepted:")
        for ep in results["dynamic_endpoints"][:20]:
            print(f"  {ep}")

if __name__ == "__main__":
    main()
