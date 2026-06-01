#!/usr/bin/env python3
"""
Module: Edge Node Cache Deception
Actively tests discovered endpoints for Web Cache Deception (WCD)
by appending static extensions (e.g., ;/.css) and checking if
the response gets cached by the CDN.
"""

import argparse
import asyncio
import sys
import ssl
from pathlib import Path
from typing import List, Dict

import aiohttp
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_finding, banner, write_lines, read_lines, RateLimiter

WCD_PAYLOADS = [
    ".css",
    "/.css",
    ";/.css",
    "%0A.css",
    ".js",
    "/.js",
    ";/.js"
]

class CacheDeceptionScanner:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.findings = []
        self.rate_limiter = RateLimiter(30)
        self._session = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            # Use random User-Agent cache-buster header to force miss on first request
            self._session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=8))
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _is_cached(self, headers: dict) -> bool:
        """Heuristic to check if a response was cached by a CDN."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Cloudflare
        if headers_lower.get("cf-cache-status") == "hit":
            return True
        # Akamai
        if "hit" in headers_lower.get("x-cache", ""):
            return True
        # Generic Edge Cache
        if "hit" in headers_lower.get("x-edge-result", ""):
            return True
        # Fastly
        if "hit" in headers_lower.get("x-fastly-cache", ""):
            return True
        # Age header implies it's cached
        if "age" in headers_lower and headers_lower["age"] != "0":
            return True
            
        return False

    async def _test_url(self, url: str) -> Dict:
        """Test a single URL with cache deception payloads."""
        await self.rate_limiter.acquire()
        session = await self._get_session()
        
        parsed = urlparse(url)
        # Skip urls that already end in static extensions
        if parsed.path.endswith((".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg")):
            return None
            
        # We only test endpoints that seem dynamic (e.g. /api/, /user/, or no extension)
        if "." in parsed.path.split("/")[-1]:
            if not parsed.path.endswith((".php", ".jsp", ".asp", ".aspx")):
                return None

        # Try a few WCD payloads
        for payload in WCD_PAYLOADS:
            test_url = url.rstrip("/") + payload
            try:
                # We send two requests. First to populate cache, second to check if it's a HIT
                headers_1 = {"User-Agent": Config.USER_AGENT, "Pragma": "akamai-x-cache-on, akamai-x-cache-remote-on"}
                async with session.get(test_url, headers=headers_1, allow_redirects=False) as resp1:
                    # If it redirects or fails, move on
                    if resp1.status != 200:
                        continue
                    
                    # Some WAFs block the payload immediately
                    content_type = resp1.headers.get("Content-Type", "").lower()
                    
                    # Second request
                    headers_2 = {"User-Agent": Config.USER_AGENT}
                    async with session.get(test_url, headers=headers_2, allow_redirects=False) as resp2:
                        if resp2.status == 200:
                            is_cached = self._is_cached(dict(resp2.headers))
                            
                            if is_cached and "text/html" not in content_type and "text/css" not in content_type and "application/javascript" not in content_type:
                                # If it's cached, and it's returning JSON or something sensitive, that's Web Cache Deception!
                                return {
                                    "url": url,
                                    "wcd_url": test_url,
                                    "payload": payload,
                                    "status": resp2.status,
                                    "content_type": content_type
                                }
            except Exception:
                pass
        return None

    async def _check_cdn_presence(self) -> bool:
        """Heuristic check to see if the target uses a CDN."""
        if not self.urls:
            return False
            
        parsed = urlparse(self.urls[0])
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        try:
            session = await self._get_session()
            async with session.get(base_url, allow_redirects=False) as resp:
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                server = headers.get("server", "")
                if any(cdn in server for cdn in ["cloudflare", "akamai", "cloudfront", "fastly"]):
                    return True
                for h in headers.keys():
                    if any(cdn in h for cdn in ["cf-", "akamai", "x-fastly", "x-cache", "x-edge"]):
                        return True
        except Exception:
            pass
        return False

    async def scan(self) -> List[Dict]:
        import time
        start = time.time()
        banner("Cache Deception Scanner")
        
        log_info(f"Testing {len(self.urls)} endpoints for Web Cache Deception...")
        
        if self.urls:
            has_cdn = await self._check_cdn_presence()
            if not has_cdn:
                log_warning("No major CDN (Cloudflare/Akamai/Fastly) detected on target.")
                log_warning("Cache Deception typically fails on Origin servers. Proceeding anyway with forced proxy headers...")
                
        tasks = [self._test_url(url) for url in self.urls]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                self.findings.append(res)
                log_finding(f"[WCD VULNERABLE] {res['url']} -> {res['wcd_url']} (Cached as {res['content_type']})")

        await self.close()
        log_success(f"Cache Deception scan completed in {time.time() - start:.2f}s. Found {len(self.findings)} vulnerable endpoints.")
        return self.findings

def main():
    parser = argparse.ArgumentParser(description="Web Cache Deception Scanner")
    parser.add_argument("-l", "--list", required=True, help="List of URLs to test")
    args = parser.parse_args()
    
    urls = read_lines(args.list)
    if not urls:
        print("No URLs provided.")
        return
        
    scanner = CacheDeceptionScanner(urls)
    asyncio.run(scanner.scan())

if __name__ == "__main__":
    main()
