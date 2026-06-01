#!/usr/bin/env python3
"""
VirusTotal Per-Subdomain URL Scraper — High-Value Target Priority

Queries VirusTotal's domain/report API for EACH live subdomain,
extracting both detected and undetected URLs. Rotates multiple
API keys to maximize throughput (4 req/min per key on free tier).

STRATEGY: Prioritize subdomains that handle auth, payments, APIs,
and user data — these are where VT URLs leak tokens, session IDs,
and credentials as URL parameters. Skip CDN/static/marketing subdomains.
"""

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error, log_finding,
    read_lines, write_lines, elapsed_str
)


# ── Priority Classification ─────────────────────────────────

# Subdomains most likely to have credential/token leaks in URLs
HIGH_VALUE_KEYWORDS = [
    'account', 'auth', 'login', 'sso', 'oauth', 'signin', 'signup',
    'checkout', 'pay', 'payment', 'billing', 'invoice', 'order',
    'api', 'gateway', 'internal', 'admin', 'portal', 'dashboard',
    'manage', 'panel', 'console', 'backend', 'staging', 'dev',
    'app', 'my', 'user', 'profile', 'member', 'customer',
    'cart', 'wallet', 'transfer', 'transaction',
    'webhook', 'callback', 'redirect', 'token',
]

# Subdomains that are never interesting (CDN, static, marketing)
SKIP_KEYWORDS = [
    'cdn', 'static', 'assets', 'img', 'images', 'media', 'video',
    'fonts', 'cache', 'edge', 'waf',
    'blog', 'news', 'press', 'careers', 'jobs', 'about',
    'marketing', 'promo', 'ads', 'tracking', 'analytics',
    'mta-sts', 'autodiscover', 'autoconfig', '_dmarc',
    'mail', 'smtp', 'pop', 'imap', 'mx',
    'ns1', 'ns2', 'ns3', 'ns4', 'dns',
    'status', 'docs', 'help', 'support', 'faq',
    'www',  # main site usually has too many garbage URLs
]

# URL parameters that indicate leaked credentials/tokens
JUICY_PARAMS = {
    # Auth & Session
    'token', 'access_token', 'refresh_token', 'id_token', 'auth_token',
    'session', 'session_id', 'sessionid', 'sid', 'jsessionid',
    'api_key', 'apikey', 'api-key', 'key', 'secret', 'client_secret',
    'password', 'passwd', 'pwd', 'pass',
    'jwt', 'bearer', 'authorization', 'auth',
    'oauth_token', 'oauth_verifier', 'code', 'grant',
    # User Data / IDOR
    'user_id', 'userid', 'uid', 'account_id', 'customer_id',
    'email', 'phone', 'ssn', 'credit_card',
    'order_id', 'orderid', 'invoice_id', 'transaction_id',
    # Redirect / SSRF
    'redirect', 'redirect_uri', 'redirect_url', 'callback',
    'return', 'return_url', 'returnto', 'next', 'dest', 'destination',
    'url', 'uri', 'link', 'goto', 'continue',
    # File / Path
    'file', 'path', 'filepath', 'filename', 'document',
    'upload', 'download', 'attachment',
}


def _classify_subdomain(domain: str) -> int:
    """Classify subdomain priority: 0=skip, 1=normal, 2=high-value."""
    d = domain.lower()

    # Check skip keywords first
    parts = d.split('.')
    for part in parts:
        for kw in SKIP_KEYWORDS:
            if kw == part or d.startswith(f"{kw}."):
                return 0

    # Check high-value keywords
    for kw in HIGH_VALUE_KEYWORDS:
        if kw in d:
            return 2

    return 1  # Normal priority


def _is_juicy_url(url: str) -> bool:
    """Check if a URL contains leaked credentials/tokens in parameters."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in params:
            if param_name.lower() in JUICY_PARAMS:
                val = params[param_name][0] if params[param_name] else ""
                # Must have an actual value (not empty or placeholder)
                if val and len(val) > 3 and val.lower() not in (
                    'true', 'false', 'null', 'none', 'undefined',
                    'test', 'example', '{token}', '{{token}}',
                ):
                    return True
    except Exception:
        pass
    return False


class VTUrlScraper:
    """Scrape VirusTotal for URLs associated with each live subdomain."""

    def __init__(self, subdomains: List[str], output_dir: Path = None):
        self.subdomains = subdomains
        self.output_dir = output_dir or Path(".")
        self.vt_keys = Config.get_vt_keys()
        self.all_urls: Set[str] = set()
        self.juicy_urls: Set[str] = set()
        self.stats = {"queried": 0, "rate_limited": 0, "urls_found": 0, "juicy_found": 0, "skipped": 0}

    def _prioritize_subdomains(self) -> List[str]:
        """Sort subdomains: high-value first, skip junk."""
        high, normal = [], []
        for d in self.subdomains:
            priority = _classify_subdomain(d)
            if priority == 2:
                high.append(d)
            elif priority == 1:
                normal.append(d)
            else:
                self.stats["skipped"] += 1
        return high + normal

    def _clean_url(self, url: str) -> str:
        """Clean common junk from URLs found in VirusTotal reports."""
        if not url:
            return ""
        url = url.strip().replace('\r', '').replace('\n', '')
        url = url.rstrip(').,!] \t')
        if ').' in url:
            url = url.split(').')[0]
        return url

    async def _fetch_urls_for_domain(self, domain: str, api_key: str, session: aiohttp.ClientSession) -> Set[str]:
        """Query VT v2 API for all URLs associated with a domain."""
        urls = set()
        vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"

        try:
            async with session.get(vt_url) as resp:
                if resp.status in (204, 429):
                    self.stats["rate_limited"] += 1
                    return urls
                if resp.status != 200:
                    return urls

                data = await resp.json()

                # 1. Detected URLs (flagged by VT scanners)
                for entry in data.get("detected_urls", []):
                    if isinstance(entry, dict):
                        url = self._clean_url(entry.get("url", ""))
                    elif isinstance(entry, list) and len(entry) > 0:
                        url = self._clean_url(entry[0])
                    else:
                        continue
                    if url and url.startswith("http"):
                        urls.add(url)

                # 2. Undetected URLs — the goldmine
                for entry in data.get("undetected_urls", []):
                    if isinstance(entry, list) and len(entry) > 0:
                        url = self._clean_url(str(entry[0]))
                    elif isinstance(entry, str):
                        url = self._clean_url(entry)
                    else:
                        continue
                    if url and url.startswith("http"):
                        urls.add(url)

                # 3. Undetected referrer samples
                for entry in data.get("undetected_referrer_samples", []):
                    if isinstance(entry, dict):
                        url = self._clean_url(entry.get("url", ""))
                        if url and url.startswith("http"):
                            urls.add(url)

        except Exception:
            pass

        return urls

    async def scrape(self) -> Dict:
        """Scrape VT for all subdomains using key rotation."""
        start = time.time()
        banner("VirusTotal Per-Subdomain URL Scraper")

        if not self.vt_keys:
            log_warning("No VirusTotal API keys configured. Skipping VT URL scraping.")
            log_info("Set VIRUSTOTAL_API_KEYS in .env (comma-separated for rotation)")
            return {"urls": [], "juicy_urls": [], "count": 0}

        # Prioritize high-value subdomains
        prioritized = self._prioritize_subdomains()

        log_info(f"Loaded {len(self.vt_keys)} VT API keys for rotation")
        log_info(f"Priority queue: {len(prioritized)} targets ({self.stats['skipped']} junk subdomains skipped)")

        high_count = sum(1 for d in prioritized if _classify_subdomain(d) == 2)
        if high_count:
            log_success(f"  🎯 {high_count} high-value targets (auth/payment/api/account) queued first")

        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=5)
        timeout = aiohttp.ClientTimeout(total=20)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": Config.USER_AGENT},
        ) as session:
            batch_size = len(self.vt_keys)
            rate_limit_hit = False

            for i in range(0, len(prioritized), batch_size):
                if rate_limit_hit:
                    break

                batch = prioritized[i:i + batch_size]
                log_info(f"Batch {i//batch_size + 1}: subdomains {i+1}–{min(i+batch_size, len(prioritized))}...")

                for j, subdomain in enumerate(batch):
                    key = self.vt_keys[j % len(self.vt_keys)]
                    urls = await self._fetch_urls_for_domain(subdomain, key, session)

                    if self.stats["rate_limited"] > 0 and not urls:
                        log_warning(f"Rate limit hit — stopping VT scraping to avoid lockout")
                        rate_limit_hit = True
                        break

                    if urls:
                        self.all_urls.update(urls)
                        self.stats["urls_found"] += len(urls)

                        # Check for juicy URLs with leaked creds/tokens
                        juicy_in_batch = {u for u in urls if _is_juicy_url(u)}
                        self.juicy_urls.update(juicy_in_batch)
                        self.stats["juicy_found"] += len(juicy_in_batch)

                        priority_tag = "🎯" if _classify_subdomain(subdomain) == 2 else "  "
                        juicy_tag = f" (🔥 {len(juicy_in_batch)} juicy)" if juicy_in_batch else ""
                        log_success(f"  {priority_tag} {subdomain:30s}: {len(urls)} URLs{juicy_tag}")

                        # Alert on juicy finds
                        for ju in juicy_in_batch:
                            log_finding(f"[VT-JUICY] {ju}")

                    self.stats["queried"] += 1

                if rate_limit_hit:
                    break

                # Wait 15.5s between batches to respect rate limits
                remaining = len(prioritized) - (i + batch_size)
                if remaining > 0:
                    wait_time = 15.5
                    log_info(f"  Waiting {wait_time}s for VT rate limits ({remaining} subdomains remaining)...")
                    await asyncio.sleep(wait_time)

        # Save all URLs
        if self.all_urls:
            output_file = self.output_dir / "virustotal_urls.txt"
            write_lines(str(output_file), sorted(self.all_urls))

        # Save juicy URLs separately
        if self.juicy_urls:
            juicy_file = self.output_dir / "vt_juicy_urls.txt"
            write_lines(str(juicy_file), sorted(self.juicy_urls))
            log_success(f"🔥 {len(self.juicy_urls)} juicy URLs with leaked tokens/creds saved to vt_juicy_urls.txt")

        log_success(f"VT scraping: {len(self.all_urls)} total, {len(self.juicy_urls)} juicy from {self.stats['queried']} subdomains")
        log_info(f"VT URL scraping completed in {elapsed_str(start)}")

        return {
            "urls": sorted(self.all_urls),
            "juicy_urls": sorted(self.juicy_urls),
            "count": len(self.all_urls),
            "juicy_count": len(self.juicy_urls),
            "queried": self.stats["queried"],
        }


# ── CLI ──────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="VirusTotal Per-Subdomain URL Scraper")
    parser.add_argument("-i", "--input", required=True, help="File with live subdomains")
    parser.add_argument("-o", "--output", default="./output", help="Output directory")
    args = parser.parse_args()

    subdomains = read_lines(args.input)
    if not subdomains:
        log_error("No subdomains to query.")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    scraper = VTUrlScraper(subdomains, output_dir)
    await scraper.scrape()


if __name__ == "__main__":
    asyncio.run(main())
