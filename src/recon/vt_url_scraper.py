#!/usr/bin/env python3
"""
VirusTotal Per-Subdomain URL Scraper — High-Value Target Priority

Queries VirusTotal's domain/report API for EACH live subdomain,
extracting both detected and undetected URLs. Rotates multiple
API keys to maximize throughput (4 req/min per key on free tier).

STRATEGY: Prioritize subdomains that handle auth, payments, APIs,
and user data — these are where VT URLs leak tokens, session IDs,
and credentials as URL parameters. Skip CDN/static/marketing subdomains.

KEY ROTATION LOGIC (v2):
  - Tracks per-key exhaustion with timestamps (not a global stop)
  - When a key hits 429/204, marks it exhausted for ~60s then retries
  - Immediately rotates to the next available key
  - When ALL keys are exhausted, waits for the soonest one to reset
  - Logs which key# hit the limit and how long until it resets
  - With 7 keys: 28 req/min = can process a 100-subdomain target in ~4 min
"""

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
    # Email/Notification — URLs leak PII (email, user_id, unsub tokens)
    'email', 'emails', 'mail', 'notification', 'notifications',
    'newsletter', 'newsletters', 'unsubscribe', 'subscribe',
    'push', 'push-notification', 'mailer', 'noreply', 'no-reply',
    # Dev/Staging — weaker security, more leaks
    'dev', 'staging', 'stg', 'uat', 'preview', 'preprod', 'pre-prod',
]

# Subdomains that never have credential/token leaks in URLs
SKIP_KEYWORDS = [
    # CDN / Static Assets
    'cdn', 'static', 'assets', 'img', 'images', 'video', 'photos',
    'fonts', 'cache', 'edge', 'waf', 'downloads', 'dl',
    'res', 'resources',
    # Marketing / SEO / Public
    'blog', 'news', 'press', 'careers', 'jobs', 'about', 'info',
    'marketing', 'promo', 'promos', 'ads', 'tracking', 'analytics',
    'seo', 'campaign', 'campaigns', 'events', 'event', 'landing',
    'brand', 'branding', 'affiliate', 'affiliates', 'partners',
    # Email Infra
    'smtp', 'pop', 'imap', 'mx',
    'mta-sts', 'autodiscover', 'autoconfig', '_dmarc',
    'postmaster', 'bounce',
    # DNS / Infra
    'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
    'vpn', 'proxy', 'relay', 'nat', 'firewall',
    'monitor', 'monitoring', 'nagios', 'zabbix', 'grafana',
    # Status / Docs / Support
    'status', 'statuspage', 'uptime', 'healthcheck', 'health',
    'docs', 'doc', 'documentation', 'wiki', 'kb', 'knowledge',
    'help', 'support', 'faq', 'helpdesk', 'zendesk', 'freshdesk',
    'community', 'forum', 'forums', 'discuss', 'feedback',
    # Sandboxed
    'sandbox', 'playground',
    # Legal
    'legal', 'privacy', 'terms', 'compliance', 'gdpr', 'cookie',
    # Localization
    'translate', 'translations', 'i18n', 'l10n', 'locale',
    # Telemetry
    'telemetry', 'metrics', 'logs', 'logging', 'sentry', 'bugsnag',
    'newrelic', 'datadog', 'splunk', 'elastic', 'kibana',
    # Social
    'share', 'social', 'connect', 'like', 'follow',
    # Main site
    'www', 'ww2', 'ww3', 'm', 'mobile',
    # Git / CI
    'git', 'gitlab', 'jenkins', 'ci', 'cd', 'build', 'deploy',
    # Chat
    'chat', 'slack', 'irc', 'xmpp',
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

# VT free tier: 4 req/min per key — keys reset after this many seconds
VT_RATE_LIMIT_WINDOW = 62  # 62s to be safe (limit is per 60s window)


def _classify_subdomain(domain: str) -> int:
    """Classify subdomain priority: 0=skip, 1=normal, 2=high-value."""
    d = domain.lower()
    parts = d.split('.')
    for part in parts:
        for kw in SKIP_KEYWORDS:
            if kw == part or d.startswith(f"{kw}."):
                return 0
    for kw in HIGH_VALUE_KEYWORDS:
        if kw in d:
            return 2
    return 1


def _is_juicy_url(url: str) -> bool:
    """Check if a URL contains leaked credentials/tokens in parameters."""
    try:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in params:
            if param_name.lower() in JUICY_PARAMS:
                val = params[param_name][0] if params[param_name] else ""
                if val and len(val) > 3 and val.lower() not in (
                    'true', 'false', 'null', 'none', 'undefined',
                    'test', 'example', '{token}', '{{token}}',
                ):
                    return True
    except Exception:
        pass
    return False


# ── Per-Key Rate Limit Rotator ───────────────────────────────

class VTKeyRotator:
    """
    Round-robin VT API key rotator with per-key rate-limit tracking.

    When a key receives a 429 or 204 response, it is marked "exhausted"
    for VT_RATE_LIMIT_WINDOW seconds. Requests automatically route to
    the next available key. When ALL keys are exhausted, callers should
    await seconds_until_reset() before retrying.
    """

    def __init__(self, keys: List[str]):
        if not keys:
            raise ValueError("VTKeyRotator requires at least one key")
        self.keys = keys
        self._idx = 0
        # key -> unix timestamp when it becomes available again
        self._exhausted_until: Dict[str, float] = {}

    def _key_label(self, key: str) -> str:
        """Short label for logging: key#N ...last8chars"""
        idx = self.keys.index(key) + 1
        return f"key#{idx}(...{key[-8:]})"

    def get_key(self) -> Optional[str]:
        """
        Return the next available (non-exhausted) key in round-robin order.
        Returns None if ALL keys are currently exhausted.
        """
        now = time.time()
        # Iterate through all keys starting from current index
        for _ in range(len(self.keys)):
            key = self.keys[self._idx % len(self.keys)]
            self._idx += 1
            if self._exhausted_until.get(key, 0) <= now:
                return key
        return None  # All exhausted

    def mark_exhausted(self, key: str):
        """Mark a key as rate-limited; won't be returned by get_key() for ~62s."""
        reset_at = time.time() + VT_RATE_LIMIT_WINDOW
        self._exhausted_until[key] = reset_at
        log_warning(
            f"  [VT] {self._key_label(key)} rate-limited — "
            f"resumes in {VT_RATE_LIMIT_WINDOW}s. "
            f"{self.available_count()}/{len(self.keys)} keys still active."
        )

    def available_count(self) -> int:
        """How many keys are currently not exhausted."""
        now = time.time()
        return sum(1 for k in self.keys if self._exhausted_until.get(k, 0) <= now)

    def seconds_until_any_reset(self) -> float:
        """
        How many seconds until the soonest exhausted key resets.
        Returns 0 if at least one key is currently available.
        """
        if self.available_count() > 0:
            return 0.0
        now = time.time()
        soonest = min(self._exhausted_until.values())
        return max(0.0, soonest - now)


# ── VT Scraper ───────────────────────────────────────────────

class VTUrlScraper:
    """Scrape VirusTotal for URLs associated with each live subdomain."""

    def __init__(self, subdomains: List[str], output_dir: Path = None):
        self.subdomains = subdomains
        self.output_dir = output_dir or Path(".")
        self.vt_keys = Config.get_vt_keys()
        self.all_urls: Set[str] = set()
        self.juicy_urls: Set[str] = set()
        self.stats = {
            "queried": 0, "rate_limited": 0,
            "urls_found": 0, "juicy_found": 0, "skipped": 0,
        }

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

    async def _fetch_domain(
        self,
        domain: str,
        api_key: str,
        session: aiohttp.ClientSession,
    ) -> Tuple[Set[str], bool]:
        """
        Query VT v2 API for all URLs associated with a domain.

        Returns:
            (urls, was_rate_limited)
            was_rate_limited=True means the key should be marked exhausted.
        """
        urls: Set[str] = set()
        vt_url = (
            f"https://www.virustotal.com/vtapi/v2/domain/report"
            f"?apikey={api_key}&domain={domain}"
        )

        try:
            async with session.get(vt_url) as resp:
                # 204 = quota exceeded, 429 = rate limited
                if resp.status in (204, 429):
                    self.stats["rate_limited"] += 1
                    return urls, True  # Signal key exhaustion
                if resp.status != 200:
                    return urls, False

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

        return urls, False

    async def scrape(self) -> Dict:
        """Scrape VT for all subdomains with smart per-key rate-limit rotation."""
        start = time.time()
        banner("VirusTotal Per-Subdomain URL Scraper")

        if not self.vt_keys:
            log_warning("No VirusTotal API keys configured. Skipping VT URL scraping.")
            log_info("Set VIRUSTOTAL_API_KEYS in .env (comma-separated for rotation)")
            return {"urls": [], "juicy_urls": [], "count": 0}

        rotator = VTKeyRotator(self.vt_keys)
        prioritized = self._prioritize_subdomains()

        log_info(f"Loaded {len(self.vt_keys)} VT API keys for rotation")
        log_info(
            f"Priority queue: {len(prioritized)} targets "
            f"({self.stats['skipped']} junk subdomains skipped)"
        )
        high_count = sum(1 for d in prioritized if _classify_subdomain(d) == 2)
        if high_count:
            log_success(f"  🎯 {high_count} high-value targets queued first")

        # Per-key rate: 4 req/min → 15s between uses of the SAME key.
        # With N keys in round-robin: inter-request delay = 15s / N keys.
        # e.g. 7 keys → ~2.1s between requests → 28 req/min total.
        inter_delay = 15.0 / len(self.vt_keys)
        log_info(
            f"Rate strategy: {len(self.vt_keys)} keys × 4 req/min = "
            f"{len(self.vt_keys) * 4} req/min total "
            f"(~{inter_delay:.1f}s between requests)"
        )

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

            for i, subdomain in enumerate(prioritized):
                # ── Get an available key ──────────────────────────────
                key = rotator.get_key()
                if key is None:
                    # All keys exhausted — wait for the soonest reset
                    wait_sec = rotator.seconds_until_any_reset()
                    log_warning(
                        f"  [VT] All {len(self.vt_keys)} keys rate-limited. "
                        f"Waiting {wait_sec:.0f}s for reset..."
                    )
                    await asyncio.sleep(wait_sec + 2)  # +2s safety buffer
                    key = rotator.get_key()
                    if key is None:
                        log_error("All VT keys still exhausted after wait — aborting.")
                        break

                # ── Fetch ─────────────────────────────────────────────
                urls, was_limited = await self._fetch_domain(subdomain, key, session)

                if was_limited:
                    rotator.mark_exhausted(key)
                    # Immediately retry this subdomain with the next available key
                    retry_key = rotator.get_key()
                    if retry_key:
                        log_info(f"  [VT] Retrying {subdomain} with next key...")
                        urls, was_limited2 = await self._fetch_domain(
                            subdomain, retry_key, session
                        )
                        if was_limited2:
                            rotator.mark_exhausted(retry_key)
                            urls = set()

                # ── Process results ────────────────────────────────────
                if urls:
                    self.all_urls.update(urls)
                    self.stats["urls_found"] += len(urls)

                    juicy = {u for u in urls if _is_juicy_url(u)}
                    self.juicy_urls.update(juicy)
                    self.stats["juicy_found"] += len(juicy)

                    priority_tag = "🎯" if _classify_subdomain(subdomain) == 2 else "  "
                    juicy_tag = f" (🔥 {len(juicy)} juicy)" if juicy else ""
                    remaining = len(prioritized) - i - 1
                    log_success(
                        f"  {priority_tag} [{i+1}/{len(prioritized)}] "
                        f"{subdomain:35s}: {len(urls)} URLs{juicy_tag} "
                        f"| {remaining} remaining | "
                        f"{rotator.available_count()}/{len(self.vt_keys)} keys active"
                    )

                    for ju in juicy:
                        log_finding(f"[VT-JUICY] {ju}")

                self.stats["queried"] += 1

                # ── Inter-request delay (respect per-key rate limits) ──
                if i < len(prioritized) - 1:
                    await asyncio.sleep(inter_delay)

        # ── Save results ──────────────────────────────────────────────
        if self.all_urls:
            output_file = self.output_dir / "virustotal_urls.txt"
            write_lines(str(output_file), sorted(self.all_urls))

        if self.juicy_urls:
            juicy_file = self.output_dir / "vt_juicy_urls.txt"
            write_lines(str(juicy_file), sorted(self.juicy_urls))
            log_success(
                f"🔥 {len(self.juicy_urls)} juicy URLs saved to vt_juicy_urls.txt"
            )

        log_success(
            f"VT scraping done: {len(self.all_urls)} URLs, "
            f"{len(self.juicy_urls)} juicy from {self.stats['queried']} subdomains "
            f"({self.stats['rate_limited']} rate-limit hits handled)"
        )
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
