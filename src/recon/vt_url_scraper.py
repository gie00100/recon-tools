#!/usr/bin/env python3
"""
VirusTotal Per-Subdomain URL Scraper

Queries VirusTotal's domain/report API for EACH live subdomain,
extracting both detected and undetected URLs. Rotates multiple
API keys to maximize throughput (4 req/min per key on free tier).

The `undetected_urls` field is a goldmine — it contains URLs that
VirusTotal has observed but weren't flagged, often revealing live
internal/staging/API endpoints.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error,
    read_lines, write_lines, elapsed_str
)


class VTUrlScraper:
    """Scrape VirusTotal for URLs associated with each live subdomain."""

    def __init__(self, subdomains: List[str], output_dir: Path = None):
        self.subdomains = subdomains
        self.output_dir = output_dir or Path(".")
        self.vt_keys = Config.get_vt_keys()
        self.all_urls: Set[str] = set()
        self.stats = {"queried": 0, "rate_limited": 0, "urls_found": 0}

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
                    # Rate limit hit
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
                # Structure in v2: list of lists [url, sha256, positives, total, date]
                for entry in data.get("undetected_urls", []):
                    if isinstance(entry, list) and len(entry) > 0:
                        url = self._clean_url(str(entry[0]))
                    elif isinstance(entry, str):
                        url = self._clean_url(entry)
                    else:
                        continue
                    if url and url.startswith("http"):
                        urls.add(url)

                # 3. Also grab undetected_downloaded_samples URLs if present
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
            return {"urls": [], "count": 0}

        log_info(f"Loaded {len(self.vt_keys)} VT API keys for rotation")
        log_info(f"Querying {len(self.subdomains)} subdomains (free tier: 4 req/min/key)")

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

            for i in range(0, len(self.subdomains), batch_size):
                if rate_limit_hit:
                    break

                batch = self.subdomains[i:i + batch_size]
                log_info(f"Processing subdomains {i+1} to {min(i+batch_size, len(self.subdomains))}...")

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
                        log_success(f"  {subdomain:30s}: {len(urls)} URLs")

                    self.stats["queried"] += 1

                if rate_limit_hit:
                    break

                # Wait 15.5s between batches to respect rate limits (4 req/min/key)
                remaining = len(self.subdomains) - (i + batch_size)
                if remaining > 0:
                    wait_time = 15.5
                    log_info(f"  Waiting {wait_time}s to respect VT rate limits ({remaining} subdomains remaining)...")
                    await asyncio.sleep(wait_time)

        # Save results
        if self.all_urls:
            output_file = self.output_dir / "virustotal_urls.txt"
            write_lines(str(output_file), sorted(self.all_urls))
            log_success(f"VT scraping complete: {len(self.all_urls)} unique URLs from {self.stats['queried']} subdomains")
        else:
            log_info("No URLs found from VirusTotal.")

        log_info(f"VT URL scraping completed in {elapsed_str(start)}")

        return {
            "urls": sorted(self.all_urls),
            "count": len(self.all_urls),
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
