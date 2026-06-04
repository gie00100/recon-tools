#!/usr/bin/env python3
"""
Watchlist Monitor — 24/7 Continuous Recon
Reads targets/watchlist.txt and periodically checks for newly discovered URLs
using waymore/vtscrape, then runs them through the passive bounty scanner.
"""

import asyncio
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon.config import Config
from recon.waymore_extractor import WaymoreExtractor
from recon.vt_url_scraper import VTUrlScraper
from recon.bounty_scanner import BountyScanner
from recon.utils import log_info, log_success, log_warning, send_discord_alert

WATCHLIST_FILE = Path(__file__).parent.parent / "targets" / "watchlist.txt"
OUTPUT_DIR = Path(__file__).parent.parent / "output" / "monitor"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def _send_alert(title: str, desc: str, color: int, is_finding: bool = True):
    """Send Discord alert to the appropriate webhook channel."""
    webhook = Config.DISCORD_RESULTS_WEBHOOK_URL if is_finding else Config.DISCORD_WEBHOOK_URL
    if webhook:
        await send_discord_alert(webhook, title, desc, color)

def get_watchlist_domains():
    """Read domains from the watchlist."""
    domains = set()
    if WATCHLIST_FILE.exists():
        with open(WATCHLIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip() or line.strip().startswith('#'):
                    continue
                parts = [p.strip() for p in line.split('|')]
                if parts:
                    domains.add(parts[0])
    return domains

def load_seen_urls(domain):
    """Load previously seen URLs for a domain to avoid duplicate processing."""
    seen_file = OUTPUT_DIR / f"{domain}_seen.txt"
    seen = set()
    if seen_file.exists():
        with open(seen_file, 'r', encoding='utf-8') as f:
            for line in f:
                seen.add(line.strip())
    return seen

def save_seen_urls(domain, urls):
    """Append new URLs to the seen file."""
    seen_file = OUTPUT_DIR / f"{domain}_seen.txt"
    with open(seen_file, 'a', encoding='utf-8') as f:
        for url in urls:
            f.write(f"{url}\n")

async def _verify_juicy_file(url: str) -> bool:
    """Actively check if a passive URL represents a real exposed juicy file."""
    import aiohttp
    import ssl
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": Config.USER_AGENT}) as session:
            async with session.get(url, allow_redirects=True, timeout=8) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type:
                        text = await resp.text(errors="ignore")
                        html_indicators = ["<!doctype html", "<html", "<head", "<body", "<script", "<title", "<div"]
                        if any(ind in text[:2048].lower() for ind in html_indicators):
                            return False # False positive HTML page
                    return True
                return False
    except Exception:
        return False

async def process_domain(domain):
    """Fetch new URLs for a domain and run bounty scan."""
    log_info(f"Monitoring: {domain}")
    
    # 1. Fetch URLs from Waymore and VT
    vt_scraper = VTUrlScraper(domain)
    vt_urls = await vt_scraper.scrape()
    
    waymore = WaymoreExtractor(domain)
    waymore_urls = await waymore.extract()
    
    all_fetched = set(vt_urls) | set(waymore_urls)
    
    # 2. Filter out already seen URLs
    seen_urls = load_seen_urls(domain)
    new_urls = all_fetched - seen_urls
    
    if not new_urls:
        log_info(f"[{domain}] No new URLs found.")
        return
        
    log_success(f"[{domain}] Found {len(new_urls)} NEW URLs! Running passive bounty scan...")
    
    # 3. Save to seen list
    save_seen_urls(domain, new_urls)
    
    # 4. Run Bounty Scanner on new URLs
    scanner = BountyScanner(list(new_urls))
    results = scanner.scan()
    
    verified_findings = []
    severity_colors = {"CRITICAL": 16711680, "HIGH": 16744448, "MEDIUM": 16753920}
    semaphore = asyncio.Semaphore(15)
    
    async def verify_and_alert(finding):
        sev = finding["severity"]
        url = finding["url"]
        
        is_juicy_file = finding["type"] in ("Juicy_Files", "Exposed_Dashboards")
        if is_juicy_file:
            async with semaphore:
                is_real = await _verify_juicy_file(url)
            if not is_real:
                return
                
        verified_findings.append(finding)
        
        if sev in severity_colors:
            emoji = "🚨" if sev == "CRITICAL" else "🎯"
            await _send_alert(
                f"{emoji} 24/7 Monitor: {finding['type']} — {domain}",
                (f"**Severity:** {sev}\n"
                 f"**Type:** {finding['type']}\n"
                 f"**Why:** {finding['description']}\n\n"
                 f"**New URL Detected:**\n```\n{finding['url']}\n```"),
                severity_colors[sev]
            )
            
    await asyncio.gather(*(verify_and_alert(f) for f in results["findings"]))
    
    if verified_findings:
        log_success(f"[{domain}] Monitor found {len(verified_findings)} new actionable findings!")

async def main():
    print("=" * 60)
    print(" 24/7 Watchlist Monitor Started")
    print("=" * 60)
    
    await _send_alert(
        "👁️ Watchlist Monitor Started",
        "24/7 continuous recon is now running on all domains in `watchlist.txt`.",
        0x3498DB,
        is_finding=False
    )
    
    while True:
        domains = get_watchlist_domains()
        if not domains:
            log_warning("Watchlist is empty. Waiting...")
        else:
            log_info(f"Starting monitoring cycle for {len(domains)} domains: {', '.join(domains)}")
            for domain in domains:
                try:
                    await process_domain(domain)
                except Exception as e:
                    log_warning(f"Error processing {domain}: {e}")
            
            log_success("Monitoring cycle complete.")
            
        # Sleep for 24 hours (86400 seconds) before next cycle
        log_info("Sleeping for 24 hours...")
        await asyncio.sleep(86400)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
