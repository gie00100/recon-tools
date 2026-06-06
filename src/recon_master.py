#!/usr/bin/env python3
"""
Recon Master — Pipeline Orchestrator
Chains all reconnaissance modules into a full automated pipeline.

Usage:
  python recon_master.py -d example.com --full
  python recon_master.py -d example.com --modules subdomain,probe,backup
  python recon_master.py -d example.com -a AS15169 --full
"""

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error, log_phase,
    write_lines, read_lines, elapsed_str, timestamp, console, RICH_AVAILABLE,
    send_discord_alert
)

# Import all modules
from recon.subdomain_enum import SubdomainEnumerator
from recon.asn_cidr_finder import ASNCIDRFinder
from recon.live_probe import LiveProber
from recon.backup_gen import BackupGenerator
from recon.js_extractor import JSExtractor
from recon.url_dedup import URLDeduplicator
from recon.bounty_scanner import BountyScanner
from recon.port_scanner import PortScanner, resolve_hostnames
from recon.cred_hunter import CredentialHunter
from recon.report_gen import ReportGenerator
from recon.schema_discovery import SchemaDiscovery
from recon.vt_url_scraper import VTUrlScraper
from recon.web_crawler import WebCrawler
from recon.passive_url_collector import PassiveURLCollector


ALL_MODULES = ["subdomain", "asn", "probe", "portscan", "backup", "credhunt", "jsextract", "schema", "vtscrape", "crawl", "waymore", "urlcollect", "dedup", "bountyscan", "report"]


class ReconMaster:
    """Master orchestrator that chains all recon modules."""

    def __init__(
        self,
        domain: str,
        asns: list = None,
        cidrs: list = None,
        modules: list = None,
        brute: bool = False,
        permutations: bool = False,
        active: bool = False,
        output_dir: str = None,
        concurrency: int = 50,
    ):
        self.domain = domain.lower().strip()
        self.asns = asns or []
        self.cidrs = cidrs or []
        self.modules = modules or ALL_MODULES
        self.brute = brute
        self.permutations = permutations
        self.active = active
        self.concurrency = concurrency

        # Create timestamped output directory
        ts = timestamp()
        self.base_out_dir = Path(output_dir or Config.OUTPUT_DIR)
        self.output_dir = self.base_out_dir / f"{self.domain}_{ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load state
        self.state_file = self.base_out_dir / f"{self.domain}_state.json"
        self.state = {"subdomains": [], "takeovers": [], "secrets": []}
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    self.state = json.load(f)
            except Exception:
                pass

        # Pipeline data shared between phases
        self.subdomains = set()
        self.vt_urls = set()
        self.waymore_urls = set()
        self.live_hosts = []
        self.exposed_ports = []
        self.js_findings = {}
        self.cred_findings = []
        self.backup_wordlist = []
        self.unique_urls = []
        self.schema_findings = {}
        self.crawled_endpoints = set()
        self.vt_scraped_urls = set()
        self.passive_collected_urls = set()  # Multi-source passive URLs
        self.bounty_flags = 0
        self.bounty_stats = {}
        self.report = None

        # Phase timing
        self.phase_times = []

    def _should_run(self, module_name: str) -> bool:
        """Check if a module should be run."""
        return module_name in self.modules

    async def _send_alert(self, title: str, desc: str, color: int, is_finding: bool = True):
        """Send Discord alert to the appropriate webhook channel."""
        webhook = Config.DISCORD_RESULTS_WEBHOOK_URL if is_finding else Config.DISCORD_WEBHOOK_URL
        if webhook:
            await send_discord_alert(webhook, title, desc, color)

    def _add_to_watchlist(self, url: str, finding_type: str, reason: str):
        """Add a domain to the continuous monitoring watchlist."""
        try:
            from urllib.parse import urlparse
            import datetime
            
            parsed = urlparse(url)
            domain = parsed.hostname
            if not domain:
                domain = url.split('/')[0]
                
            watchlist_path = Path(__file__).parent.parent / "targets" / "watchlist.txt"
            
            # Read existing to avoid duplicates
            existing_domains = set()
            if watchlist_path.exists():
                with open(watchlist_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip() or line.strip().startswith('#'):
                            continue
                        parts = [p.strip() for p in line.split('|')]
                        if parts:
                            existing_domains.add(parts[0])
            
            if domain not in existing_domains:
                date_str = datetime.datetime.now().strftime("%Y-%m-%d")
                entry = f"{domain} | {finding_type} | {date_str} | {reason}\n"
                with open(watchlist_path, 'a', encoding='utf-8') as f:
                    f.write(entry)
                log_success(f"Added {domain} to 24/7 Watchlist (Reason: {finding_type})")
        except Exception as e:
            log_warning(f"Failed to add to watchlist: {e}")

    async def _phase_subdomain_enum(self):
        """Phase 1: Subdomain Enumeration."""
        if not self._should_run("subdomain"):
            return

        start = time.time()
        log_phase(1, len(self.modules), "Subdomain Enumeration")

        enumerator = SubdomainEnumerator(
            domain=self.domain,
            brute=self.brute,
            permutations=self.permutations,
        )
        self.subdomains = await enumerator.enumerate()
        self.vt_urls = enumerator.vt_urls

        # Save results
        output_file = self.output_dir / "subdomains.txt"
        write_lines(str(output_file), self.subdomains)
        
        if self.vt_urls:
            vt_file = self.output_dir / "virustotal_urls.txt"
            write_lines(str(vt_file), self.vt_urls)

        duration = elapsed_str(start)
        self.phase_times.append(("Subdomain Enumeration", duration, len(self.subdomains)))

    async def _phase_asn_discovery(self):
        """Phase 2: ASN/CIDR Hostname Discovery."""
        if not self._should_run("asn"):
            return
        if not self.asns and not self.cidrs:
            log_info("No ASNs or CIDRs provided, skipping ASN phase")
            return

        start = time.time()
        log_phase(2, len(self.modules), "ASN/CIDR Discovery")

        finder = ASNCIDRFinder(asns=self.asns, cidrs=self.cidrs)
        asn_hosts = await finder.discover()

        # Merge with subdomains
        before = len(self.subdomains)
        self.subdomains.update(asn_hosts)
        new = len(self.subdomains) - before

        # Save merged results
        output_file = self.output_dir / "all_hosts.txt"
        write_lines(str(output_file), self.subdomains)

        log_success(f"Merged {new} new hosts from ASN discovery")
        duration = elapsed_str(start)
        self.phase_times.append(("ASN/CIDR Discovery", duration, len(asn_hosts)))

    async def _phase_live_probe(self):
        """Phase 3: Live Host Probing."""
        if not self._should_run("probe"):
            return
        if not self.subdomains:
            log_warning("No subdomains to probe")
            return

        start = time.time()
        log_phase(3, len(self.modules), "Live Host Probing")

        prober = LiveProber(
            targets=list(self.subdomains),
            concurrency=self.concurrency,
        )
        self.live_hosts = await prober.probe()
        
        # Check for takeovers — only alert on high-confidence findings
        for host in self.live_hosts:
            if host.get("takeover"):
                tk = host["takeover"]
                url = host["url"]
                if url not in self.state["takeovers"]:
                    # Determine confidence level from the tag
                    is_confirmed = "[CONFIRMED" in tk
                    is_dangling = "[DANGLING" in tk
                    is_candidate = "[CANDIDATE" in tk
                    
                    if is_confirmed or is_dangling:
                        # High confidence — send alert
                        await self._send_alert(
                            "🚨 Subdomain Takeover Detected!",
                            f"**URL:** {url}\n**Service:** {tk}\n\n*High confidence — verify and claim immediately!*",
                            16711680,  # Red
                            is_finding=True
                        )
                    elif is_candidate:
                        # Low confidence — send info alert
                        await self._send_alert(
                            "⚠️ Subdomain Takeover Candidate",
                            f"**URL:** {url}\n**Service:** {tk}\n\n*CNAME points to a known service but no takeover signature matched. Requires manual verification.*",
                            16776960,  # Yellow
                            is_finding=True
                        )
                    self.state["takeovers"].append(url)

        # Save results
        output_file = self.output_dir / "live_hosts.json"
        with open(output_file, "w", encoding="utf-8") as f:
            # Clean headers for JSON serialization
            clean_hosts = []
            for h in self.live_hosts:
                clean = dict(h)
                clean["headers"] = dict(list(h.get("headers", {}).items())[:10])
                clean_hosts.append(clean)
            json.dump(clean_hosts, f, indent=2, default=str)

        # Also save just the URLs
        urls_file = self.output_dir / "live_urls.txt"
        write_lines(str(urls_file), [h["url"] for h in self.live_hosts])

        duration = elapsed_str(start)
        self.phase_times.append(("Live Host Probing", duration, len(self.live_hosts)))

    async def _phase_port_scan(self):
        """Phase 4: High-Value Port Scanning"""
        if not self._should_run("portscan"):
            return
            
        start = time.time()
        log_phase(4, len(self.modules), "Infrastructure Port Scanning")
        
        if not self.live_hosts:
            log_warning("No live hosts available to scan for ports.")
            return
            
        # Extract hostnames from live URLs
        hostnames = [h.get("url", "").split("://")[-1].split("/")[0] for h in self.live_hosts]
        hostnames = [h for h in hostnames if h]
        
        log_info(f"Resolving {len(hostnames)} hostnames to IPs...")
        # Resolve to IPs synchronously for simplicity
        ips = resolve_hostnames(hostnames)
        
        if not ips:
            log_warning("Failed to resolve any IPs.")
            return
            
        scanner = PortScanner(ips)
        results = await scanner.scan()
        self.exposed_ports = results
        
        if results:
            output_file = self.output_dir / "exposed_ports.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
                
            for res in results:
                if res["port"] in [9090, 9200, 2375, 5601, 8500]:
                    await self._send_alert(
                        f"CRITICAL Infrastructure Exposed! 🚨",
                        f"**IP:** {res['ip']}\n**Port:** {res['port']}\n**Service:** {res['service']}\n**Banner:** {res.get('title', 'N/A')}",
                        16711680
                    )
                    
        duration = elapsed_str(start)
        self.phase_times.append(("Port Scanning", duration, len(results)))

    async def _phase_backup_gen(self):
        """Phase 5: Backup File Wordlist Generation."""
        if not self._should_run("backup"):
            return

        start = time.time()
        log_phase(5, len(self.modules), "Backup File Wordlist Generation")

        # Use live host URLs if available, else subdomains
        urls = [h["url"] for h in self.live_hosts] if self.live_hosts else list(self.subdomains)

        generator = BackupGenerator(urls=urls, active=self.active)
        self.backup_wordlist = await generator.generate()

        if self.active and self.backup_wordlist:
            for url in self.backup_wordlist:
                self._add_to_watchlist(url, "Live_Backup", "Found live backup file")
                await self._send_alert(
                    f"🚨 LIVE BACKUP FOUND — {self.domain}",
                    f"**Backup File:**\n```\n{url}\n```\nAdded to 24/7 Watchlist.",
                    16744448  # Orange
                )

        # Save results
        output_file = self.output_dir / "backup_wordlist.txt"
        write_lines(str(output_file), self.backup_wordlist, deduplicate=False)

        duration = elapsed_str(start)
        self.phase_times.append(("Backup Wordlist Generation", duration, len(self.backup_wordlist)))

    async def _phase_cred_hunt(self):
        """Phase 6: Credential & Secret Hunting"""
        if not self._should_run("credhunt"):
            return
            
        start = time.time()
        log_phase(6, len(self.modules), "Credential & Secret Hunting")
        
        # Pull Github Token from environment if available
        import os
        github_token = os.environ.get("GITHUB_TOKEN", "")
        
        # Use live backups found in Phase 5
        # The BackupGenerator returns live URLs if active=True, otherwise full list
        # If it returned a massive list (not active), we don't want to scan 50,000 files!
        # Only scan if active was true (urls start with http)
        live_configs = [u for u in self.backup_wordlist if u.startswith("http")]
        
        if not live_configs and not github_token:
            log_warning("No live config URLs and no GITHUB_TOKEN. Skipping credential hunt.")
            return
            
        hunter = CredentialHunter(self.domain, live_configs, github_token)
        results = await hunter.hunt()
        self.cred_findings = results
        
        if results:
            output_file = self.output_dir / "credentials_found.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
                
            for res in results:
                await self._send_alert(
                    f"CRITICAL: Hardcoded Credential Found! 🔑",
                    f"**Type:** {res['type']}\n**Source:** {res['source_type']}\n**URL:** {res['source']}\n**Secret:** `{res['redacted_value']}`",
                    16711680
                )
                
        duration = elapsed_str(start)
        self.phase_times.append(("Credential Hunting", duration, len(results)))

    async def _phase_js_extract(self):
        """Phase 7: JavaScript Analysis."""
        if not self._should_run("jsextract"):
            return
        if not self.live_hosts:
            log_warning("No live hosts for JS analysis")
            return

        start = time.time()
        log_phase(7, len(self.modules), "JavaScript Analysis")

        # Collect all JS URLs from probing results
        js_urls = []
        for host in self.live_hosts:
            js_urls.extend(host.get("js_files", []))

        js_urls = list(set(js_urls))
        if not js_urls:
            log_warning("No JavaScript files discovered")
            return

        log_info(f"Found {len(js_urls)} unique JS files to analyze")

        extractor = JSExtractor(js_urls=js_urls, base_url=f"https://{self.domain}")
        self.js_findings = await extractor.extract()
        
        # Check for critical secrets
        for secret in self.js_findings.get("secrets", []):
            if secret["severity"] in ("CRITICAL", "HIGH"):
                match_id = f"{secret['source']}:{secret['type']}"
                if match_id not in self.state["secrets"]:
                    emoji = "🚨" if secret["severity"] == "CRITICAL" else "🔑"
                    await self._send_alert(
                        f"{emoji} JS Secret: {secret['type']} — {self.domain}",
                        (f"**Severity:** {secret['severity']}\n"
                         f"**Type:** {secret['type']}\n\n"
                         f"**Leaked Value:**\n```\n{secret['match']}\n```\n"
                         f"**Found In:**\n```\n{secret['source']}\n```\n"
                         f"**Context:**\n```\n{secret.get('context', 'N/A')[:500]}\n```"),
                        16711680 if secret["severity"] == "CRITICAL" else 16753920
                    )
                    self.state["secrets"].append(match_id)

        # Save results
        output_file = self.output_dir / "js_findings.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.js_findings, f, indent=2, default=str)

        # Save endpoints separately
        if self.js_findings.get("endpoints"):
            ep_file = self.output_dir / "js_endpoints.txt"
            write_lines(str(ep_file), self.js_findings["endpoints"])

        total_findings = len(self.js_findings.get("endpoints", [])) + len(self.js_findings.get("secrets", []))
        duration = elapsed_str(start)
        self.phase_times.append(("JavaScript Analysis", duration, total_findings))

    async def _phase_schema_discovery(self):
        """Phase 7.5: API & Schema Discovery (Swagger, GraphQL, Feature Flags)."""
        if not self._should_run("schema"):
            return
        if not self.live_hosts:
            log_warning("No live hosts for schema discovery")
            return

        start = time.time()
        log_phase("7.5", len(self.modules), "API & Schema Discovery")

        live_domains = [h.get("hostname", "") for h in self.live_hosts if h.get("hostname")]
        if not live_domains:
            live_domains = [urlparse(h["url"]).hostname for h in self.live_hosts if h.get("url")]
            live_domains = [d for d in live_domains if d]

        scanner = SchemaDiscovery(
            live_domains=live_domains,
            output_dir=self.output_dir,
            concurrency=min(self.concurrency, 20),
        )
        self.schema_findings = await scanner.discover()

        # Alert on critical findings
        for finding in self.schema_findings.get("findings", []):
            sev = finding.get("severity", "INFO")
            if sev in ("CRITICAL", "HIGH"):
                emoji = "🚨" if sev == "CRITICAL" else "🔥"
                await self._send_alert(
                    f"{emoji} {finding['type']} Found — {self.domain}",
                    (f"**Severity:** {sev}\n"
                     f"**Type:** {finding['type']}\n"
                     f"**URL:** {finding['url']}\n"
                     f"**Domain:** {finding['domain']}"),
                    16711680 if sev == "CRITICAL" else 16744448
                )

        duration = elapsed_str(start)
        ep_count = len(self.schema_findings.get("api_endpoints", []))
        self.phase_times.append(("Schema Discovery", duration, ep_count))

    async def _phase_vt_url_scrape(self):
        """Phase 7.6: VirusTotal Per-Subdomain URL Scraping."""
        if not self._should_run("vtscrape"):
            return
        if not self.live_hosts:
            log_warning("No live hosts for VT URL scraping")
            return

        start = time.time()
        log_phase("7.6", len(self.modules), "VirusTotal URL Scraping")

        live_domains = [h.get("hostname", "") for h in self.live_hosts if h.get("hostname")]
        if not live_domains:
            from urllib.parse import urlparse
            live_domains = [urlparse(h["url"]).hostname for h in self.live_hosts if h.get("url")]
            live_domains = [d for d in live_domains if d]

        scraper = VTUrlScraper(
            subdomains=live_domains,
            output_dir=self.output_dir,
        )
        result = await scraper.scrape()
        self.vt_scraped_urls = set(result.get("urls", []))

        duration = elapsed_str(start)
        self.phase_times.append(("VT URL Scraping", duration, len(self.vt_scraped_urls)))

    async def _phase_web_crawl(self):
        """Phase 7.7: Active Web Crawling."""
        if not self._should_run("crawl"):
            return
        if not self.live_hosts:
            log_warning("No live hosts for web crawling")
            return

        start = time.time()
        log_phase("7.7", len(self.modules), "Active Web Crawling")

        live_domains = [h.get("hostname", "") for h in self.live_hosts if h.get("hostname")]
        if not live_domains:
            from urllib.parse import urlparse
            live_domains = [urlparse(h["url"]).hostname for h in self.live_hosts if h.get("url")]
            live_domains = [d for d in live_domains if d]

        crawler = WebCrawler(
            live_domains=live_domains,
            output_dir=self.output_dir,
            concurrency=min(self.concurrency, 15),
        )
        result = await crawler.crawl()
        self.crawled_endpoints = set(result.get("endpoints", []))

        duration = elapsed_str(start)
        self.phase_times.append(("Web Crawling", duration, len(self.crawled_endpoints)))

    async def _phase_waymore_url_collection(self):
        """Phase 8: Passive URL Collection via Waymore."""
        if not self._should_run("waymore"):
            return

        start = time.time()
        log_phase(8, len(self.modules), "Passive URL Collection")

        # Handle both Windows and Linux venv paths
        waymore_windows = Config.PROJECT_ROOT.parent / "venv" / "Scripts" / "waymore.exe"
        waymore_linux = Config.PROJECT_ROOT.parent / "venv" / "bin" / "waymore"
        
        if waymore_linux.exists():
            waymore_bin = waymore_linux
        elif waymore_windows.exists():
            waymore_bin = waymore_windows
        else:
            log_warning("Waymore not found. Skipping URL Collection.")
            return

        waymore_config = Config.PROJECT_ROOT / "waymore_config.yml"
        output_file = self.output_dir / "waymore_urls.txt"
        
        cmd = [
            str(waymore_bin),
            "-i", self.domain,
            "-mode", "U",
            "-oU", str(output_file),
        ]
        
        if waymore_config.exists():
            cmd.extend(["-c", str(waymore_config)])

        log_info(f"Running Waymore against {self.domain}...")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if output_file.exists():
                urls = read_lines(output_file)
                self.waymore_urls = set(urls)
                log_success(f"Waymore found {len(self.waymore_urls)} URLs")
            else:
                self.waymore_urls = set()
                log_warning("Waymore returned no URLs.")
        except Exception as e:
            log_error(f"Waymore error: {e}")
            self.waymore_urls = set()

        duration = elapsed_str(start)
        self.phase_times.append(("Waymore URL Collection", duration, len(self.waymore_urls)))

    async def _phase_passive_url_collect(self):
        """Phase 9: Multi-Source Passive URL Collection."""
        if not self._should_run("urlcollect"):
            return

        start = time.time()
        log_phase(9, len(self.modules), "Multi-Source Passive URL Collection")

        # Pass discovered subdomains for richer collection
        subdomain_list = list(self.subdomains)

        collector = PassiveURLCollector(
            domain=self.domain,
            subdomains=subdomain_list,
            concurrency=min(self.concurrency, 15),
        )
        result = await collector.collect()
        self.passive_collected_urls = set(result.get("urls", []))

        # Save raw collected URLs
        if self.passive_collected_urls:
            output_file = self.output_dir / "passive_collected_urls.txt"
            write_lines(str(output_file), sorted(self.passive_collected_urls))

        duration = elapsed_str(start)
        self.phase_times.append(("Passive URL Collection", duration, len(self.passive_collected_urls)))

    async def _phase_url_dedup(self):
        """Phase 9: URL Deduplication."""
        if not self._should_run("dedup"):
            return

        start = time.time()
        log_phase(9, len(self.modules), "Smart URL Deduplication")

        # Collect all URLs from ALL sources
        all_urls = [h["url"] for h in self.live_hosts]
        all_urls.extend(self.js_findings.get("endpoints", []))
        all_urls.extend(self.vt_urls)
        all_urls.extend(self.waymore_urls)
        all_urls.extend(self.vt_scraped_urls)  # VT per-subdomain URLs
        all_urls.extend(self.crawled_endpoints)  # Web crawler endpoints
        all_urls.extend(self.schema_findings.get("api_endpoints", []))  # Schema-extracted APIs
        all_urls.extend(self.passive_collected_urls)  # Multi-source passive (Wayback CDX, CC, OTX, URLScan, sitemaps)

        if not all_urls:
            log_warning("No URLs to deduplicate")
            return

        # Save ALL raw URLs before dedup for manual analysis
        all_urls_file = self.output_dir / "all_urls.txt"
        write_lines(str(all_urls_file), sorted(set(all_urls)))
        log_info(f"Saved {len(set(all_urls))} raw URLs to all_urls.txt")

        # Log source breakdown
        log_info(f"  Live hosts: {len(self.live_hosts)}")
        log_info(f"  JS endpoints: {len(self.js_findings.get('endpoints', []))}")
        log_info(f"  VT URLs: {len(self.vt_urls)}")
        log_info(f"  Waymore URLs: {len(self.waymore_urls)}")
        log_info(f"  VT scraped: {len(self.vt_scraped_urls)}")
        log_info(f"  Crawled: {len(self.crawled_endpoints)}")
        log_info(f"  Schema APIs: {len(self.schema_findings.get('api_endpoints', []))}")
        log_info(f"  Passive collected: {len(self.passive_collected_urls)}")

        deduplicator = URLDeduplicator()
        self.unique_urls = deduplicator.deduplicate(all_urls)

        # Save deduped results
        output_file = self.output_dir / "unique_urls.txt"
        write_lines(str(output_file), self.unique_urls, deduplicate=False)

        duration = elapsed_str(start)
        self.phase_times.append(("URL Deduplication", duration, len(self.unique_urls)))

    async def _verify_juicy_file(self, url: str) -> bool:
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
                        # If it's an HTML page/redirect (e.g. SPA fallback), verify its content
                        if "text/html" in content_type:
                            text = await resp.text(errors="ignore")
                            html_indicators = ["<!doctype html", "<html", "<head", "<body", "<script", "<title", "<div"]
                            if any(ind in text[:2048].lower() for ind in html_indicators):
                                return False # False positive HTML page
                        return True
                    return False
        except Exception:
            return False

    async def _phase_bounty_scan(self):
        """Phase 10: Passive Bounty URL Scan."""
        if not self._should_run("bountyscan"):
            return

        start = time.time()
        log_phase(10, len(self.modules), "Passive Bounty Scan")

        if not self.unique_urls:
            log_warning("No unique URLs available for bounty scanning.")
            return

        scanner = BountyScanner(self.unique_urls)
        results = scanner.scan()
        
        verified_findings = []
        self.bounty_stats = results["stats"]

        # Alert for ALL HIGH+ findings with full evidence, but perform active verification first
        severity_colors = {"CRITICAL": 16711680, "HIGH": 16744448}  # Red, Orange
        
        # Limit parallel verification requests
        semaphore = asyncio.Semaphore(15)
        
        async def verify_and_alert(finding):
            sev = finding["severity"]
            url = finding["url"]
            
            # Active verification for file/config findings to eliminate SPA routing FPs
            needs_active_verify = finding["type"] in ("Exposed_Config_File", "Debug_Admin_Panel")
            
            if needs_active_verify:
                async with semaphore:
                    is_real = await self._verify_juicy_file(url)
                if not is_real:
                    log_warning(f"Discarded false positive: {url}")
                    return
            
            # Record verified findings
            verified_findings.append(finding)
            
            if sev in severity_colors:
                self._add_to_watchlist(url, finding['type'], f"Bounty Scan: {sev} finding")
                emoji = "🚨" if sev == "CRITICAL" else "🎯"
                await self._send_alert(
                    f"{emoji} {sev}: {finding['type']} — {self.domain}",
                    (f"**Severity:** {sev}\n"
                     f"**Type:** {finding['type']}\n"
                     f"**Why:** {finding['description']}\n\n"
                     f"**Evidence URL:**\n```\n{finding['url']}\n```\n"
                     f"👆 Open this URL to verify the finding."),
                    severity_colors[sev]
                )

        # Run verification concurrently
        await asyncio.gather(*(verify_and_alert(f) for f in results["findings"]))
        
        self.bounty_flags = len(verified_findings)

        # Save findings
        if verified_findings:
            output_file = self.output_dir / "bounty_targets.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump({"findings": verified_findings, "stats": self.bounty_stats, "total_urls": len(self.unique_urls)}, f, indent=2)

        duration = elapsed_str(start)
        self.phase_times.append(("Bounty Scanning", duration, self.bounty_flags))

    async def _phase_report(self):
        """Phase 11: Report Generation."""
        if not self._should_run("report"):
            return []

        start = time.time()
        log_phase(11, len(self.modules), "Report Generation")

        self.report = ReportGenerator(self.domain, str(self.output_dir))
        self.report.set_subdomains(list(self.subdomains))
        self.report.set_live_hosts(self.live_hosts)
        self.report.set_js_findings(self.js_findings)
        self.report.set_backup_count(len(self.backup_wordlist))
        self.report.set_unique_urls(self.unique_urls)

        for name, dur, count in self.phase_times:
            self.report.add_phase(name, dur, count)

        paths = self.report.generate()

        duration = elapsed_str(start)
        self.phase_times.append(("Report Generation", duration, 2))

        return paths

    async def run(self):
        """Execute the full recon pipeline."""
        pipeline_start = time.time()

        banner("Recon Master — Pipeline Orchestrator")
        log_info(f"Target: {self.domain}")
        log_info(f"Modules: {', '.join(self.modules)}")
        log_info(f"Output: {self.output_dir}")
        if self.asns:
            log_info(f"ASNs: {', '.join(self.asns)}")
        if self.cidrs:
            log_info(f"CIDRs: {', '.join(self.cidrs)}")
            
        await self._send_alert(f"Recon Started: {self.domain}", f"Modules: {', '.join(self.modules)}", 3447003, is_finding=False)

        # Execute phases in order
        await self._phase_subdomain_enum()
        await self._phase_asn_discovery()
        await self._phase_live_probe()
        await self._phase_port_scan()
        await self._phase_backup_gen()
        await self._phase_cred_hunt()
        await self._phase_js_extract()
        await self._phase_schema_discovery()
        await self._phase_vt_url_scrape()
        await self._phase_web_crawl()
        await self._phase_waymore_url_collection()
        await self._phase_passive_url_collect()
        await self._phase_url_dedup()
        await self._phase_bounty_scan()
        report_paths = await self._phase_report()
        
        # Save state
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f)

        # Final summary
        total_time = elapsed_str(pipeline_start)
        
        await self._send_alert(
            f"Recon Complete: {self.domain} 🎯", 
            (f"**Duration:** {total_time}\n"
             f"**Subdomains:** {len(self.subdomains)}\n"
             f"**Live Hosts:** {len(self.live_hosts)}\n"
             f"**Exposed Ports:** {len(self.exposed_ports)}\n"
             f"**Credentials:** {len(self.cred_findings)}\n"
             f"**JS Endpoints:** {len(self.js_findings.get('endpoints', []))}\n"
             f"**Waymore URLs:** {len(self.waymore_urls)}\n"
             f"**Passive Collected:** {len(self.passive_collected_urls)}\n"
             f"**VT Scraped URLs:** {len(self.vt_scraped_urls)}\n"
             f"**Crawled Endpoints:** {len(self.crawled_endpoints)}\n"
             f"**Schema APIs:** {len(self.schema_findings.get('api_endpoints', []))}\n"
             f"**Unique URLs:** {len(self.unique_urls)}\n"
             f"**Secrets Found:** {len(self.js_findings.get('secrets', []))}\n"
             f"**Bounty Flags:** {self.bounty_flags}"),
            65280,
            is_finding=False
        )

        if RICH_AVAILABLE:
            from rich.panel import Panel
            from rich import box

            summary_lines = [
                f"[bold cyan]Target:[/bold cyan] {self.domain}",
                f"[bold cyan]Duration:[/bold cyan] {total_time}",
                f"[bold cyan]Output:[/bold cyan] {self.output_dir}",
                "",
                f"[bold green]Subdomains:[/bold green] {len(self.subdomains)}",
                f"[bold green]Live Hosts:[/bold green] {len(self.live_hosts)}",
                f"[bold green]JS Endpoints:[/bold green] {len(self.js_findings.get('endpoints', []))}",
                f"[bold green]VT URLs:[/bold green] {len(self.vt_urls)}",
                f"[bold green]VT Scraped:[/bold green] {len(self.vt_scraped_urls)}",
                f"[bold green]Crawled:[/bold green] {len(self.crawled_endpoints)}",
                f"[bold green]Schema APIs:[/bold green] {len(self.schema_findings.get('api_endpoints', []))}",
                f"[bold green]Waymore URLs:[/bold green] {len(self.waymore_urls)}",
                f"[bold green]Passive Collected:[/bold green] {len(self.passive_collected_urls)}",
                f"[bold green]Secrets:[/bold green] {len(self.js_findings.get('secrets', []))}",
                f"[bold green]Backup Paths:[/bold green] {len(self.backup_wordlist)}",
                f"[bold green]Unique URLs:[/bold green] {len(self.unique_urls)}",
            ]

            if report_paths:
                summary_lines.append("")
                summary_lines.append(f"[bold]📊 Report:[/bold] {report_paths.get('html', '')}")

            console.print(Panel(
                "\n".join(summary_lines),
                title="[bold white]🎯 Recon Complete[/bold white]",
                border_style="green",
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            ))
        else:
            print(f"\n{'='*50}")
            print(f"  RECON COMPLETE — {self.domain}")
            print(f"  Duration: {total_time}")
            print(f"  Output: {self.output_dir}")
            print(f"{'='*50}")


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recon Master — Automated Bug Bounty Reconnaissance Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipeline Phases:
  1. subdomain  — Multi-source subdomain enumeration
  2. asn        — ASN/CIDR hostname discovery
  3. probe      — Live host probing & tech fingerprinting
  4. backup     — Backup file wordlist generation
  5. jsextract  — JavaScript endpoint & secret extraction
  6. schema     — API & Schema Discovery (Swagger/GraphQL/FeatureFlags)
  7. vtscrape   — VirusTotal per-subdomain URL extraction
  8. crawl      — Active web crawling (BFS link extraction)
  9. waymore    — Passive URL collection via Wayback/CommonCrawl
 10. urlcollect — Multi-source passive URLs (WB CDX, CC, OTX, URLScan, sitemaps)
 11. dedup      — Smart URL deduplication
 12. bountyscan — High-value bounty heuristic filtering
 13. report     — HTML/JSON report generation

Examples:
  python recon_master.py -d example.com --full
  python recon_master.py -d example.com --modules subdomain,probe,schema,crawl
  python recon_master.py -d example.com -a AS15169 --full
  python recon_master.py -d example.com --brute --full
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--full", action="store_true", help="Run all modules")
    parser.add_argument("--modules", help="Comma-separated modules: " + ",".join(ALL_MODULES))
    parser.add_argument("-a", "--asn", help="ASN number(s), comma-separated")
    parser.add_argument("-c", "--cidr", help="CIDR block(s), comma-separated")
    parser.add_argument("--brute", action="store_true", help="Enable DNS brute-force in subdomain enum")
    parser.add_argument("--permutations", action="store_true", help="Enable subdomain permutations in enum phase")
    parser.add_argument("--active", action="store_true", help="Actively probe generated backup URLs")
    parser.add_argument("-o", "--output", help="Output directory (default: ./output/)")
    parser.add_argument("--concurrency", type=int, default=50, help="Max concurrent requests (default: 50)")

    args = parser.parse_args()

    # Determine modules
    if args.full:
        modules = ALL_MODULES[:]
    elif args.modules:
        modules = [m.strip().lower() for m in args.modules.split(",")]
        # Validate
        for m in modules:
            if m not in ALL_MODULES:
                parser.error(f"Unknown module: {m}. Valid: {', '.join(ALL_MODULES)}")
    else:
        # Default: subdomain + probe + report
        modules = ["subdomain", "probe", "report"]

    # If ASN provided, ensure asn module is included
    asns = [a.strip() for a in args.asn.split(",")] if args.asn else []
    cidrs = [c.strip() for c in args.cidr.split(",")] if args.cidr else []
    if (asns or cidrs) and "asn" not in modules:
        modules.insert(1, "asn")

    master = ReconMaster(
        domain=args.domain,
        asns=asns,
        cidrs=cidrs,
        modules=modules,
        brute=args.brute,
        permutations=args.permutations,
        active=args.active,
        output_dir=args.output,
        concurrency=args.concurrency,
    )

    asyncio.run(master.run())


if __name__ == "__main__":
    main()
