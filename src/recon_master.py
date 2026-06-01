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
from recon.semantic_fuzzer import SemanticFuzzer
from recon.saas_hunter import SaasHunter
from recon.apk_extractor import APKExtractor
from recon.cache_deception import CacheDeceptionScanner
from recon.headless_hooker import HeadlessHooker
from recon.historical_js import HistoricalJS


ALL_MODULES = ["subdomain", "asn", "probe", "portscan", "backup", "credhunt", "jsextract", "waymore", "dedup", "bountyscan", "deep", "report"]


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
        deep: bool = False,
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
        self.deep = deep
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
        
        # Check for takeovers
        for host in self.live_hosts:
            if host.get("takeover"):
                tk = host["takeover"]
                url = host["url"]
                if url not in self.state["takeovers"]:
                    await self._send_alert(
                        "Subdomain Takeover Detected! 🚨",
                        f"**URL:** {url}\n**Service:** {tk}\n\n*Verify immediately via CNAME lookups or registration portals to claim this bounty!*",
                        16711680,
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
            if not github_token:
                log_info("To enable GitHub Secret Hunting:")
                log_info("  1. Go to https://github.com/settings/tokens")
                log_info("  2. Generate new token (classic) with 'repo' and 'read:org' scopes")
                log_info("  3. Set it via: set GITHUB_TOKEN=ghp_... (Windows) or export GITHUB_TOKEN=ghp_... (Linux)")
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

    async def _phase_url_dedup(self):
        """Phase 9: URL Deduplication."""
        if not self._should_run("dedup"):
            return

        start = time.time()
        log_phase(9, len(self.modules), "Smart URL Deduplication")

        # Collect all URLs from live hosts + JS endpoints + VirusTotal + Waymore
        all_urls = [h["url"] for h in self.live_hosts]
        all_urls.extend(self.js_findings.get("endpoints", []))
        all_urls.extend(self.vt_urls)
        all_urls.extend(self.waymore_urls)

        if not all_urls:
            log_warning("No URLs to deduplicate")
            return

        deduplicator = URLDeduplicator()
        self.unique_urls = deduplicator.deduplicate(all_urls)

        # Save results
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
            
            # Check if this is a file or endpoint where false positives commonly occur
            is_juicy_file = finding["type"] in ("Juicy_Files", "Exposed_Dashboards")
            
            if is_juicy_file:
                async with semaphore:
                    is_real = await self._verify_juicy_file(url)
                if not is_real:
                    log_warning(f"Discarded false positive juicy target: {url}")
                    return
            
            # Record verified findings
            verified_findings.append(finding)
            
            if sev in severity_colors:
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

    async def _phase_deep_recon(self):
        """Phase X: Deep Elite Recon (SaaS, Semantic, Cache Deception)."""
        if not self._should_run("deep") and not self.deep:
            return

        start = time.time()
        log_phase(len(self.modules), len(self.modules), "Deep Elite Recon")
        
        # 1. SaaS Hunter
        log_info("Running SaaS Hunter...")
        hunter = SaasHunter(self.domain)
        saas_findings = await hunter.hunt()
        if saas_findings:
            output_file = self.output_dir / "saas_findings.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(saas_findings, f, indent=2)
                
        # 2. Semantic Fuzzer
        log_info("Generating Semantic API Wordlist...")
        fuzzer = SemanticFuzzer(self.domain)
        wordlist = await fuzzer.generate()
        if wordlist:
            output_file = self.output_dir / "semantic_api_wordlist.txt"
            write_lines(str(output_file), wordlist)
            
            # Actively Fuzz top 50 hosts
            base_urls = [h["url"] for h in self.live_hosts][:50]
            if not base_urls:
                base_urls = [f"https://{self.domain}"]
            
            active_endpoints = await fuzzer.active_fuzz(base_urls, wordlist)
            if active_endpoints:
                fuzz_output = self.output_dir / "semantic_active_findings.txt"
                write_lines(str(fuzz_output), active_endpoints)

        # 3. Mobile APK API Extraction
        log_info("Running Mobile APK Extractor...")
        apk = APKExtractor(self.domain)
        apk_results = await apk.extract()
        if apk_results["endpoints"] or apk_results["secrets"]:
            output_file = self.output_dir / "apk_findings.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(apk_results, f, indent=2)

        # 4. Cache Deception
        log_info("Running Edge Node Cache Deception Scanner...")
        cd_scanner = CacheDeceptionScanner(self.unique_urls)
        cd_findings = await cd_scanner.scan()
        if cd_findings:
            output_file = self.output_dir / "cache_deception.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(cd_findings, f, indent=2)

        # 5. Headless Hooker
        log_info("Running Headless JS Hooker...")
        headless_targets = [h["url"] for h in self.live_hosts][:50]
        hooker = HeadlessHooker(headless_targets)
        hooker_endpoints = await hooker.run()
        if hooker_endpoints:
            output_file = self.output_dir / "headless_endpoints.txt"
            write_lines(str(output_file), hooker_endpoints)

        # 6. Historical JS
        log_info("Running Historical JS Archeology...")
        js_urls = []
        for host in self.live_hosts:
            js_urls.extend(host.get("js_files", []))
        js_urls = list(set(js_urls))
        
        archeology = HistoricalJS(js_urls)
        historical_endpoints = await archeology.run()
        if historical_endpoints:
            output_file = self.output_dir / "historical_endpoints.txt"
            write_lines(str(output_file), historical_endpoints)

        total_deep = len(saas_findings) + len(wordlist) + len(apk_results["endpoints"]) + len(cd_findings) + len(hooker_endpoints) + len(historical_endpoints)
        duration = elapsed_str(start)
        self.phase_times.append(("Deep Elite Recon", duration, total_deep))

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
        await self._phase_waymore_url_collection()
        await self._phase_url_dedup()
        await self._phase_bounty_scan()
        await self._phase_deep_recon()
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
                f"[bold green]Waymore URLs:[/bold green] {len(self.waymore_urls)}",
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
  6. waymore    — Passive URL collection via Wayback/CommonCrawl
  7. dedup      — Smart URL deduplication
  8. bountyscan — High-value bounty heuristic filtering
  9. report     — HTML/JSON report generation

Examples:
  python recon_master.py -d example.com --full
  python recon_master.py -d example.com --modules subdomain,probe,backup
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
    parser.add_argument("--deep", action="store_true", help="Enable elite deep recon modules (SaaS hunter, Semantic fuzzing, etc.)")
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
        deep=args.deep,
        output_dir=args.output,
        concurrency=args.concurrency,
    )

    asyncio.run(master.run())


if __name__ == "__main__":
    main()
