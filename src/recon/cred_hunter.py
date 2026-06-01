#!/usr/bin/env python3
"""
Module: Credential & Secret Hunter
Actively scrapes exposed config files and OSINT (GitHub) for hardcoded secrets and employee credentials.
"""

import asyncio
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, elapsed_str, RateLimiter, RICH_AVAILABLE

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
    from rich.console import Console
    console = Console()
else:
    console = None

# Regex patterns for high-value secrets
SECRET_REGEXES = {
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws_(?:secret_access_key|secret_key|access_key_id|access_key)\s*={0,1}\s*['\"]?([A-Za-z0-9/\+=]{40})['\"]?",
    "Stripe API Key": r"(?:sk_live|pk_live|rk_live)_[a-zA-Z0-9]{24}",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "GitHub PAT": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
    "Database Password": r"(?i)(?:db_password|database_password|db_pass|database_pass|postgres_password|mysql_password)\s*[:=]\s*['\"]?([^'\"\s\n]{3,})['\"]?",
    "MongoDB URI": r"mongodb(?:\+srv)?:\/\/[^\s\'\"\/]+:[^\s\'\"\/]+@[^\s\'\"\/]+",
    "Generic Password": r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?([^'\"\s\n]{5,})['\"]?"
}

class CredentialHunter:
    def __init__(self, target_domain: str, config_urls: List[str], github_token: str = None, concurrency: int = 20):
        self.target_domain = target_domain
        self.config_urls = config_urls
        self.github_token = github_token
        self.concurrency = concurrency
        self.findings = []
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT)
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=self.concurrency, resolver=aiohttp.ThreadedResolver())
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": Config.USER_AGENT}
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _extract_secrets(self, text: str, source: str, source_type: str):
        """Run regexes against text to find secrets."""
        for secret_name, regex in SECRET_REGEXES.items():
            matches = re.finditer(regex, text)
            for match in matches:
                # Get the matched value (prefer group 1 if it exists)
                if len(match.groups()) > 0:
                    matched_value = match.group(1)
                else:
                    matched_value = match.group(0)
                
                # Filter out obvious false positives
                if len(matched_value) < 5 or matched_value.lower() in ['true', 'false', 'null', 'undefined', 'password', 'secret']:
                    continue
                    
                # Redact the secret for safe logging
                redacted = matched_value[:4] + "***" + matched_value[-4:] if len(matched_value) > 8 else "***"

                finding = {
                    "type": secret_name,
                    "redacted_value": redacted,
                    "source": source,
                    "source_type": source_type
                }
                
                # Prevent duplicate findings for the same source
                if finding not in self.findings:
                    self.findings.append(finding)

    async def _scan_config_url(self, url: str, semaphore: asyncio.Semaphore):
        """Download and scan a configuration file."""
        async with semaphore:
            await self.rate_limiter.acquire()
            try:
                session = await self._get_session()
                async with session.get(url, allow_redirects=True, timeout=10) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "").lower()
                        # Ignore binary or large files
                        if "text/" in content_type or "application/json" in content_type or url.endswith((".env", ".yml", ".yaml", ".ini", ".conf", ".bak", ".config")):
                            text = await resp.text(errors="ignore")
                            # Defense-in-depth: If it's an HTML page/redirect (SPA routing fallback), discard it
                            if "text/html" in content_type or "<html" in text[:500].lower():
                                html_indicators = ["<!doctype html", "<html", "<head", "<body", "<script", "<title", "<div"]
                                if any(ind in text[:2048].lower() for ind in html_indicators):
                                    return # Ignore false positive HTML pages
                            
                            # Cap size to 2MB to prevent OOM
                            self._extract_secrets(text[:2_000_000], url, "Live Config File")
            except Exception:
                pass

    async def _scan_github(self):
        """Scan GitHub API for leaked credentials."""
        if not self.github_token:
            log_warning("No GitHub Token provided. Skipping OSINT credential hunt.")
            return

        log_info(f"Querying GitHub API for leaked credentials related to {self.target_domain}...")
        
        # High value search queries
        queries = [
            f'"{self.target_domain}" password',
            f'"{self.target_domain}" API_KEY',
            f'"{self.target_domain}" AWS_SECRET',
        ]
        
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        session = await self._get_session()
        
        for q in queries:
            try:
                # GitHub code search API
                encoded_q = urllib.parse.quote(q)
                url = f"https://api.github.com/search/code?q={encoded_q}"
                
                async with session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        
                        for item in items[:10]: # Only check top 10 results per query to avoid rate limits
                            repo_name = item.get("repository", {}).get("full_name", "")
                            file_url = item.get("html_url", "")
                            
                            # We can just record the file URL as a finding for manual review
                            finding = {
                                "type": "GitHub Code Leak (Manual Review)",
                                "redacted_value": f"Matches: {q}",
                                "source": file_url,
                                "source_type": f"GitHub Repo: {repo_name}"
                            }
                            if finding not in self.findings:
                                self.findings.append(finding)
                                
                    elif resp.status == 403:
                        log_warning("GitHub API rate limit exceeded or invalid token.")
                        break
                        
                # GitHub API requires sleeping between requests
                await asyncio.sleep(2)
                
            except Exception as e:
                log_error(f"GitHub Search Error: {e}")

    async def hunt(self) -> List[Dict]:
        start = time.time()
        banner("Credential & Secret Hunter")
        
        # Phase 1: GitHub OSINT
        await self._scan_github()
        
        # Phase 2: Live Config Scraping
        if self.config_urls:
            log_info(f"Scraping {len(self.config_urls)} live configuration files for hardcoded secrets...")
            semaphore = asyncio.Semaphore(self.concurrency)
            tasks = [self._scan_config_url(url, semaphore) for url in self.config_urls]
            
            if RICH_AVAILABLE:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                ) as progress:
                    task_id = progress.add_task("[cyan]Scraping Configs...", total=len(tasks))
                    for coro in asyncio.as_completed(tasks):
                        await coro
                        progress.advance(task_id)
            else:
                await asyncio.gather(*tasks)
        else:
            log_warning("No live configuration URLs provided for scraping.")

        await self.close()
        
        log_success(f"Credential Hunt completed in {elapsed_str(start)}")
        if self.findings:
            log_success(f"Found {len(self.findings)} critical secret exposures!")
        else:
            log_info("No obvious hardcoded credentials found.")
            
        return self.findings
