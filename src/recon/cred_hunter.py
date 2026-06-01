#!/usr/bin/env python3
"""
Module: Credential & Secret Hunter
Scrapes exposed config files for hardcoded secrets and generates
comprehensive GitHub dork queries for manual OSINT hunting.

GitHub API search is too rate-limited for automation, so this module
generates ready-to-paste search queries and saves them to a file.
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
import tldextract

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    log_info, log_success, log_warning, log_error, log_finding,
    banner, elapsed_str, write_lines, RateLimiter, RICH_AVAILABLE
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
    from rich.console import Console
    console = Console()
else:
    console = None

# ── Secret Regex Patterns (expanded) ──────────────────────────────────────
SECRET_REGEXES = {
    # Cloud Provider Keys
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"""(?i)aws_(?:secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Client ID": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
    "Azure Storage Key": r"""(?i)(?:AccountKey|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?""",
    "GCP Service Account": r'"type"\s*:\s*"service_account"',

    # Payment / SaaS
    "Stripe API Key": r"(?:sk_live|pk_live|rk_live)_[a-zA-Z0-9]{24,}",
    "Stripe Test Key": r"(?:sk_test|pk_test|rk_test)_[a-zA-Z0-9]{24,}",
    "Twilio Account SID": r"AC[a-f0-9]{32}",
    "Twilio Auth Token": r"""(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun API Key": r"key-[a-zA-Z0-9]{32}",

    # Tokens
    "Slack Token": r"xox[bpoa]-[0-9]{10,13}-[a-zA-Z0-9\-]+",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "GitHub PAT": r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
    "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+",

    # Database
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
    "PostgreSQL URI": r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
    "MySQL URI": r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
    "Redis URI": r"redis://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",

    # Generic Secrets
    "Database Password": r"""(?i)(?:db_password|database_password|db_pass|postgres_password|mysql_password|mysql_pwd)\s*[=:]\s*['"]?([^'"\\s\\n]{5,})['"]?""",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic API Key": r"""(?i)(?:api[_\-]?key|api[_\-]?secret|auth[_\-]?token|access[_\-]?token|secret[_\-]?key)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""",
    "Bearer Token": r"""(?i)(?:bearer|authorization)\s*[=:]\s*['"]?Bearer\s+([a-zA-Z0-9_\-.]+)['"]?""",
    "Generic Password": r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]""",
}

# ── Config file paths to probe on live hosts ──────────────────────────────
CONFIG_PROBE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.development",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/configuration.json",
    "/settings.json",
    "/settings.yml",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/web.config",
    "/appsettings.json",
    "/appsettings.Development.json",
    "/application.yml",
    "/application.properties",
    "/database.yml",
    "/secrets.json",
    "/credentials.json",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/debug/vars",
    "/debug/pprof",
    "/.well-known/openid-configuration",
    "/swagger.json",
    "/api-docs",
    "/graphql",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/health",
]


class CredentialHunter:
    def __init__(self, target_domain: str, config_urls: List[str], github_token: str = None, concurrency: int = 20):
        self.target_domain = target_domain
        ext = tldextract.extract(target_domain)
        self.company_name = ext.domain
        self.config_urls = config_urls
        self.github_token = github_token
        self.concurrency = concurrency
        self.findings = []
        self.github_dorks = []
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
                if match.lastindex and match.lastindex >= 1:
                    matched_value = match.group(1)
                else:
                    matched_value = match.group(0)
                
                if not matched_value:
                    continue

                # Filter out obvious false positives
                fp_words = [
                    'true', 'false', 'null', 'undefined', 'password', 'secret',
                    'example', 'your_', 'xxx', 'placeholder', 'change_me',
                    'insert', 'replace', 'todo', 'fixme', 'CHANGE',
                ]
                if len(matched_value) < 5 or matched_value.lower() in fp_words:
                    continue
                if any(fp in matched_value.lower() for fp in ['example', 'your_', 'xxx', 'placeholder', 'change_me']):
                    continue
                    
                # Redact the secret for safe logging
                if len(matched_value) > 12:
                    redacted = matched_value[:6] + "***" + matched_value[-4:]
                elif len(matched_value) > 8:
                    redacted = matched_value[:4] + "***" + matched_value[-4:]
                else:
                    redacted = "***"

                finding = {
                    "type": secret_name,
                    "redacted_value": redacted,
                    "source": source,
                    "source_type": source_type
                }
                
                # Prevent duplicate findings
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
                        # Accept text, JSON, YAML, and files with config extensions
                        if ("text/" in content_type or
                            "application/json" in content_type or
                            "application/yaml" in content_type or
                            "application/xml" in content_type or
                            url.endswith((".env", ".yml", ".yaml", ".ini", ".conf",
                                         ".bak", ".config", ".json", ".properties",
                                         ".xml", ".toml"))):
                            text = await resp.text(errors="ignore")
                            
                            # Defense: If it's a full HTML page (SPA fallback), discard
                            if "text/html" in content_type:
                                html_indicators = ["<!doctype html", "<html", "<head", "<body", "<script", "<title"]
                                if any(ind in text[:2048].lower() for ind in html_indicators):
                                    return
                            
                            # Cap size to 2MB
                            self._extract_secrets(text[:2_000_000], url, "Live Config File")
            except Exception:
                pass

    async def _probe_config_paths(self, base_urls: List[str]):
        """Actively probe common config file paths on live hosts."""
        if not base_urls:
            return
        
        log_info(f"Probing {len(base_urls)} hosts for {len(CONFIG_PROBE_PATHS)} common config paths...")
        
        probe_urls = []
        for base in base_urls[:20]:  # Cap at 20 hosts to avoid being too noisy
            base = base.rstrip("/")
            for path in CONFIG_PROBE_PATHS:
                probe_urls.append(f"{base}{path}")
        
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._scan_config_url(url, semaphore) for url in probe_urls]
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
            ) as progress:
                task_id = progress.add_task("[cyan]Probing config paths...", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

    def _generate_github_dorks(self) -> List[str]:
        """Generate comprehensive GitHub search dork queries as full clickable URLs."""
        domain = self.target_domain
        company = self.company_name
        
        def dork_url(query: str) -> str:
            """Convert a search query into a full GitHub code search URL."""
            from urllib.parse import quote
            return f"https://github.com/search?q={quote(query)}&type=code"
        
        dorks = []
        
        # ── Category 1: Direct credential leaks ──
        dorks.append(f"# ═══ CREDENTIAL LEAKS ═══")
        dorks.append(dork_url(f'"{domain}" password'))
        dorks.append(dork_url(f'"{domain}" secret'))
        dorks.append(dork_url(f'"{domain}" api_key'))
        dorks.append(dork_url(f'"{domain}" apikey'))
        dorks.append(dork_url(f'"{domain}" access_token'))
        dorks.append(dork_url(f'"{domain}" auth_token'))
        dorks.append(dork_url(f'"{domain}" client_secret'))
        dorks.append(dork_url(f'"{domain}" private_key'))
        
        # ── Category 2: Database connections ──
        dorks.append(f"# ═══ DATABASE CONNECTIONS ═══")
        dorks.append(dork_url(f'"{domain}" mongodb+srv'))
        dorks.append(dork_url(f'"{domain}" postgres://'))
        dorks.append(dork_url(f'"{domain}" mysql://'))
        dorks.append(dork_url(f'"{domain}" redis://'))
        dorks.append(dork_url(f'"{domain}" jdbc:'))
        dorks.append(dork_url(f'"{domain}" DATABASE_URL'))
        
        # ── Category 3: Cloud credentials ──
        dorks.append(f"# ═══ CLOUD CREDENTIALS ═══")
        dorks.append(dork_url(f'"{domain}" AWS_SECRET_ACCESS_KEY'))
        dorks.append(dork_url(f'"{domain}" AWS_ACCESS_KEY_ID'))
        dorks.append(dork_url(f'"{domain}" AKIA'))
        dorks.append(dork_url(f'"{domain}" s3.amazonaws.com'))
        dorks.append(dork_url(f'"{company}" GOOGLE_API_KEY'))
        dorks.append(dork_url(f'"{company}" firebase'))
        dorks.append(dork_url(f'"{domain}" AZURE_STORAGE'))
        
        # ── Category 4: .env and config files ──
        dorks.append(f"# ═══ CONFIGURATION FILES ═══")
        dorks.append(dork_url(f'"{domain}" filename:.env'))
        dorks.append(dork_url(f'"{domain}" filename:.env.local'))
        dorks.append(dork_url(f'"{domain}" filename:.env.production'))
        dorks.append(dork_url(f'"{domain}" filename:config.json'))
        dorks.append(dork_url(f'"{domain}" filename:config.yml'))
        dorks.append(dork_url(f'"{domain}" filename:docker-compose.yml'))
        dorks.append(dork_url(f'"{domain}" filename:settings.py'))
        dorks.append(dork_url(f'"{domain}" filename:application.properties'))
        dorks.append(dork_url(f'"{domain}" filename:wp-config.php'))
        dorks.append(dork_url(f'"{company}" filename:.npmrc _authToken'))
        dorks.append(dork_url(f'"{company}" filename:.dockercfg'))
        dorks.append(dork_url(f'"{company}" filename:id_rsa'))
        dorks.append(dork_url(f'"{company}" filename:credentials'))
        
        # ── Category 5: Internal / staging endpoints ──
        dorks.append(f"# ═══ INTERNAL ENDPOINTS ═══")
        dorks.append(dork_url(f'"{domain}" staging'))
        dorks.append(dork_url(f'"{domain}" internal'))
        dorks.append(dork_url(f'"{domain}" dev.{company}'))
        dorks.append(dork_url(f'"{domain}" admin'))
        dorks.append(dork_url(f'"{domain}" swagger'))
        dorks.append(dork_url(f'"{domain}" graphql'))
        dorks.append(dork_url(f'"{domain}" /api/v1'))
        
        # ── Category 6: Payment / tokens ──
        dorks.append(f"# ═══ PAYMENT & TOKENS ═══")
        dorks.append(dork_url(f'"{domain}" sk_live'))
        dorks.append(dork_url(f'"{domain}" pk_live'))
        dorks.append(dork_url(f'"{company}" twilio'))
        dorks.append(dork_url(f'"{company}" sendgrid'))
        dorks.append(dork_url(f'"{company}" mailgun'))
        dorks.append(dork_url(f'"{domain}" slack webhook'))
        dorks.append(dork_url(f'"{domain}" discord webhook'))
        
        # ── Category 7: Organization-specific ──
        dorks.append(f"# ═══ ORGANIZATION SEARCH ═══")
        dorks.append(dork_url(f'org:{company} password'))
        dorks.append(dork_url(f'org:{company} secret'))
        dorks.append(dork_url(f'org:{company} filename:.env'))
        dorks.append(dork_url(f'org:{company} filename:config'))
        dorks.append(dork_url(f'org:{company} PRIVATE KEY'))
        dorks.append(dork_url(f'org:{company} TODO fix security'))
        
        # ── Category 8: Trufflehog style ──
        dorks.append(f"# ═══ HIGH-ENTROPY SECRETS ═══")
        dorks.append(dork_url(f'"{domain}" BEGIN RSA PRIVATE KEY'))
        dorks.append(dork_url(f'"{domain}" BEGIN OPENSSH PRIVATE KEY'))
        dorks.append(dork_url(f'"{company}" ssh-rsa AAAA'))
        dorks.append(dork_url(f'"{company}" BEGIN CERTIFICATE'))
        
        return dorks

    async def hunt(self) -> List[Dict]:
        start = time.time()
        banner("Credential & Secret Hunter")
        
        # ── Phase 1: Generate GitHub Dorks (manual OSINT) ──
        log_info("Generating GitHub dork queries for manual OSINT...")
        self.github_dorks = self._generate_github_dorks()
        
        # Count actual queries (not category headers)
        query_count = len([d for d in self.github_dorks if not d.startswith("#")])
        log_success(f"Generated {query_count} clickable GitHub dork URLs across 8 categories.")
        log_info("Each link opens directly in GitHub code search — just click!")
        
        # Print a few examples
        examples = [d for d in self.github_dorks if not d.startswith("#")][:5]
        for ex in examples:
            log_info(f"  → {ex}")
        log_info(f"  ... and {query_count - 5} more (saved to output file)")
        
        # ── Phase 2: Active Config Probing ──
        # Build base URLs from config_urls or domain
        if self.config_urls:
            # Extract base URLs from provided config URLs
            base_urls = list(set(
                f"{urllib.parse.urlparse(u).scheme}://{urllib.parse.urlparse(u).netloc}"
                for u in self.config_urls if u.startswith("http")
            ))
            
            # First scan the explicitly provided config URLs
            log_info(f"Scanning {len(self.config_urls)} provided configuration URLs...")
            semaphore = asyncio.Semaphore(self.concurrency)
            tasks = [self._scan_config_url(url, semaphore) for url in self.config_urls]
            
            if RICH_AVAILABLE:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                ) as progress:
                    task_id = progress.add_task("[cyan]Scanning provided configs...", total=len(tasks))
                    for coro in asyncio.as_completed(tasks):
                        await coro
                        progress.advance(task_id)
            else:
                await asyncio.gather(*tasks)
            
            # Then probe common config paths on the same hosts
            await self._probe_config_paths(base_urls)
        else:
            # No config URLs — probe the domain directly
            base_urls = [f"https://www.{self.target_domain}", f"https://{self.target_domain}"]
            await self._probe_config_paths(base_urls)

        await self.close()
        
        # ── Results ──
        log_success(f"Credential Hunt completed in {elapsed_str(start)}")
        if self.findings:
            log_success(f"Found {len(self.findings)} secret exposures!")
            for f in self.findings[:10]:
                log_finding(f"  [{f['type']}] {f['redacted_value']} — {f['source_type']}")
        else:
            log_info("No hardcoded credentials found in live config files.")
            log_info("Run the GitHub dorks manually for deeper OSINT results.")
            
        return self.findings

    def get_github_dorks(self) -> List[str]:
        """Return the generated GitHub dork queries."""
        if not self.github_dorks:
            self.github_dorks = self._generate_github_dorks()
        return self.github_dorks
