#!/usr/bin/env python3
"""
Module 5: JavaScript Endpoint & Secret Extraction
Extracts API endpoints, secrets, and sensitive data from JavaScript files.

Features:
- URL/endpoint extraction from JS files
- Secret detection (AWS, Google, JWT, private keys, etc.)
- Inline & external JS processing
- Severity classification of findings
"""

import argparse
import asyncio
import json
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse, urljoin

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error, log_finding,
    RateLimiter, read_lines, elapsed_str, console, RICH_AVAILABLE
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box


# ── Secret Patterns with Severity ────────────────────────────
SECRET_PATTERNS = {
    # Critical
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
    },
    "AWS Secret Key": {
        "pattern": r"""(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]""",
        "severity": "CRITICAL",
    },
    "Private Key": {
        "pattern": r"-----BEGIN\s*(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----",
        "severity": "CRITICAL",
    },
    "GitHub Token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": "CRITICAL",
    },

    # High
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "INFO",  # Most are restricted Maps keys; auto-validated below
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
        "severity": "HIGH",
    },
    "Stripe Secret Key": {
        "pattern": r"[sr]k_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "HIGH",
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "severity": "HIGH",
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "HIGH",
    },
    "Twilio API Key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "HIGH",
    },
    "Telegram Bot Token": {
        "pattern": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
        "severity": "HIGH",
    },

    # Medium
    "Generic API Key": {
        "pattern": r"""(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9\-._~+/]{16,}['"]?""",
        "severity": "MEDIUM",
    },
    "Generic Secret": {
        "pattern": r"""(?i)(secret|password|passwd|pwd|token|auth[_-]?key|access[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9\-._~+/]{8,}['"]?""",
        "severity": "MEDIUM",
    },
    "Bearer Token": {
        "pattern": r"""(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*""",
        "severity": "MEDIUM",
    },
    "Basic Auth": {
        "pattern": r"(?i)basic\s+[A-Za-z0-9+/=]{10,}",
        "severity": "MEDIUM",
    },
    "URL with Credentials": {
        "pattern": r"https?://[^/\s:]+:[^/\s:]+@[^/\s]+",
        "severity": "MEDIUM",
    },
    "Discord Webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "severity": "MEDIUM",
    },
    "Slack Webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "severity": "MEDIUM",
    },

    # Info
    "Internal IP": {
        "pattern": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        "severity": "INFO",
    },
    "Firebase URL": {
        "pattern": r"https?://[a-z0-9-]+\.firebaseio\.com",
        "severity": "INFO",
    },
    "S3 Bucket": {
        "pattern": r"""(?:https?://)?(?:[a-zA-Z0-9.-]+\.)?s3(?:[.-](?:ap|cn|eu|us|sa|af|me|ca)-(?:central|east|west|south|southeast|northeast|north|northwest)-\d)?\.amazonaws\.com""",
        "severity": "INFO",
    },
    "Email Address": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": "INFO",
    },
}

# ── Endpoint Extraction Pattern ──────────────────────────────
ENDPOINT_PATTERN = re.compile(
    r"""(?:"|')"""                           # Opening quote
    r"""("""
    r"""(?:[a-zA-Z]{1,10}://|//)"""          # Scheme
    r"""[^"'/]{1,}"""                         # Rest of absolute URL
    r"""|"""
    r"""(?:/|\.\./)"""                         # Relative path
    r"""[^"'><,;| *()(%%$^/\\\[\]]"""         # First char of path
    r"""[^"'><,;|()]{1,}"""                    # Rest of path
    r"""|"""
    r"""(?:[a-zA-Z0-9_\-/]{1,}/"""            # Path-like string
    r"""[a-zA-Z0-9_\-/]{1,}"""
    r"""\.(?:[a-zA-Z]{1,4}|action)"""          # File extension
    r"""(?:[\?|#][^"|']{0,}|))"""             # Query/fragment
    r"""|"""
    r"""(?:[a-zA-Z0-9_\-/]{1,}/"""            # API path
    r"""[a-zA-Z0-9_\-/]{3,}"""
    r"""(?:[\?|#][^"|']{0,}|))"""
    r""")"""
    r"""(?:"|')""",                            # Closing quote
    re.VERBOSE
)

# Simpler fallback endpoint patterns
SIMPLE_ENDPOINT_PATTERNS = [
    re.compile(r"""['"](/[a-zA-Z0-9_\-/.]+(?:\?[^'"]*)?)['"]\s*"""),
    re.compile(r"""['"](\.\./[a-zA-Z0-9_\-/.]+(?:\?[^'"]*)?)['"]\s*"""),
    re.compile(r"""['"]([a-zA-Z]{1,10}://[^'"]+)['"]\s*"""),
    re.compile(r"""['"]//([^'"]+)['"]\s*"""),
]


class JSExtractor:
    """Extract endpoints and secrets from JavaScript files."""

    def __init__(self, js_urls: list = None, base_url: str = None):
        self.js_urls = js_urls or []
        self.base_url = base_url
        self.endpoints: Set[str] = set()
        self.secrets: List[Dict] = []
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT)
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=20, resolver=aiohttp.ThreadedResolver())
            timeout = aiohttp.ClientTimeout(total=15)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": Config.USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _extract_endpoints_from_content(self, content: str, source_url: str) -> Set[str]:
        """Extract endpoints from JS content."""
        endpoints = set()

        # Try the complex pattern first
        matches = ENDPOINT_PATTERN.findall(content)
        endpoints.update(matches)

        # Try simple patterns
        for pattern in SIMPLE_ENDPOINT_PATTERNS:
            for match in pattern.findall(content):
                endpoints.add(match)

        # Resolve relative URLs
        resolved = set()
        base = source_url or self.base_url or ""

        for ep in endpoints:
            ep = ep.strip()
            if not ep or len(ep) < 3:
                continue

            # Skip obvious non-endpoints
            if ep in ("//", "/", "./", "../"):
                continue
            if any(ep.endswith(ext) for ext in [".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"]):
                continue

            if ep.startswith("//"):
                ep = "https:" + ep
            elif not ep.startswith("http://") and not ep.startswith("https://"):
                ep = urljoin(base, ep)

            resolved.add(ep)

        return resolved

    def _scan_secrets_in_content(self, content: str, source_url: str) -> List[Dict]:
        """Scan JS content for secrets and sensitive data."""
        findings = []

        for secret_name, config in SECRET_PATTERNS.items():
            pattern = config["pattern"]
            severity = config["severity"]

            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    match = str(match).strip()

                    # Skip very short matches or common false positives
                    if len(match) < 8:
                        continue
                    if match.lower() in ("password", "secret", "apikey", "token", "your_api_key", "api_key_here"):
                        continue

                    # Find context (line containing the match)
                    context = ""
                    for line in content.split("\n"):
                        if match in line:
                            context = line.strip()[:200]
                            break

                    findings.append({
                        "type": secret_name,
                        "severity": severity,
                        "match": match[:100],  # Truncate for safety
                        "source": source_url,
                        "context": context,
                    })
            except re.error:
                continue

        return findings

    async def _validate_google_key(self, api_key: str) -> bool:
        """Test if a Google API key is unrestricted (real bug) vs restricted Maps key (no impact)."""
        test_apis = [
            f"https://www.googleapis.com/customsearch/v1?q=test&key={api_key}",
            f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={api_key}",
            f"https://translation.googleapis.com/language/translate/v2?q=hello&target=es&key={api_key}",
        ]
        try:
            session = await self._get_session()
            for url in test_apis:
                async with session.get(url, timeout=8) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if not data.get("error"):
                            return True  # Unrestricted — real vulnerability!
        except Exception:
            pass
        return False  # Restricted Maps key — no impact

    async def _process_js_url(self, url: str) -> Dict:
        """Download and analyze a single JS file."""
        result = {"url": url, "endpoints": [], "secrets": [], "error": None}

        try:
            await self.rate_limiter.acquire()
            session = await self._get_session()
            async with session.get(url) as resp:
                if resp.status == 200:
                    content = await resp.text(encoding="utf-8", errors="ignore")
                    # Limit processing to 2MB files
                    content = content[:2_000_000]

                    # Extract endpoints
                    endpoints = self._extract_endpoints_from_content(content, url)
                    result["endpoints"] = list(endpoints)
                    self.endpoints.update(endpoints)

                    # Scan for secrets
                    secrets = self._scan_secrets_in_content(content, url)
                    
                    # Auto-validate Google API keys
                    for secret in secrets:
                        if secret["type"] == "Google API Key":
                            is_unrestricted = await self._validate_google_key(secret["match"])
                            if is_unrestricted:
                                secret["severity"] = "CRITICAL"
                                secret["type"] = "Google API Key (UNRESTRICTED)"
                                log_finding(f"[CRITICAL] Unrestricted Google API Key: {secret['match'][:20]}...")
                            # else stays INFO — restricted Maps key, no impact
                    
                    result["secrets"] = secrets
                    self.secrets.extend(secrets)
                    
                    # Try fetching the sourcemap (.js.map → unminified source code)
                    if not url.endswith(".map"):
                        map_url = url + ".map"
                        try:
                            async with session.get(map_url, timeout=aiohttp.ClientTimeout(total=10)) as map_resp:
                                if map_resp.status == 200:
                                    map_text = await map_resp.text(encoding="utf-8", errors="ignore")
                                    map_text = map_text[:5_000_000]  # Allow up to 5MB for maps
                                    
                                    # Try to parse as JSON and extract sourcesContent
                                    source_content = ""
                                    try:
                                        import json as _json
                                        map_data = _json.loads(map_text)
                                        # sourcesContent has the full unminified source code
                                        sources = map_data.get("sourcesContent", [])
                                        if sources:
                                            source_content = "\n".join([str(s) for s in sources if s])
                                    except Exception:
                                        # Not valid JSON, scan raw text
                                        source_content = map_text
                                    
                                    if source_content:
                                        # Log as HIGH finding — exposed source maps reveal original code
                                        self.secrets.append({
                                            "type": "Source Map Exposed",
                                            "severity": "HIGH",
                                            "match": map_url,
                                            "source": url,
                                            "context": f"Unminified source code exposed ({len(source_content)//1024}KB)",
                                        })
                                        result["secrets"].append({
                                            "type": "Source Map Exposed",
                                            "severity": "HIGH",
                                            "match": map_url,
                                            "source": url,
                                            "context": f"Unminified source code exposed ({len(source_content)//1024}KB)",
                                        })
                                        log_finding(f"[SOURCEMAP] Exposed source map: {map_url} ({len(source_content)//1024}KB)")
                                        
                                        # Scan the unminified source for secrets (dev comments, hardcoded keys)
                                        map_secrets = self._scan_secrets_in_content(source_content, map_url)
                                        result["secrets"].extend(map_secrets)
                                        self.secrets.extend(map_secrets)
                                        
                                        # Also extract endpoints from unminified source
                                        map_endpoints = self._extract_endpoints_from_content(source_content, map_url)
                                        result["endpoints"].extend(list(map_endpoints))
                                        self.endpoints.update(map_endpoints)
                        except Exception:
                            pass
                else:
                    result["error"] = f"HTTP {resp.status}"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def extract(self) -> Dict:
        """Process all JS files and extract data."""
        start = time.time()
        banner("JS Endpoint & Secret Extractor")
        log_info(f"Processing {len(self.js_urls)} JavaScript files...")

        results = []

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Analyzing JS files", total=len(self.js_urls))
                for url in self.js_urls:
                    result = await self._process_js_url(url)
                    results.append(result)
                    progress.advance(task)
        else:
            for url in self.js_urls:
                result = await self._process_js_url(url)
                results.append(result)

        await self.close()

        # Summary
        log_success(f"Analysis complete in {elapsed_str(start)}")
        log_success(f"Total endpoints: {len(self.endpoints)}")
        log_success(f"Total secrets: {len(self.secrets)}")

        # Display secrets by severity
        if self.secrets and RICH_AVAILABLE:
            table = Table(title="🔑 Secrets Found", box=box.SIMPLE_HEAVY)
            table.add_column("Severity", style="bold")
            table.add_column("Type", style="cyan")
            table.add_column("Match", max_width=50)
            table.add_column("Source", max_width=40)

            severity_colors = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "INFO": "blue",
            }

            for s in sorted(self.secrets, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "INFO"].index(x["severity"])):
                color = severity_colors.get(s["severity"], "white")
                table.add_row(
                    f"[{color}]{s['severity']}[/{color}]",
                    s["type"],
                    s["match"][:50],
                    s["source"].split("/")[-1][:40],
                )
            console.print(table)

        # Display some endpoints
        if self.endpoints and RICH_AVAILABLE:
            log_info(f"Sample endpoints (showing first 20 of {len(self.endpoints)}):")
            for ep in sorted(self.endpoints)[:20]:
                console.print(f"    [dim]→[/dim] {ep}")

        return {
            "endpoints": sorted(self.endpoints),
            "secrets": self.secrets,
            "files_processed": len(results),
            "files_with_errors": sum(1 for r in results if r["error"]),
        }


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JavaScript Endpoint & Secret Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_extractor.py -l js_urls.txt
  python js_extractor.py -u https://example.com/app.js
  python js_extractor.py -l js_urls.txt -o findings.json
  python js_extractor.py --probe-json alive.json
        """
    )
    parser.add_argument("-l", "--list", help="File with JS URLs (one per line)")
    parser.add_argument("-u", "--url", help="Single JS file URL to analyze")
    parser.add_argument("--probe-json", help="Use probe results JSON (extracts JS URLs)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--base-url", help="Base URL for resolving relative paths")

    args = parser.parse_args()

    js_urls = []
    if args.url:
        js_urls.append(args.url)
    if args.list:
        js_urls.extend(read_lines(args.list))
    if args.probe_json:
        # Extract JS URLs from probe results
        probe_path = Path(args.probe_json)
        if probe_path.exists():
            with open(probe_path, "r") as f:
                probe_data = json.load(f)
            for host in probe_data:
                js_urls.extend(host.get("js_files", []))
            log_info(f"Extracted {len(js_urls)} JS URLs from probe results")

    if not js_urls:
        parser.error("Provide JS URLs via --list, --url, or --probe-json")

    # Deduplicate
    js_urls = list(set(js_urls))

    extractor = JSExtractor(js_urls=js_urls, base_url=args.base_url)
    results = asyncio.run(extractor.extract())

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        log_success(f"Results saved to {output_path}")
    else:
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
