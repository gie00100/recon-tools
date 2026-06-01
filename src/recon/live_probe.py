#!/usr/bin/env python3
"""
Module 3: Live Host Prober & Tech Fingerprinter
Enhanced httpx-style prober with async HTTP/HTTPS probing,
technology fingerprinting, WAF detection, and title extraction.
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
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.exception

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error, log_finding,
    RateLimiter, read_lines, write_lines, elapsed_str,
    console, RICH_AVAILABLE
)

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
    from rich.table import Table
    from rich import box


# WAF signatures in headers / response bodies
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "Akamai": ["akamai", "x-akamai", "akamaighost"],
    "AWS WAF": ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "Imperva": ["imperva", "incapsula", "x-iinfo", "visid_incap"],
    "F5 BIG-IP": ["bigip", "f5", "x-wa-info"],
    "Barracuda": ["barracuda", "barra_counter_session"],
    "ModSecurity": ["modsecurity", "mod_security"],
    "Fortinet": ["fortigate", "fortiWeb", "fgd_"],
    "DDoS-Guard": ["ddos-guard"],
    "Varnish": ["x-varnish", "via: varnish"],
}

# Subdomain Takeover signatures (response body)
TAKEOVER_SIGNATURES = {
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "AWS S3": "The specified bucket does not exist",
    "Fastly": "Fastly error: unknown domain",
    "Zendesk": "Help Center Closed",
    "Azure": "404 Web Site not found",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Tumblr": "Whatever you were looking for doesn't currently exist at this address",
    "WordPress": "Do you want to register",
    "Ghost": "The thing you were looking for is no longer here",
    "Pantheon": "The magic starts here",
    "Bitbucket": "Repository not found",
    "AWS S3 (Alternative)": "NoSuchBucket",
    "Azure Traffic Manager": "invalid host",
    "Azure (Alternative)": "Web App - Unavailable",
    "Elastic Beanstalk": "NoSuchKey",
    "Campaign Monitor": "Double check the URL",
    "Cargo Collective": "If you're looking for something that used to be here",
    "Feedpress": "The feed has not been found",
    "Help Juice": "We could not find what you're looking for",
    "Intercom": "This domain is not configured for Cloudfront",
    "Pingdom": "Public Back-End",
    "Readme.io": "Project not found",
    "Surge.sh": "project not found",
    "Webflow": "The page you are looking for doesn't exist",
    "Unbounce": "The requested URL was not found on this server"
}


class LiveProber:
    """Async HTTP prober with tech fingerprinting."""

    def __init__(
        self,
        targets: list,
        concurrency: int = 50,
        timeout: int = 10,
        follow_redirects: bool = True,
        status_filter: list = None,
        ports: list = None,
    ):
        self.targets = targets
        self.concurrency = concurrency
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.status_filter = status_filter  # None = all, [200, 301] = only these
        self.ports = ports or [80, 443]
        self.results: List[Dict] = []
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT * 10)  # Higher rate for probing
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            # Disable SSL verification for probing
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(
                ssl=ssl_ctx,
                limit=self.concurrency,
                limit_per_host=5,
                ttl_dns_cache=300,
                resolver=aiohttp.ThreadedResolver(),
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": Config.USER_AGENT},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            # Clean up whitespace
            title = re.sub(r"\s+", " ", title)
            return title[:200]  # Truncate long titles
        return ""

    def _detect_tech(self, headers: dict, html: str) -> List[str]:
        """Detect technologies from headers and HTML."""
        techs = []

        # Server header
        server = headers.get("server", "")
        if server:
            techs.append(f"Server:{server}")

        # X-Powered-By
        powered = headers.get("x-powered-by", "")
        if powered:
            techs.append(f"PoweredBy:{powered}")

        # Common framework indicators
        framework_patterns = {
            "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
            "Drupal": [r"Drupal", r"drupal\.js", r"sites/default"],
            "Joomla": [r"/media/jui/", r"joomla", r"/administrator/"],
            "Laravel": [r"laravel_session", r"csrf-token"],
            "Django": [r"csrfmiddlewaretoken", r"__admin__"],
            "React": [r"react\.production\.min\.js", r"_reactRoot", r"__NEXT_DATA__"],
            "Angular": [r"ng-version", r"angular\.js", r"ng-app"],
            "Vue.js": [r"vue\.js", r"vuejs", r"__vue__"],
            "ASP.NET": [r"__VIEWSTATE", r"asp\.net", r"x-aspnet-version"],
            "Spring": [r"spring", r"x-application-context"],
            "Ruby on Rails": [r"_rails", r"action_dispatch", r"x-runtime"],
        }

        html_lower = html.lower() if html else ""
        headers_str = str(headers).lower()

        for tech, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE) or re.search(pattern, headers_str, re.IGNORECASE):
                    techs.append(tech)
                    break

        return list(set(techs))

    def _detect_waf(self, headers: dict, body: str = "") -> str:
        """Detect WAF from response headers."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        all_header_text = " ".join(list(headers_lower.keys()) + list(headers_lower.values()))

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_header_text:
                    return waf_name

        return ""

    async def _resolve_cname(self, hostname: str) -> str:
        """Resolve CNAME record asynchronously to find target domains."""
        try:
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            # Execute DNS resolution synchronously in executor to avoid blocking the event loop
            answers = await loop.run_in_executor(None, resolver.resolve, hostname, "CNAME")
            for rdata in answers:
                return str(rdata.target).lower().strip().rstrip(".")
        except Exception:
            pass
        return ""

    def _detect_takeover(self, body: str, cname: str = "") -> str:
        """Detect subdomain takeovers from response body signatures and CNAME mapping."""
        # Check CNAME targets first for high confidence takeover candidates
        if cname:
            cname_map = {
                "github.io": "GitHub Pages",
                "herokuapp.com": "Heroku",
                "s3.amazonaws.com": "AWS S3",
                "s3-website": "AWS S3",
                "cloudfront.net": "AWS S3 (Alternative)",
                "fastly.net": "Fastly",
                "zendesk.com": "Zendesk",
                "azurewebsites.net": "Azure",
                "myshopify.com": "Shopify",
                "tumblr.com": "Tumblr",
                "pantheonsite.io": "Pantheon",
                "bitbucket.org": "Bitbucket",
                "webflow.io": "Webflow",
                "unbouncepages.com": "Unbounce"
            }
            for pattern, service in cname_map.items():
                if pattern in cname:
                    # If we got a signature in body OR the body returned connection errors/timeouts, flag it!
                    if not body or any(sig in body for sig in TAKEOVER_SIGNATURES.values()):
                        return f"{service} (CNAME: {cname})"

        if not body:
            return ""
            
        for service, signature in TAKEOVER_SIGNATURES.items():
            if signature in body:
                return service
        return ""

    async def _fetch_extra(self, base_url: str, path: str, session: aiohttp.ClientSession) -> str:
        """Fetch extra files like robots.txt or sitemap.xml."""
        url = base_url.rstrip("/") + path
        try:
            async with session.get(url, allow_redirects=False, timeout=5) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    return text[:50000]
        except Exception:
            pass
        return ""

    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML."""
        js_files = []
        # Match src attributes in script tags
        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)

        for match in matches:
            if match.startswith("//"):
                match = "https:" + match
            elif match.startswith("/"):
                parsed = urlparse(base_url)
                match = f"{parsed.scheme}://{parsed.netloc}{match}"
            elif not match.startswith("http"):
                match = base_url.rstrip("/") + "/" + match
            js_files.append(match)

        return js_files

    async def _probe_url(self, url: str, semaphore: asyncio.Semaphore) -> Dict:
        """Probe a single URL and collect metadata."""
        async with semaphore:
            await self.rate_limiter.acquire()
            result = {
                "url": url,
                "status": 0,
                "title": "",
                "content_length": 0,
                "response_time_ms": 0,
                "server": "",
                "technologies": [],
                "waf": "",
                "takeover": "",
                "redirect_url": "",
                "js_files": [],
                "headers": {},
                "alive": False,
            }

            # Extract hostname for CNAME checks
            parsed_host = urlparse(url).netloc
            cname_target = await self._resolve_cname(parsed_host)

            try:
                session = await self._get_session()
                start_time = time.time()

                async with session.get(
                    url,
                    allow_redirects=self.follow_redirects,
                    max_redirects=5,
                ) as resp:
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    result["status"] = resp.status
                    result["response_time_ms"] = elapsed_ms
                    result["alive"] = True

                    # Headers
                    headers = {k: v for k, v in resp.headers.items()}
                    result["headers"] = headers
                    result["server"] = headers.get("Server", "")
                    result["content_length"] = int(headers.get("Content-Length", 0))

                    # Check for redirect
                    if str(resp.url) != url:
                        result["redirect_url"] = str(resp.url)

                    # Read body (limit to 500KB)
                    try:
                        body = await resp.text(encoding="utf-8", errors="ignore")
                        body = body[:500_000]
                    except Exception:
                        body = ""

                    # Extract metadata
                    result["title"] = self._extract_title(body)
                    result["technologies"] = self._detect_tech(headers, body)
                    result["waf"] = self._detect_waf(headers, body)
                    result["js_files"] = self._extract_js_files(body, url)
                    
                    # Detect takeover (using body + CNAME)
                    result["takeover"] = self._detect_takeover(body, cname_target)
                    if result["takeover"]:
                        # Log it immediately to console
                        log_finding(f"[TAKEOVER] {url} -> {result['takeover']}")
                        
                    # Fetch robots/sitemap
                    if result["status"] == 200:
                        robots = await self._fetch_extra(url, "/robots.txt", session)
                        if robots:
                            result["technologies"].append("Robots.txt")
                        sitemap = await self._fetch_extra(url, "/sitemap.xml", session)
                        if sitemap:
                            result["technologies"].append("Sitemap.xml")

                    if not result["content_length"] and body:
                        result["content_length"] = len(body)

            except asyncio.TimeoutError:
                result["title"] = "[Timeout]"
                # If HTTP timed out but we have a dangling CNAME, classify as takeover candidate!
                if cname_target:
                    result["takeover"] = self._detect_takeover("", cname_target)
                    if result["takeover"]:
                        result["alive"] = True
                        log_finding(f"[TAKEOVER-DNS-TIMEOUT] {url} -> {result['takeover']}")
            except aiohttp.ClientConnectorError:
                result["title"] = "[Connection Error]"
                # If connection refused/failed but we have a dangling CNAME, classify as takeover candidate!
                if cname_target:
                    result["takeover"] = self._detect_takeover("", cname_target)
                    if result["takeover"]:
                        result["alive"] = True
                        log_finding(f"[TAKEOVER-DNS-CONNERR] {url} -> {result['takeover']}")
            except Exception as e:
                result["title"] = f"[Error: {type(e).__name__}]"

            return result

    def _build_urls(self) -> List[str]:
        """Build full URLs from targets with appropriate schemes."""
        urls = []
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
            if target.startswith("http://") or target.startswith("https://"):
                urls.append(target)
            else:
                # Probe both HTTP and HTTPS
                urls.append(f"https://{target}")
                urls.append(f"http://{target}")
        return urls

    async def probe(self) -> List[Dict]:
        """Run probing on all targets."""
        start = time.time()
        banner("Live Host Prober")

        urls = self._build_urls()
        log_info(f"Probing {len(urls)} URLs ({len(self.targets)} targets)...")

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._probe_url(url, semaphore) for url in urls]

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Probing hosts", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    if result["alive"]:
                        self.results.append(result)
                    progress.advance(task)
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, dict) and result.get("alive"):
                    self.results.append(result)

        # Apply status filter
        if self.status_filter:
            self.results = [r for r in self.results if r["status"] in self.status_filter]

        # Deduplicate: prefer HTTPS over HTTP for same host
        seen_hosts = {}
        for r in self.results:
            parsed = urlparse(r["url"])
            host = parsed.netloc
            if host not in seen_hosts or parsed.scheme == "https":
                seen_hosts[host] = r
        self.results = list(seen_hosts.values())

        await self.close()

        # Summary
        log_success(f"Probing complete in {elapsed_str(start)}")
        log_success(f"Live hosts: {len(self.results)}")

        # Display results table
        if RICH_AVAILABLE and self.results:
            table = Table(title="Live Hosts", box=box.SIMPLE_HEAVY, show_lines=True)
            table.add_column("URL", style="cyan", max_width=50)
            table.add_column("Status", justify="center", style="bold")
            table.add_column("Title", max_width=35)
            table.add_column("Tech", style="yellow", max_width=30)
            table.add_column("WAF/Takeover", style="red")
            table.add_column("Time", justify="right")

            for r in sorted(self.results, key=lambda x: x["status"]):
                status_style = "green" if r["status"] == 200 else "yellow" if r["status"] < 400 else "red"
                tech_str = ", ".join(r["technologies"][:3]) if r["technologies"] else "-"
                waf_takeover = []
                if r["waf"]: waf_takeover.append(r["waf"])
                if r["takeover"]: waf_takeover.append(f"TK:{r['takeover']}")
                waf_str = ", ".join(waf_takeover) or "-"
                
                table.add_row(
                    r["url"],
                    f"[{status_style}]{r['status']}[/{status_style}]",
                    r["title"][:35] or "-",
                    tech_str,
                    waf_str,
                    f"{r['response_time_ms']}ms",
                )
            console.print(table)

        return self.results


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Live Host Prober & Tech Fingerprinter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python live_probe.py -l subdomains.txt
  python live_probe.py -l subs.txt -o alive.json --status 200 301 302
  python live_probe.py -t example.com -c 100
        """
    )
    parser.add_argument("-l", "--list", help="File with list of targets (one per line)")
    parser.add_argument("-t", "--target", help="Single target hostname")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Concurrent requests (default: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--status", nargs="+", type=int, help="Filter by status codes (e.g., 200 301 302)")
    parser.add_argument("--no-redirect", action="store_true", help="Don't follow redirects")
    parser.add_argument("--urls-only", action="store_true", help="Output only live URLs (no JSON)")

    args = parser.parse_args()

    if not args.list and not args.target:
        parser.error("Either --list or --target is required")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        targets.extend(read_lines(args.list))

    prober = LiveProber(
        targets=targets,
        concurrency=args.concurrency,
        timeout=args.timeout,
        follow_redirects=not args.no_redirect,
        status_filter=args.status,
    )

    results = asyncio.run(prober.probe())

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if args.urls_only:
            write_lines(str(output_path), [r["url"] for r in results])
        else:
            # Strip raw headers for cleaner JSON output
            for r in results:
                r["headers"] = dict(list(r["headers"].items())[:10])  # Keep top 10 headers
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            log_success(f"Results saved to {output_path}")
    elif args.urls_only:
        for r in results:
            print(r["url"])
    else:
        for r in results:
            status = r["status"]
            title = r["title"] or "-"
            tech = ",".join(r["technologies"][:3]) or "-"
            print(f"{r['url']} [{status}] [{title}] [{tech}]")


if __name__ == "__main__":
    main()
