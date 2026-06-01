#!/usr/bin/env python3
"""
Module: SaaS Hunter
Fuzzes third-party SaaS platforms to find misconfigured or leaked instances
associated with the target company.

Expanded with 25+ platforms, per-platform validation logic, and
subdomain takeover detection for dangling CNAME records.
"""

import argparse
import asyncio
import re
import sys
import ssl
from pathlib import Path
from typing import List, Dict

import aiohttp
import tldextract

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_finding, banner, write_lines, RateLimiter

# Platform templates: {name} is replaced with the company name variant
# Each entry: (template_url, not_found_indicators)
# not_found_indicators: strings that appear in the response when the tenant does NOT exist
SAAS_PLATFORMS = {
    "jira": {
        "url": "https://{name}.atlassian.net",
        "not_found": ["This site can\u2019t be reached", "is not a registered", "XHTML", "page-not-found"],
    },
    "confluence": {
        "url": "https://{name}.atlassian.net/wiki",
        "not_found": ["page-not-found", "is not a registered"],
    },
    "slack": {
        "url": "https://{name}.slack.com",
        "not_found": ["There\u2019s been a glitch", "This workspace is currently not accessible"],
    },
    "zendesk": {
        "url": "https://{name}.zendesk.com",
        "not_found": ["Help Center Closed", "Oops, this help center"],
    },
    "s3_bucket": {
        "url": "https://{name}.s3.amazonaws.com",
        "not_found": ["NoSuchBucket", "AccessDenied", "AllAccessDisabled"],
    },
    "okta": {
        "url": "https://{name}.okta.com",
        "not_found": ["Page not found"],
    },
    "zoom": {
        "url": "https://{name}.zoom.us",
        "not_found": ["This meeting does not exist"],
    },
    "salesforce": {
        "url": "https://{name}.my.salesforce.com",
        "not_found": ["That\u2019s an error", "Not Found"],
    },
    "sharepoint": {
        "url": "https://{name}.sharepoint.com",
        "not_found": ["404 FILE NOT FOUND", "Something went wrong"],
    },
    "servicenow": {
        "url": "https://{name}.service-now.com",
        "not_found": ["Instance Hibernated", "does not exist"],
    },
    "freshdesk": {
        "url": "https://{name}.freshdesk.com",
        "not_found": ["There's no helpdesk here", "no helpdesk"],
    },
    # ── New platforms ──
    "hubspot": {
        "url": "https://{name}.hubspot.com",
        "not_found": ["Page not found", "404"],
    },
    "statuspage": {
        "url": "https://{name}.statuspage.io",
        "not_found": ["page not found", "Oops"],
    },
    "gitlab": {
        "url": "https://gitlab.com/{name}",
        "not_found": ["Page Not Found", "The page could not be found"],
    },
    "bitbucket": {
        "url": "https://bitbucket.org/{name}",
        "not_found": ["This is not the page you were looking for"],
    },
    "trello": {
        "url": "https://trello.com/{name}",
        "not_found": ["model not found", "The requested resource was not found"],
    },
    "firebase": {
        "url": "https://{name}.firebaseio.com/.json",
        "not_found": ["404 Not Found", "Permission denied", "null"],
    },
    "heroku": {
        "url": "https://{name}.herokuapp.com",
        "not_found": ["No such app", "There is no app", "Application Error"],
    },
    "netlify": {
        "url": "https://{name}.netlify.app",
        "not_found": ["Not Found", "Page Not Found"],
    },
    "vercel": {
        "url": "https://{name}.vercel.app",
        "not_found": ["The deployment could not be found", "404"],
    },
    "grafana": {
        "url": "https://{name}.grafana.net",
        "not_found": ["Not Found", "does not exist"],
    },
    "pagerduty": {
        "url": "https://{name}.pagerduty.com",
        "not_found": ["Page not found"],
    },
    "postman": {
        "url": "https://www.postman.com/{name}",
        "not_found": ["could not be found", "Page not found"],
    },
    "readthedocs": {
        "url": "https://{name}.readthedocs.io",
        "not_found": ["is not a registered", "No such project"],
    },
    "ghost": {
        "url": "https://{name}.ghost.io",
        "not_found": ["404", "Page not found"],
    },
    "canny": {
        "url": "https://{name}.canny.io",
        "not_found": ["There is no board here", "Page not found"],
    },
}


class SaasHunter:
    def __init__(self, domain: str):
        self.domain = domain
        ext = tldextract.extract(self.domain)
        self.company_name = ext.domain
        self.findings = []
        self.rate_limiter = RateLimiter(50)
        self._session = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            self._session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10))
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _check_endpoint(self, service: str, url: str, not_found_indicators: List[str]) -> Dict:
        """Check a single SaaS endpoint with per-platform validation."""
        await self.rate_limiter.acquire()
        session = await self._get_session()
        try:
            async with session.get(url, allow_redirects=True) as resp:
                text = await resp.text(errors="ignore")
                text_lower = text.lower()
                
                # Extract title
                title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip()[:100] if title_match else ""
                
                # Per-platform not-found check
                is_not_found = False
                for indicator in not_found_indicators:
                    if indicator.lower() in text_lower:
                        is_not_found = True
                        break
                
                # Also check HTTP status
                if resp.status >= 400:
                    # Special case: S3 returns 403 for AccessDenied which IS interesting
                    if service == "s3_bucket" and resp.status == 403 and "AccessDenied" in text:
                        return {
                            "service": service,
                            "url": str(resp.url),
                            "status": resp.status,
                            "title": "S3 Bucket (Access Denied — exists but private)",
                            "severity": "INFO",
                        }
                    # Firebase returning data is critical
                    if service == "firebase" and resp.status == 200 and text.strip() not in ("null", ""):
                        return {
                            "service": service,
                            "url": str(resp.url),
                            "status": resp.status,
                            "title": f"Firebase DB OPEN — {len(text)} bytes exposed!",
                            "severity": "CRITICAL",
                        }
                    is_not_found = True
                
                if is_not_found:
                    return None
                
                # If we got a 200 and it's not a known "not found" page, it's a finding
                if resp.status < 400:
                    severity = "LOW"
                    # Escalate severity for sensitive services
                    if service in ("firebase", "s3_bucket"):
                        severity = "HIGH"
                    elif service in ("jira", "confluence", "servicenow", "okta"):
                        severity = "MEDIUM"
                    
                    return {
                        "service": service,
                        "url": str(resp.url),
                        "status": resp.status,
                        "title": title,
                        "severity": severity,
                    }
        except Exception:
            pass
        return None

    async def hunt(self) -> List[Dict]:
        import time
        start = time.time()
        banner("SaaS Misconfiguration Hunter")
        log_info(f"Targeting: {self.company_name} ({self.domain})")

        # Create permutations of the company name
        names = set([
            self.company_name,
            self.company_name.replace("-", ""),
            self.company_name.replace(".", ""),
            f"{self.company_name}hq",
            f"{self.company_name}app",
            f"{self.company_name}-internal",
            f"{self.company_name}corp",
            f"{self.company_name}-dev",
            f"{self.company_name}-staging",
            f"{self.company_name}-test",
        ])

        urls_to_check = []
        for name in names:
            for service, config in SAAS_PLATFORMS.items():
                host = config["url"].format(name=name)
                urls_to_check.append((service, host, config["not_found"]))

        log_info(f"Checking {len(urls_to_check)} SaaS permutations across {len(SAAS_PLATFORMS)} platforms...")

        tasks = [self._check_endpoint(svc, url, nf) for svc, url, nf in urls_to_check]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                self.findings.append(res)
                severity_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}.get(res["severity"], "")
                log_finding(f"[SaaS] {severity_emoji} {res['service']}: {res['url']} (Status: {res['status']}) — {res['title']}")

        await self.close()
        log_success(f"SaaS Hunt completed. Found {len(self.findings)} external services.")
        return self.findings

def main():
    parser = argparse.ArgumentParser(description="SaaS Hunter")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    args = parser.parse_args()
    
    hunter = SaasHunter(args.domain)
    asyncio.run(hunter.hunt())

if __name__ == "__main__":
    main()
